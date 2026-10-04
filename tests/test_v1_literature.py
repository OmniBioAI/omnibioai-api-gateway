"""Public /v1/literature API: org requirement, JSON validation, per-caller
rate limiting with X-RateLimit-* and 429/Retry-After, billing quota (402),
Idempotency-Key replay / in-progress / reuse-mismatch / release-on-failure,
exactly one billable usage event per successful answer (none for replays,
failures or the free studies listing), upstream error mapping, the error
envelope, policy mapping of /v1/literature to rag, and Redis-outage fail-open.
"""
import json
from unittest.mock import AsyncMock, patch

import pytest

import app.main as _main_mod
import app.routes.v1 as v1
from app.core.config import Config
from app.core.router import service_for_path
from app.services.outbox import Outbox
from app.services.v1_store import V1Store, request_fingerprint

KEY = "omni_sk_" + "a" * 40
USER = {
    "user_id": "5", "email": "", "roles": [], "permissions": ["dataset.read"],
    "org_id": "42", "org_role": [], "token_type": "api_key", "api_key_id": 7,
    "access_token": "minted.jwt.token",
}
# BODY is the frozen *public* request shape; RAG_BODY is what build_rag_query
# (app/services/literature_contract.py) translates it into, and what the
# fake upstream actually receives. RAG_RESPONSE is RAG's own internal
# response shape (what the fake upstream returns); PUBLIC_CITATIONS is
# what build_public_answer translates RAG_RESPONSE's documents into.
BODY = {"question": "What does TP53 do?"}
RAG_BODY = {"query": "What does TP53 do?", "study": "default"}
RAG_RESPONSE = {
    "study": "default",
    "summary": {"text": "TP53 [PMID:1]", "model": "llama3"},
    "documents": [{"pmid": "1", "title": "TP53 review", "year": 2021, "citation_confidence": 0.9}],
}
PUBLIC_CITATIONS = [{"pmid": "1", "title": "TP53 review", "year": 2021, "score": 0.9}]


class FakeRedis:
    def __init__(self):
        self.kv = {}
        self.streams = {}

    async def incr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        return self.kv[key]

    async def decr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) - 1
        return self.kv[key]

    async def expire(self, key, ttl):
        return True

    async def get(self, key):
        value = self.kv.get(key)
        return None if value is None else str(value)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def delete(self, key):
        self.kv.pop(key, None)

    async def xadd(self, stream, fields, maxlen=None, approximate=True):
        self.streams.setdefault(stream, []).append(fields)
        return "0-1"


class BrokenRedis:
    async def _boom(self, *a, **k):
        raise ConnectionError("redis down")

    incr = decr = expire = get = set = delete = xadd = _boom


@pytest.fixture
def redis(tmp_path):
    fake = FakeRedis()
    outbox = Outbox(str(tmp_path / "usage_outbox.db"))
    with (
        patch.object(v1.store, "redis", fake),
        patch.object(v1.store, "usage_redis", fake),
        patch.object(v1.store, "outbox", outbox),
    ):
        yield fake


@pytest.fixture
def upstream():
    forward = AsyncMock(return_value=(200, RAG_RESPONSE))
    with (
        patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=USER)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})) as policy,
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.v1.proxy.forward", forward),
    ):
        forward.policy = policy
        yield forward


def _post(client, body=BODY, idem=None, raw=None):
    headers = {"Authorization": f"Bearer {KEY}"}
    if idem is not None:
        headers["Idempotency-Key"] = idem
    if raw is not None:
        headers["Content-Type"] = "application/json"
        return client.post("/v1/literature/answers", content=raw, headers=headers)
    return client.post("/v1/literature/answers", json=body, headers=headers)


def _usage(redis):
    return [json.loads(f["data"]) for f in redis.streams.get(Config.USAGE_STREAM, [])]


def test_service_for_path():
    assert service_for_path("/v1/literature/answers") == "rag"
    assert service_for_path("/v1/other/x") == "v1"
    assert service_for_path("/rag/v1/query") == "rag"


def test_answer_forwards_to_rag_and_bills_once(client, redis, upstream):
    resp = _post(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["answer"] == "TP53 [PMID:1]"
    assert body["citations"] == PUBLIC_CITATIONS
    assert body["model"] == "llama3"
    assert body["model_source"] == "omnibioai_gpu"
    assert body["domain"] == "default"
    assert body["id"].startswith("ans_")
    assert body["usage"]["queries"] == 1
    assert body["usage"]["billed_by"] == "query"
    assert body["usage"]["input_tokens"] is None and body["usage"]["output_tokens"] is None
    assert isinstance(body["usage"]["latency_ms"], int) and body["usage"]["latency_ms"] >= 0
    assert resp.headers["X-RateLimit-Limit"] == str(Config.V1_RATE_LIMIT_PER_MINUTE)
    assert resp.headers["X-Request-Id"]

    kwargs = upstream.call_args.kwargs
    assert kwargs["url"] == "http://rag:8096/v1/query"
    # The public request shape (BODY) is translated to RAG's own shape
    # (RAG_BODY) before forwarding -- never passed through unchanged.
    assert kwargs["method"] == "POST" and kwargs["body"] == RAG_BODY
    assert kwargs["headers"]["Authorization"] == "Bearer minted.jwt.token"
    assert upstream.policy.call_args.kwargs["service"] == "rag"
    assert upstream.policy.call_args.kwargs["required_permission"] == "dataset.read"

    (event,) = _usage(redis)
    assert event["organization_id"] == "42" and event["user_id"] == "5"
    assert event["service"] == "api" and event["resource"] == "literature.answer"
    assert event["quantity"] == 1 and event["unit"] == "requests"
    assert event["metadata"]["billable"] is True and event["metadata"]["client_id"] == "api_key:7"
    assert KEY not in json.dumps(event)


def test_query_string_is_preserved(client, redis, upstream):
    client.post("/v1/literature/answers?stream=false", json=BODY, headers={"Authorization": f"Bearer {KEY}"})
    assert upstream.call_args.kwargs["url"].endswith("/v1/query?stream=false")


def test_requires_an_organization(client, redis, upstream):
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value={**USER, "org_id": None})):
        resp = _post(client)
    assert resp.status_code == 403
    assert resp.json()["error"]["type"] == "organization_required"
    upstream.assert_not_called()


def test_rejects_non_json_body(client, redis, upstream):
    resp = _post(client, raw=b"not json")
    assert resp.status_code == 400
    assert resp.json()["error"]["type"] == "invalid_request"


def test_rejects_missing_question(client, redis, upstream):
    resp = _post(client, body={})
    assert resp.status_code == 400
    error = resp.json()["error"]
    assert error["type"] == "unsupported_request" and error["detail"]["field"] == "question"
    upstream.assert_not_called()


@pytest.mark.parametrize("field,body", [
    ("model", {"question": "q", "model": "llama-4"}),
    ("use_own_key", {"question": "q", "model": "claude"}),  # claude without use_own_key: true
    ("stream", {"question": "q", "stream": True}),
])
def test_rejects_not_yet_supported_fields_without_calling_upstream_or_billing(client, redis, upstream, field, body):
    resp = _post(client, body=body)
    assert resp.status_code == 400
    error = resp.json()["error"]
    assert error["type"] == "unsupported_request" and error["detail"]["field"] == field
    upstream.assert_not_called()
    assert _usage(redis) == []


def test_model_default_and_none_are_both_accepted(client, redis, upstream):
    assert _post(client, body={"question": "q", "model": "default"}).status_code == 200
    assert _post(client, body={"question": "q", "model": None}).status_code == 200


def test_domain_maps_to_rag_study_and_max_citations_maps_to_top_k(client, redis, upstream):
    resp = _post(client, body={"question": "q", "domain": "Oncology", "max_citations": 3})
    assert resp.status_code == 200
    assert upstream.call_args.kwargs["body"] == {"query": "q", "study": "Oncology", "top_k": 3}


def test_rate_limit(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 2)
    assert _post(client).status_code == 200
    second = _post(client)
    assert second.headers["X-RateLimit-Remaining"] == "0"
    third = _post(client)
    assert third.status_code == 429
    assert third.json()["error"]["type"] == "rate_limit_exceeded"
    assert int(third.headers["Retry-After"]) >= 1
    assert len(_usage(redis)) == 2


def test_rate_limit_is_shared_across_multiple_keys_in_the_same_organization(client, redis, upstream, monkeypatch):
    """Design audit gap #7: rate limiting must be enforced both per key
    and per organization. Two different API keys belonging to the same
    organization must share one organization-wide budget -- a key that
    has made zero requests of its own must still be blocked once the
    organization's shared budget is exhausted by a *different* key."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 2)
    user_key_b = {**USER, "api_key_id": 8}

    assert _post(client).status_code == 200
    assert _post(client).status_code == 200  # key A alone has now used the org's shared budget of 2

    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=user_key_b)):
        third = _post(client)  # key B, same org, zero requests of its own
    assert third.status_code == 429
    assert third.json()["error"]["type"] == "rate_limit_exceeded"


def test_rate_limit_per_key_budget_is_independent_across_organizations(client, redis, upstream, monkeypatch):
    """The organization-wide counter must not leak across organizations
    -- exhausting org 42's shared budget must not affect a key
    belonging to a different organization."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 1)
    other_org_user = {**USER, "org_id": "99", "api_key_id": 9}

    assert _post(client).status_code == 200  # org 42 exhausts its budget of 1
    assert _post(client).status_code == 429

    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=other_org_user)):
        resp = _post(client)  # a different organization entirely
    assert resp.status_code == 200


def test_rate_limit_headers_report_whichever_counter_is_binding(client, redis, upstream, monkeypatch):
    """A key that has made no requests of its own, blocked purely by its
    organization's exhausted shared budget, must see 0 remaining -- not
    its own, still-fresh per-key count."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 1)
    user_key_b = {**USER, "api_key_id": 8}

    assert _post(client).status_code == 200  # key A exhausts the org's shared budget of 1

    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=user_key_b)):
        resp = _post(client)
    assert resp.status_code == 429
    assert resp.headers["X-RateLimit-Remaining"] == "0"


def test_rate_limit_uses_the_organizations_plan_specific_override(client, redis, upstream, monkeypatch):
    """omnibioai-billing publishes this org's plan-specific override
    under gateway:v1:quota:{org}:ratelimit (see
    gateway_quota_sync_service.py) -- when set, it wins over the
    configured global default."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 100)
    redis.kv["gateway:v1:quota:42:ratelimit"] = 1

    first = _post(client)
    assert first.status_code == 200
    assert first.headers["X-RateLimit-Limit"] == "1"
    second = _post(client)
    assert second.status_code == 429


def test_rate_limit_falls_back_to_the_global_default_when_no_override_is_set(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 100)
    # No gateway:v1:quota:42:ratelimit key at all.

    resp = _post(client)
    assert resp.headers["X-RateLimit-Limit"] == "100"


def test_rate_limit_override_of_zero_is_honored_not_treated_as_unset(client, redis, upstream, monkeypatch):
    """`is not None`, not a truthiness/`or` check -- a plan-specific
    limit of exactly 0 is a real (if unusual) value."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 100)
    redis.kv["gateway:v1:quota:42:ratelimit"] = 0

    resp = _post(client)
    assert resp.status_code == 429
    assert resp.headers["X-RateLimit-Limit"] == "0"


def test_rate_limit_override_fails_open_on_redis_error(client, upstream, monkeypatch):
    """A broken Redis for the rate-limit *lookup* must still let the
    request through at the global default -- the same fail-open
    posture every other V1Store method takes on a Redis error."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 100)

    class BrokenGetRedis:
        async def get(self, key):
            raise ConnectionError("redis down")

        async def incr(self, key):
            return 1

        async def expire(self, key, ttl):
            return True

    with patch.object(v1.store, "redis", BrokenGetRedis()), \
         patch.object(v1.store, "usage_redis", BrokenGetRedis()), \
         patch.object(v1.store, "outbox", Outbox(":memory:")):
        resp = _post(client)

    assert resp.status_code == 200
    assert resp.headers["X-RateLimit-Limit"] == "100"


def test_token_bucket_refills_a_token_after_the_rate_elapses(client, redis, upstream, monkeypatch):
    """Design audit gap #7: the fixed one-minute window's hard reset at
    :00 let a caller spend its whole budget in the last second of one
    window and again in the first second of the next -- 2x limit in
    under two seconds. A token bucket instead earns back one token at a
    time, continuously: here, waiting exactly 1/rate seconds after
    exhausting a limit-of-2 bucket earns back exactly one token, no
    more."""
    import app.services.v1_store as v1_store

    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 2)
    now = [1_000_000.0]
    monkeypatch.setattr(v1_store.time, "time", lambda: now[0])

    assert _post(client).status_code == 200
    assert _post(client).status_code == 200
    denied = _post(client)
    assert denied.status_code == 429

    rate = 2 / 60.0
    now[0] += 1.0 / rate  # exactly enough time for one token to refill
    allowed = _post(client)
    assert allowed.status_code == 200
    immediately_after = _post(client)
    assert immediately_after.status_code == 429  # only one token refilled, not a full reset


def test_rate_limit_of_zero_reports_a_fixed_reset_without_dividing_by_zero(client, redis, upstream, monkeypatch):
    """limit=0 means rate=0 tokens/sec -- the reset-time computation must
    not attempt to divide by that rate."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 100)
    redis.kv["gateway:v1:quota:42:ratelimit"] = 0

    resp = _post(client)
    assert resp.status_code == 429
    assert int(resp.headers["Retry-After"]) >= 1


# ---------------------------------------------------------------------------
# Concurrent-answer limits (design audit gap #7's other remaining bullet)
# ---------------------------------------------------------------------------


def test_concurrency_limit_rejects_once_the_keys_slot_cap_is_reached(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "V1_MAX_CONCURRENT_ANSWERS", 2)
    redis.kv["gateway:v1:conc:api_key:7"] = 2  # already at the cap

    resp = _post(client, idem="conc-1")
    assert resp.status_code == 429
    assert resp.json()["error"]["type"] == "concurrency_limit_exceeded"
    upstream.assert_not_called()
    assert _usage(redis) == []
    # The denied attempt must not have left the counter net-incremented.
    assert redis.kv["gateway:v1:conc:api_key:7"] == 2


def test_concurrency_limit_is_enforced_per_organization_too(client, redis, upstream, monkeypatch):
    """A key with no in-flight calls of its own is still blocked once its
    organization's shared concurrency budget is exhausted by other
    keys -- the same per-key-and-per-org pairing the rate limiter uses."""
    monkeypatch.setattr(Config, "V1_MAX_CONCURRENT_ANSWERS", 2)
    redis.kv["gateway:v1:conc:org:42"] = 2  # org's shared budget already full
    # This key's own counter is fresh (zero/absent).

    resp = _post(client, idem="conc-2")
    assert resp.status_code == 429
    assert resp.json()["error"]["type"] == "concurrency_limit_exceeded"
    # The key's own slot, acquired before the org check failed, must have
    # been released back out rather than left incremented.
    assert redis.kv.get("gateway:v1:conc:api_key:7", 0) == 0


def test_concurrency_slot_is_released_after_a_successful_request(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "V1_MAX_CONCURRENT_ANSWERS", 5)
    resp = _post(client)
    assert resp.status_code == 200
    assert redis.kv["gateway:v1:conc:api_key:7"] == 0
    assert redis.kv["gateway:v1:conc:org:42"] == 0


def test_concurrency_slot_is_released_after_a_quota_denial(client, redis, upstream, monkeypatch):
    """The concurrency slot is acquired before the quota check -- a 402
    must still release it, or a key that's merely out of quota would
    also look permanently "busy" to the concurrency limiter."""
    monkeypatch.setattr(Config, "V1_MAX_CONCURRENT_ANSWERS", 5)
    redis.kv["gateway:v1:quota:42:literature.answer"] = 0

    resp = _post(client, idem="conc-3")
    assert resp.status_code == 402
    assert redis.kv["gateway:v1:conc:api_key:7"] == 0
    assert redis.kv["gateway:v1:conc:org:42"] == 0


def test_literature_search_has_no_concurrency_cap(client, redis, upstream, monkeypatch):
    """Design audit gap #7 names /v1/literature/answers specifically (the
    expensive, LLM-invoking call) -- /search is retrieval-only and
    carries no concurrency limit of its own."""
    monkeypatch.setattr(Config, "V1_MAX_CONCURRENT_ANSWERS", 1)
    redis.kv["gateway:v1:conc:api_key:7"] = 1_000_000  # would deny /answers outright

    headers = {"Authorization": f"Bearer {KEY}"}
    resp = client.post("/v1/literature/search", json={"question": "q"}, headers=headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# omni_sk_test_ keys: canned, unbilled responses (design audit gap #9's
# remaining "test keys and canned, unbilled responses are absent" bullet)
# ---------------------------------------------------------------------------

TEST_MODE_USER = {**USER, "test_mode": True}


def test_test_mode_answers_returns_a_canned_response_without_calling_upstream(client, redis, upstream):
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=TEST_MODE_USER)):
        resp = _post(client)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"].startswith("ans_test_")
    assert body["model"] == "test" and body["model_source"] == "test"
    assert body["citations"] == []
    assert body["usage"]["queries"] == 0
    upstream.assert_not_called()
    assert _usage(redis) == []  # never billed


def test_test_mode_search_returns_a_canned_response_without_calling_upstream(client, redis, upstream):
    headers = {"Authorization": f"Bearer {KEY}"}
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=TEST_MODE_USER)):
        resp = client.post("/v1/literature/search", json={"question": "q"}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"].startswith("srch_test_")
    assert body["results"] == []
    assert body["usage"]["searches"] == 0
    upstream.assert_not_called()
    assert _usage(redis) == []


def test_test_mode_key_does_not_consume_quota(client, redis, upstream):
    """A test key answers successfully even when the organization's real
    quota is already exhausted -- test mode never checks it at all."""
    redis.kv["gateway:v1:quota:42:literature.answer"] = 0
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=TEST_MODE_USER)):
        resp = _post(client)
    assert resp.status_code == 200


def test_test_mode_key_is_still_rate_limited(client, redis, upstream, monkeypatch):
    """Test mode skips quota/billing/RAG, but not rate limiting -- the
    gateway's own resources still need abuse protection regardless of
    whether a call is "real"."""
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 1)
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=TEST_MODE_USER)):
        assert _post(client).status_code == 200
        assert _post(client).status_code == 429


def test_test_mode_key_does_not_acquire_a_concurrency_slot(client, redis, upstream, monkeypatch):
    """A test key never calls RAG, so it must not compete for -- or even
    touch -- the real concurrency budget shared with live callers."""
    monkeypatch.setattr(Config, "V1_MAX_CONCURRENT_ANSWERS", 1)
    redis.kv["gateway:v1:conc:api_key:7"] = 1  # already at the cap for a real call

    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=TEST_MODE_USER)):
        resp = _post(client, idem="test-conc-1")
    assert resp.status_code == 200
    assert redis.kv["gateway:v1:conc:api_key:7"] == 1  # untouched


def test_test_mode_key_supports_idempotency_replay(client, redis, upstream):
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=TEST_MODE_USER)):
        first = _post(client, idem="test-idem-1")
        second = _post(client, idem="test-idem-1")
    assert first.status_code == 200 and second.status_code == 200
    assert second.headers.get("Idempotent-Replayed") == "true"
    assert first.json() == second.json()
    upstream.assert_not_called()


# ---------------------------------------------------------------------------
# M16 (design audit gap #4): BYOK provider routing. "upstream" patches
# proxy.forward globally, so these tests distinguish the reveal call
# (to omnibioai-auth) from the RAG forward by URL via a custom side_effect.
# ---------------------------------------------------------------------------

BYOK_BODY = {"question": "What does TP53 do?", "model": "claude", "use_own_key": True}
RAG_RESPONSE_WITH_USAGE = {
    "study": "default",
    "summary": {
        "text": "TP53 [PMID:1]", "model": "claude-3-5-sonnet-20241022",
        "model_source": "claude", "input_tokens": 120, "output_tokens": 15,
    },
    "documents": [{"pmid": "1", "title": "TP53 review", "year": 2021, "citation_confidence": 0.9}],
}


def _byok_forward(reveal_response=(200, {"provider": "claude", "api_key": "sk-ant-real-key"}),
                   rag_response=(200, RAG_RESPONSE_WITH_USAGE)):
    def fake_forward(url, method, headers=None, body=None):
        if "provider-keys" in url:
            return reveal_response
        return rag_response
    return fake_forward


def test_byok_reveals_key_and_forwards_it_with_the_rag_request(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "PROVIDER_KEY_REVEAL_SECRET", "test-reveal-secret")
    upstream.side_effect = _byok_forward()

    resp = _post(client, body=BYOK_BODY)
    assert resp.status_code == 200
    assert resp.json()["model_source"] == "claude"

    reveal_call, rag_call = upstream.call_args_list
    assert reveal_call.kwargs["url"] == "http://omnibioai-auth:8000/internal/organizations/42/provider-keys/claude/reveal"
    assert reveal_call.kwargs["method"] == "POST"
    assert reveal_call.kwargs["headers"] == {"X-Provider-Key-Reveal-Secret": "test-reveal-secret"}

    assert rag_call.kwargs["body"]["model"] == "claude"
    assert rag_call.kwargs["body"]["provider_api_key"] == "sk-ant-real-key"
    # The key must never appear in the headers forwarded to RAG (that's
    # still the minted JWT, exactly like every other /v1 call).
    assert "sk-ant-real-key" not in str(rag_call.kwargs["headers"])


def test_byok_without_configured_reveal_secret_returns_503(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "PROVIDER_KEY_REVEAL_SECRET", "")
    resp = _post(client, body=BYOK_BODY)
    assert resp.status_code == 503
    upstream.assert_not_called()


def test_byok_no_key_configured_returns_400_without_calling_rag(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "PROVIDER_KEY_REVEAL_SECRET", "test-reveal-secret")
    upstream.side_effect = _byok_forward(reveal_response=(404, {"detail": "No claude key is configured"}))

    resp = _post(client, body=BYOK_BODY)
    assert resp.status_code == 400
    assert resp.json()["error"]["type"] == "provider_key_not_configured"
    assert upstream.call_count == 1  # reveal only -- RAG never called
    assert _usage(redis) == []


def test_byok_reveal_5xx_returns_502_without_calling_rag(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "PROVIDER_KEY_REVEAL_SECRET", "test-reveal-secret")
    upstream.side_effect = _byok_forward(reveal_response=(500, {"detail": "CONFIG_ENCRYPTION_KEY is not set"}))

    resp = _post(client, body=BYOK_BODY)
    assert resp.status_code == 502
    assert upstream.call_count == 1


def test_byok_emits_token_usage_events_alongside_the_answer_event(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "PROVIDER_KEY_REVEAL_SECRET", "test-reveal-secret")
    upstream.side_effect = _byok_forward()

    resp = _post(client, body=BYOK_BODY)
    assert resp.status_code == 200

    events = _usage(redis)
    by_resource = {e["resource"]: e for e in events}
    assert set(by_resource) == {"literature.answer", "llm.tokens.input", "llm.tokens.output"}
    assert by_resource["llm.tokens.input"]["quantity"] == 120 and by_resource["llm.tokens.input"]["unit"] == "tokens"
    assert by_resource["llm.tokens.output"]["quantity"] == 15 and by_resource["llm.tokens.output"]["unit"] == "tokens"
    assert by_resource["literature.answer"]["quantity"] == 1 and by_resource["literature.answer"]["unit"] == "requests"


def test_default_path_never_emits_token_usage_events(client, redis, upstream):
    """RAG_RESPONSE (the default fixture) has no input_tokens/output_tokens
    at all -- the non-BYOK path must not emit token events."""
    resp = _post(client)
    assert resp.status_code == 200
    resources = {e["resource"] for e in _usage(redis)}
    assert resources == {"literature.answer"}


def test_byok_search_is_rejected_regardless_of_use_own_key(client, redis, upstream):
    """build_rag_search_query never validates model/use_own_key at all
    (search is retrieval-only) -- confirms that stays true after M16."""
    headers = {"Authorization": f"Bearer {KEY}"}
    resp = client.post("/v1/literature/search", json={"question": "q", "model": "claude", "use_own_key": True},
                       headers=headers)
    assert resp.status_code == 200  # accepted; search never routes through a provider at all
    upstream.assert_called_once()  # only the retrieval-only RAG call, no reveal


def test_quota_exhausted_returns_402_without_calling_upstream(client, redis, upstream):
    redis.kv["gateway:v1:quota:42:literature.answer"] = 0
    resp = _post(client, idem="q-1")
    assert resp.status_code == 402
    body = resp.json()["error"]
    assert body["type"] == "quota_exceeded" and body["request_id"]
    upstream.assert_not_called()
    assert _usage(redis) == []
    assert not any(k.startswith("gateway:v1:idem:") for k in redis.kv)


def test_quota_is_consumed_on_success_and_never_created(client, redis, upstream):
    redis.kv["gateway:v1:quota:42:literature.answer"] = 2
    assert _post(client).status_code == 200
    assert redis.kv["gateway:v1:quota:42:literature.answer"] == 1
    del redis.kv["gateway:v1:quota:42:literature.answer"]
    assert _post(client).status_code == 200
    assert "gateway:v1:quota:42:literature.answer" not in redis.kv


def test_quota_reservation_is_atomic_under_concurrency(client, redis, upstream):
    """Two concurrent requests with only 1 unit of quota left: exactly one
    must succeed and one must be quota_exceeded -- not both succeeding
    (an overrun) and not both failing (undercounting real capacity).
    FakeRedis's incr/decr aren't async-concurrent in the true sense (no
    real parallelism in this test process), but this still exercises the
    actual reserve-then-compensate sequence reserve_quota runs, not a
    mock standing in for it."""
    redis.kv["gateway:v1:quota:42:literature.answer"] = 1
    first = _post(client, idem="race-1")
    second = _post(client, idem="race-2")
    statuses = sorted([first.status_code, second.status_code])
    assert statuses == [200, 402]
    # The quota key never goes negative and ends at exactly zero, not
    # some other value a non-atomic check-then-decrement could leave it at.
    assert redis.kv["gateway:v1:quota:42:literature.answer"] == 0


def test_quota_is_refunded_when_upstream_call_fails(client, redis, upstream):
    """reserve_quota decrements optimistically, before knowing whether the
    call will succeed -- a failed upstream call must give the unit back,
    or a string of transient RAG failures would silently burn through an
    organization's quota for answers it never actually got billed for
    (and never received)."""
    redis.kv["gateway:v1:quota:42:literature.answer"] = 1
    upstream.return_value = (503, {"detail": "rag down"})
    resp = _post(client)
    assert resp.status_code == 503
    assert redis.kv["gateway:v1:quota:42:literature.answer"] == 1
    assert _usage(redis) == []


def test_idempotent_retry_replays_without_running_or_billing_again(client, redis, upstream):
    first = _post(client, idem="retry-1")
    second = _post(client, idem="retry-1")
    assert first.status_code == second.status_code == 200
    assert second.json() == first.json()
    assert second.headers["Idempotent-Replayed"] == "true"
    assert upstream.call_count == 1
    assert len(_usage(redis)) == 1


def test_idempotency_key_reused_with_other_body_is_rejected(client, redis, upstream):
    _post(client, idem="k")
    resp = _post(client, body={"question": "different"}, idem="k")
    assert resp.status_code == 422
    assert resp.json()["error"]["type"] == "idempotency_key_reused"


def test_idempotency_in_progress_returns_409(client, redis, upstream):
    subject = "api_key:7"
    key = v1.store._idem_key(subject, "busy")
    redis.kv[key] = json.dumps({"state": "in_progress", "fingerprint": request_fingerprint(BODY)})
    resp = _post(client, idem="busy")
    assert resp.status_code == 409
    upstream.assert_not_called()


def test_invalid_idempotency_key(client, redis, upstream):
    resp = _post(client, idem="has space")
    assert resp.status_code == 400
    upstream.assert_not_called()


def test_failed_request_releases_key_and_is_not_billed(client, redis, upstream):
    upstream.return_value = (500, {"error": "boom"})
    resp = _post(client, idem="fail-1")
    assert resp.status_code == 502
    assert resp.json()["error"]["type"] == "upstream_error"
    assert _usage(redis) == []
    upstream.return_value = (200, RAG_RESPONSE)
    assert _post(client, idem="fail-1").status_code == 200
    assert len(_usage(redis)) == 1


@pytest.mark.parametrize(
    "status,error_type", [(422, "invalid_request"), (404, "request_failed"), (503, "upstream_error")]
)
def test_upstream_error_mapping(client, redis, upstream, status, error_type):
    upstream.return_value = (status, {"detail": "x"})
    resp = _post(client)
    assert resp.status_code == status
    assert resp.json()["error"]["type"] == error_type
    assert _usage(redis) == []


def test_studies_is_free_and_rate_limited(client, redis, upstream, monkeypatch):
    upstream.return_value = (200, {"studies": ["Oncology"]})
    resp = client.get("/v1/literature/studies", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200 and resp.json() == {"studies": ["Oncology"]}
    assert upstream.call_args.kwargs["url"] == "http://rag:8096/v1/studies"
    assert _usage(redis) == []

    upstream.return_value = (500, {})
    assert client.get("/v1/literature/studies", headers={"Authorization": f"Bearer {KEY}"}).status_code == 502

    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 0)
    assert client.get("/v1/literature/studies", headers={"Authorization": f"Bearer {KEY}"}).status_code == 429


def test_domains_is_free_and_rate_limited(client, redis, upstream, monkeypatch):
    upstream.return_value = (200, {"studies": [{"name": "oncology", "abstract_count": 12}]})
    resp = client.get("/v1/literature/domains", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200
    assert resp.json() == {"domains": [{"name": "oncology", "abstract_count": 12}]}
    assert upstream.call_args.kwargs["url"] == "http://rag:8096/v1/studies"
    assert _usage(redis) == []

    upstream.return_value = (500, {})
    assert client.get("/v1/literature/domains", headers={"Authorization": f"Bearer {KEY}"}).status_code == 502

    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 0)
    assert client.get("/v1/literature/domains", headers={"Authorization": f"Bearer {KEY}"}).status_code == 429


def test_search_forwards_search_mode_and_bills_search_resource(client, redis, upstream):
    """/v1/literature/search uses the same billable-call lifecycle as
    /v1/literature/answers, but bills "literature.search" (not
    "literature.answer") and tells RAG mode="search" so no LLM is
    invoked -- the response has no generated answer."""
    upstream.return_value = (200, {
        "study": "default", "mode": "search", "summary": None,
        "documents": [{"pmid": "1", "title": "TP53 review", "year": 2021, "citation_confidence": 0.9,
                        "abstract": "TP53 is a tumor suppressor."}],
    })
    resp = client.post("/v1/literature/search", json={"question": "What does TP53 do?"},
                        headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"].startswith("srch_")
    assert body["results"] == [{"pmid": "1", "title": "TP53 review", "year": 2021, "score": 0.9,
                                 "snippet": "TP53 is a tumor suppressor."}]
    assert body["domain"] == "default"
    assert body["usage"]["searches"] == 1
    assert "answer" not in body

    kwargs = upstream.call_args.kwargs
    assert kwargs["method"] == "POST"
    assert kwargs["body"] == {"query": "What does TP53 do?", "study": "default", "mode": "search"}

    (event,) = _usage(redis)
    assert event["resource"] == "literature.search"


def test_search_rejects_missing_question(client, redis, upstream):
    resp = client.post("/v1/literature/search", json={}, headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 400
    assert resp.json()["error"]["detail"]["field"] == "question"
    upstream.assert_not_called()


def test_search_quota_exceeded(client, redis, upstream):
    with patch.object(v1.store, "reserve_quota", AsyncMock(return_value=False)):
        resp = client.post("/v1/literature/search", json={"question": "q"},
                            headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 402
    assert resp.json()["error"]["type"] == "quota_exceeded"
    upstream.assert_not_called()


def test_usage_requires_an_organization(client, redis, upstream):
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value={**USER, "org_id": None})):
        resp = client.get("/v1/usage", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 403
    assert resp.json()["error"]["type"] == "organization_required"
    upstream.assert_not_called()


def test_usage_translates_billing_response_and_is_free(client, redis, upstream):
    upstream.return_value = (200, {
        "organization_id": 42, "billing_plan_id": 1, "plan_name": "Free", "as_of": "2026-10-03",
        "limits": [
            {"service": "api", "action": "answer", "resource": "literature.answer", "unit": "requests",
             "period": "monthly", "included": 100, "used": 12, "remaining": 88, "percentage_used": 12.0},
        ],
    })
    resp = client.get("/v1/usage", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["plan"] == "Free"
    assert body["as_of"] == "2026-10-03"
    assert body["usage"] == [
        {"resource": "literature.answer", "unit": "requests", "period": "monthly",
         "included": 100, "used": 12, "remaining": 88},
    ]
    assert upstream.call_args.kwargs["url"] == "http://billing-service:8005/billing/organizations/42/subscription/usage-limits"
    assert _usage(redis) == []


def test_usage_no_active_plan_returns_404(client, redis, upstream):
    upstream.return_value = (404, {"detail": "No active subscription"})
    resp = client.get("/v1/usage", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 404
    assert resp.json()["error"]["type"] == "no_active_plan"


def test_usage_upstream_5xx_is_502(client, redis, upstream):
    upstream.return_value = (500, {})
    resp = client.get("/v1/usage", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 502
    assert resp.json()["error"]["type"] == "upstream_error"


def test_models_is_free_static_and_never_calls_upstream(client, redis, upstream):
    resp = client.get("/v1/models", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200
    assert resp.json() == {"models": [
        {"model": "default", "source": "omnibioai_gpu", "billed_by": "query", "price": None},
        {"model": "claude", "source": "claude", "billed_by": "query", "price": None},
        {"model": "openai", "source": "openai", "billed_by": "query", "price": None},
    ]}
    upstream.assert_not_called()
    assert _usage(redis) == []


# ---------------------------------------------------------------------------
# M15 (design audit gap #4's BYOK storage, public surface): PUT/GET/DELETE
# /v1/provider-keys(/{provider}) proxy into omnibioai-auth's own
# /orgs/{org_id}/provider-keys(/{provider}) -- storage only, never a
# billable call.
# ---------------------------------------------------------------------------


def test_set_provider_key_requires_an_organization(client, redis, upstream):
    with patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value={**USER, "org_id": None})):
        resp = client.request(
            "PUT", "/v1/provider-keys/claude", json={"api_key": "sk-x"}, headers={"Authorization": f"Bearer {KEY}"},
        )
    assert resp.status_code == 403
    assert resp.json()["error"]["type"] == "organization_required"
    upstream.assert_not_called()


def test_set_provider_key_forwards_to_auth_service(client, redis, upstream):
    upstream.return_value = (200, {"provider": "claude", "has_key": True, "updated_at": None, "updated_by_email": None})
    resp = client.request(
        "PUT", "/v1/provider-keys/claude", json={"api_key": "sk-secret"}, headers={"Authorization": f"Bearer {KEY}"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"provider": "claude", "has_key": True, "updated_at": None, "updated_by_email": None}

    kwargs = upstream.call_args.kwargs
    assert kwargs["url"] == "http://omnibioai-auth:8000/orgs/42/provider-keys/claude"
    assert kwargs["method"] == "PUT" and kwargs["body"] == {"api_key": "sk-secret"}
    assert "sk-secret" not in kwargs["headers"].get("Authorization", "")
    assert _usage(redis) == []  # never billed


def test_get_provider_key_forwards_to_auth_service(client, redis, upstream):
    upstream.return_value = (200, {"provider": None, "has_key": False, "updated_at": None, "updated_by_email": None})
    resp = client.get("/v1/provider-keys", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200
    assert resp.json()["has_key"] is False
    kwargs = upstream.call_args.kwargs
    assert kwargs["url"] == "http://omnibioai-auth:8000/orgs/42/provider-keys"
    assert kwargs["method"] == "GET"


def test_delete_provider_key_forwards_to_auth_service(client, redis, upstream):
    upstream.return_value = (200, {"provider": None, "has_key": False, "updated_at": None, "updated_by_email": None})
    resp = client.request("DELETE", "/v1/provider-keys/claude", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200
    kwargs = upstream.call_args.kwargs
    assert kwargs["url"] == "http://omnibioai-auth:8000/orgs/42/provider-keys/claude"
    assert kwargs["method"] == "DELETE"


def test_set_provider_key_maps_403_to_forbidden(client, redis, upstream):
    upstream.return_value = (403, {"detail": "Forbidden"})
    resp = client.request(
        "PUT", "/v1/provider-keys/claude", json={"api_key": "sk-x"}, headers={"Authorization": f"Bearer {KEY}"},
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["type"] == "forbidden"


def test_delete_provider_key_maps_404_to_not_found(client, redis, upstream):
    upstream.return_value = (404, {"detail": "No claude key is configured for this organization."})
    resp = client.request("DELETE", "/v1/provider-keys/claude", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 404
    assert resp.json()["error"]["type"] == "not_found"


def test_set_provider_key_maps_upstream_5xx_to_502(client, redis, upstream):
    upstream.return_value = (500, {"detail": "CONFIG_ENCRYPTION_KEY is not set"})
    resp = client.request(
        "PUT", "/v1/provider-keys/claude", json={"api_key": "sk-x"}, headers={"Authorization": f"Bearer {KEY}"},
    )
    assert resp.status_code == 502
    assert resp.json()["error"]["type"] == "upstream_error"


def test_set_provider_key_rejects_non_json_body(client, redis, upstream):
    resp = client.request(
        "PUT", "/v1/provider-keys/claude", content=b"not json",
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    upstream.assert_not_called()


def test_provider_key_routes_are_rate_limited(client, redis, upstream, monkeypatch):
    monkeypatch.setattr(Config, "V1_RATE_LIMIT_PER_MINUTE", 1)
    upstream.return_value = (200, {"provider": None, "has_key": False, "updated_at": None, "updated_by_email": None})
    assert client.get("/v1/provider-keys", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200
    assert client.get("/v1/provider-keys", headers={"Authorization": f"Bearer {KEY}"}).status_code == 429


def test_unauthenticated_v1_is_rejected(client):
    assert client.post("/v1/literature/answers", json=BODY).status_code == 401


def test_redis_outage_fails_open_for_limits_and_idempotency(client, upstream, tmp_path):
    broken = BrokenRedis()
    outbox = Outbox(str(tmp_path / "usage_outbox.db"))
    with (
        patch.object(v1.store, "redis", broken),
        patch.object(v1.store, "usage_redis", broken),
        patch.object(v1.store, "outbox", outbox),
    ):
        resp = _post(client, idem="x")
    assert resp.status_code == 200
    # The lost usage event landed in the outbox instead of being discarded.
    assert outbox.pending_count() == 1


def test_emit_usage_drains_pending_outbox_once_redis_recovers(tmp_path):
    import asyncio

    with patch("app.services.v1_store.aioredis.from_url", return_value=FakeRedis()):
        store = V1Store("redis://x", "redis://y", outbox_path=str(tmp_path / "outbox.db"))
    store.usage_redis = BrokenRedis()

    # First call: Redis is down, the event is written to the outbox instead of lost.
    ok = asyncio.run(store.emit_usage(
        org_id="42", user_id="5", resource="literature.answer", trace_id="t-1",
        dedup_key="d-1", metadata={},
    ))
    assert ok is False
    assert store.outbox.pending_count() == 1

    # Redis recovers; the next call both emits its own event and drains the backlog.
    store.usage_redis = FakeRedis()
    ok = asyncio.run(store.emit_usage(
        org_id="42", user_id="5", resource="literature.answer", trace_id="t-2",
        dedup_key="d-2", metadata={},
    ))
    assert ok is True
    assert store.outbox.pending_count() == 0
    assert len(store.usage_redis.streams[Config.USAGE_STREAM]) == 2


def test_store_edge_cases(tmp_path):
    import asyncio
    with patch("app.services.v1_store.aioredis.from_url", return_value=FakeRedis()):
        store = V1Store("redis://x", "redis://y", outbox_path=str(tmp_path / "outbox.db"))
    store.redis.kv["gateway:v1:quota:1:r"] = "not-a-number"
    assert asyncio.run(store.quota_remaining("1", "r")) is None
    key = store._idem_key("s", "k")
    assert asyncio.run(store.idempotency_begin("s", "k", "f")) == {"state": "new"}
    store.redis.kv.pop(key)
    store.redis.set = AsyncMock(return_value=None)
    assert asyncio.run(store.idempotency_begin("s", "k", "f")) == {"state": "in_progress"}


def test_rate_limit_for_org_edge_cases(tmp_path):
    import asyncio
    with patch("app.services.v1_store.aioredis.from_url", return_value=FakeRedis()):
        store = V1Store("redis://x", "redis://y", outbox_path=str(tmp_path / "outbox.db"))
    assert asyncio.run(store.rate_limit_for_org("1")) is None  # no key set at all
    store.redis.kv["gateway:v1:quota:1:ratelimit"] = "not-a-number"
    assert asyncio.run(store.rate_limit_for_org("1")) is None
    store.redis.kv["gateway:v1:quota:1:ratelimit"] = "30"
    assert asyncio.run(store.rate_limit_for_org("1")) == 30


def test_memory_store_semantics():
    import asyncio

    from app.services.v1_store import MemoryStore

    now = [0.0]
    mem = MemoryStore(clock=lambda: now[0])

    async def scenario():
        assert await mem.incr("c") == 1
        assert await mem.expire("c", 10) is True
        assert await mem.incr("c") == 2
        assert await mem.expire("missing", 10) is False
        assert await mem.set("k", "v", nx=True, ex=5) is True
        assert await mem.set("k", "w", nx=True, ex=5) is None
        assert await mem.get("k") == "v"
        assert await mem.decr("q") == -1
        now[0] = 11.0
        assert await mem.get("c") is None and await mem.get("k") is None
        await mem.set("p", "1")
        await mem.delete("p")
        assert await mem.get("p") is None

    asyncio.run(scenario())


def test_memory_store_prunes_when_full(monkeypatch):
    import asyncio

    from app.services.v1_store import MemoryStore

    monkeypatch.setattr(MemoryStore, "MAX_KEYS", 10)
    now = [0.0]
    mem = MemoryStore(clock=lambda: now[0])

    async def fill():
        for i in range(5):
            await mem.set(f"short{i}", "x", ex=1)
        for i in range(5):
            await mem.set(f"long{i}", "x")
        now[0] = 2.0
        await mem.set("new", "x")
        assert not any(k.startswith("short") for k in mem._data)
        for i in range(10):
            await mem.set(f"more{i}", "x")
        assert len(mem._data) <= 10

    asyncio.run(fill())


def test_store_uses_memory_without_redis_url(tmp_path):
    from app.services.v1_store import MemoryStore

    outbox_path = str(tmp_path / "outbox.db")
    with patch("app.services.v1_store.aioredis.from_url", return_value=FakeRedis()):
        assert isinstance(V1Store("", "redis://usage", outbox_path=outbox_path).redis, MemoryStore)
        assert isinstance(V1Store("redis://v1", "redis://usage", outbox_path=outbox_path).redis, FakeRedis)

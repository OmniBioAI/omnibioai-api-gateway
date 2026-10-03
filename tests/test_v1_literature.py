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
from app.services.v1_store import V1Store, request_fingerprint

KEY = "omni_sk_" + "a" * 40
USER = {
    "user_id": "5", "email": "", "roles": [], "permissions": ["dataset.read"],
    "org_id": "42", "org_role": [], "token_type": "api_key", "api_key_id": 7,
    "access_token": "minted.jwt.token",
}
ANSWER = {"answer": "TP53 [PMID:1]", "citations": [{"pmid": "1"}]}
BODY = {"query": "What does TP53 do?"}


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
def redis():
    fake = FakeRedis()
    with patch.object(v1.store, "redis", fake), patch.object(v1.store, "usage_redis", fake):
        yield fake


@pytest.fixture
def upstream():
    forward = AsyncMock(return_value=(200, ANSWER))
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
    assert resp.json() == ANSWER
    assert resp.headers["X-RateLimit-Limit"] == str(Config.V1_RATE_LIMIT_PER_MINUTE)
    assert resp.headers["X-Request-Id"]

    kwargs = upstream.call_args.kwargs
    assert kwargs["url"] == "http://rag:8096/v1/query"
    assert kwargs["method"] == "POST" and kwargs["body"] == BODY
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
    resp = _post(client, body={"query": "different"}, idem="k")
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
    upstream.return_value = (200, ANSWER)
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


def test_unauthenticated_v1_is_rejected(client):
    assert client.post("/v1/literature/answers", json=BODY).status_code == 401


def test_redis_outage_fails_open_for_limits_and_idempotency(client, upstream):
    broken = BrokenRedis()
    with patch.object(v1.store, "redis", broken), patch.object(v1.store, "usage_redis", broken):
        resp = _post(client, idem="x")
    assert resp.status_code == 200


def test_store_edge_cases():
    import asyncio
    with patch("app.services.v1_store.aioredis.from_url", return_value=FakeRedis()):
        store = V1Store("redis://x", "redis://y")
    store.redis.kv["gateway:v1:quota:1:r"] = "not-a-number"
    assert asyncio.run(store.quota_remaining("1", "r")) is None
    key = store._idem_key("s", "k")
    assert asyncio.run(store.idempotency_begin("s", "k", "f")) == {"state": "new"}
    store.redis.kv.pop(key)
    store.redis.set = AsyncMock(return_value=None)
    assert asyncio.run(store.idempotency_begin("s", "k", "f")) == {"state": "in_progress"}


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


def test_store_uses_memory_without_redis_url():
    from app.services.v1_store import MemoryStore

    with patch("app.services.v1_store.aioredis.from_url", return_value=FakeRedis()):
        assert isinstance(V1Store("", "redis://usage").redis, MemoryStore)
        assert isinstance(V1Store("redis://v1", "redis://usage").redis, FakeRedis)

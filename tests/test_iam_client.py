"""IAMClient (app/services/iam_client.py): Redis-backed token-validation
cache (get/set/evict), the validate() flow combining local decode_token()
pre-check + cache + remote /auth/validate with timeout-retry and
fail-closed error handling, org-context propagation/normalization, and
pub/sub cache invalidation. Also covers the PHI P1-5 HMAC cache-signing
remediation (TestCacheIntegrity): a cache entry with no valid MAC, a
tampered body, a cross-secret signature, or a replayed token must all be
rejected as a clean miss rather than trusted, and validate() must fall
through to a real check rather than ever surfacing attacker-controlled
cache content.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.config import Config
from app.services.iam_client import IAMClient, _sign_cache_entry


class _FakeAsyncRedis:
    """In-memory stand-in for the subset of redis.asyncio IAMClient uses --
    a real backing store is needed for the cache-integrity tests below
    (roundtrip / tamper / replay), unlike the plain-value AsyncMock the
    other tests in this file use for the remote-validate flow."""

    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def setex(self, key, ttl, value):
        self.store[key] = value

    async def delete(self, key):
        self.store.pop(key, None)


@pytest.fixture
def iam_client():
    """A real IAMClient built against mocked Redis/httpx, returned as
    (client, mock_redis, mock_http) with local decode_token() stubbed to
    succeed so tests focus on the cache/remote-validate flow below it."""
    # Use MagicMock so pubsub() returns a plain mock (not a coroutine).
    # Async methods are explicitly overridden with AsyncMock.
    mock_redis = MagicMock()
    mock_redis.get = AsyncMock()
    mock_redis.setex = AsyncMock()
    mock_redis.delete = AsyncMock()
    mock_http = AsyncMock()
    with (
        patch("app.services.iam_client.aioredis.from_url", return_value=mock_redis),
        patch("app.services.iam_client.httpx.AsyncClient", return_value=mock_http),
    ):
        client = IAMClient("http://iam-service", "redis://localhost")
    # IAM Foundation gateway integration: validate() now calls
    # client._shared.decode_token(...) (the real shared omnibioai-iam-client
    # package -- see app/services/iam_client.py) before ever reaching the
    # remote-validate code these existing tests exercise. Stubbed to
    # succeed by default so those tests keep covering cache/remote-validate
    # behavior unaffected; test_validate_local_decode_failure_returns_none_
    # without_remote_call below covers the new failure path this stub
    # bypasses everywhere else.
    client._shared.decode_token = AsyncMock(return_value={"sub": "test-user", "roles": [], "permissions": []})
    return client, mock_redis, mock_http


async def test_get_cached_hit(iam_client):
    """PHI P1-5: a cache hit now requires a valid HMAC prefix -- raw
    unsigned JSON (the pre-fix shape) is covered separately below by
    test_get_cached_rejects_unsigned_legacy_entry, which asserts the
    opposite (rejected, not returned)."""
    client, mock_redis, _ = iam_client
    user = {"user_id": "42", "valid": True}
    body = json.dumps(user)
    mock_redis.get.return_value = f"{_sign_cache_entry('tok', body)}:{body}"
    result = await client._get_cached("tok")
    assert result == user
    mock_redis.get.assert_called_once_with("gateway:iam:tok")


async def test_get_cached_miss_returns_none(iam_client):
    """No cached entry for the token -- _get_cached returns None."""
    client, mock_redis, _ = iam_client
    mock_redis.get.return_value = None
    assert await client._get_cached("tok") is None


async def test_get_cached_redis_error_returns_none(iam_client):
    """A Redis error on GET fails safe: treated as a cache miss, not
    propagated as an exception."""
    client, mock_redis, _ = iam_client
    mock_redis.get.side_effect = ConnectionError("redis down")
    assert await client._get_cached("tok") is None


async def test_set_cached_calls_setex(iam_client):
    """PHI P1-5: the stored value is now `<mac>:<json>`, not bare JSON --
    verify the MAC matches and the body round-trips, rather than asserting
    the old unsigned exact-bytes shape."""
    client, mock_redis, _ = iam_client
    user = {"user_id": "1"}
    await client._set_cached("tok", user, ttl=60)
    mock_redis.setex.assert_called_once()
    key, ttl, value = mock_redis.setex.call_args[0]
    assert key == "gateway:iam:tok"
    assert ttl == 60
    mac, sep, body = value.partition(":")
    assert sep == ":"
    assert body == json.dumps(user)
    assert mac == _sign_cache_entry("tok", body)


async def test_set_cached_default_ttl(iam_client):
    """Calling _set_cached without an explicit ttl uses the 300s default."""
    client, mock_redis, _ = iam_client
    await client._set_cached("tok", {"user_id": "1"})
    args = mock_redis.setex.call_args[0]
    assert args[1] == 300


async def test_set_cached_redis_error_silenced(iam_client):
    """A Redis error on SETEX is swallowed -- caching is best-effort."""
    client, mock_redis, _ = iam_client
    mock_redis.setex.side_effect = RuntimeError("redis down")
    await client._set_cached("tok", {"user_id": "1"})  # must not raise


async def test_evict_calls_delete(iam_client):
    """evict() deletes the token's cache key under the gateway:iam: prefix."""
    client, mock_redis, _ = iam_client
    await client.evict("tok")
    mock_redis.delete.assert_called_once_with("gateway:iam:tok")


async def test_evict_redis_error_silenced(iam_client):
    """A Redis error on DELETE is swallowed rather than raised."""
    client, mock_redis, _ = iam_client
    mock_redis.delete.side_effect = RuntimeError("redis down")
    await client.evict("tok")  # must not raise


async def test_validate_cache_hit_returns_cached(iam_client):
    """A signed cache hit is returned directly, with no remote HTTP call."""
    client, mock_redis, mock_http = iam_client
    user = {"user_id": "7", "valid": True}
    body = json.dumps(user)
    mock_redis.get.return_value = f"{_sign_cache_entry('tok', body)}:{body}"
    result = await client.validate("tok")
    assert result == user
    mock_http.post.assert_not_called()


async def test_validate_remote_valid_returns_user(iam_client):
    """A cache miss falls through to /auth/validate; a valid response's
    fields (user_id/email/roles/valid) are returned in the result dict."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {
        "valid": True,
        "user_id": "99",
        "email": "u@test.com",
        "roles": ["admin"],
        "permissions": ["write"],
    }
    mock_http.post.return_value = resp
    result = await client.validate("tok")
    assert result is not None
    assert result["user_id"] == "99"
    assert result["email"] == "u@test.com"
    assert result["roles"] == ["admin"]
    assert result["valid"] is True


async def test_validate_remote_propagates_org_context(iam_client):
    """Phase 1 PR3: a fresh /auth/validate response carrying org_id/
    org_role/schema_version must actually end up in the cached user dict,
    not be silently dropped the way the old 5-field reconstruction would
    have done."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {
        "valid": True,
        "user_id": "99",
        "email": "u@test.com",
        "roles": ["admin"],
        "permissions": ["write"],
        "org_id": 7,
        "org_role": ["org_admin"],
        "schema_version": 2,
    }
    mock_http.post.return_value = resp
    result = await client.validate("tok")
    # PR14.5D: str, not the raw int /auth/validate returns -- see
    # test_validate_remote_casts_org_id_to_string_for_shared_cache_
    # compatibility below for why.
    assert result["org_id"] == "7"
    assert result["org_role"] == ["org_admin"]
    assert result["schema_version"] == 2


async def test_validate_remote_casts_org_id_to_string_for_shared_cache_compatibility(iam_client):
    """PR14.5D regression test: this cache lives under the same `iam:
    {token}` Redis key namespace the shared omnibioai-iam-client
    package's AsyncIAMClient reads from (every other IAM-integrated
    service -- billing, rag, model-registry -- uses that package). Its
    UserContext model declares org_id: Optional[str], strict in
    pydantic v2 -- caching the raw int /auth/validate returns broke any
    of those services' first read of a token gateway had already
    validated and cached, misreporting it as an invalid token. See this
    file's iam_client.py::validate() for the live-reproduction note."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {
        "valid": True, "user_id": "1", "email": "u@test.com",
        "roles": [], "permissions": [], "org_id": 1,
    }
    mock_http.post.return_value = resp
    result = await client.validate("tok")
    assert result["org_id"] == "1"
    assert isinstance(result["org_id"], str)


async def test_validate_remote_defaults_org_context_when_absent(iam_client):
    """A /auth/validate response with none of the PR3 fields (e.g. served
    by an auth-service instance mid-rolling-deploy that hasn't picked up
    this change yet) must still produce a usable user dict with sensible
    defaults, not a KeyError."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {
        "valid": True,
        "user_id": "42",
        "email": "old@test.com",
        "roles": ["user"],
        "permissions": [],
    }
    mock_http.post.return_value = resp
    result = await client.validate("tok")
    assert result["org_id"] is None
    assert result["org_role"] == []
    assert result["schema_version"] == 1


async def test_validate_cache_hit_with_pre_pr3_shaped_entry(iam_client):
    """Redis mixed-version cache-*shape* compatibility (org_id/org_role/
    schema_version keys absent, not even null) is still honored -- but only
    once the entry carries a valid HMAC. Sign the legacy-shaped body here so
    this test still isolates the thing it's meant to cover (missing PR3
    fields, not the separate unsigned-entry question, which is covered by
    test_validate_cache_hit_with_legacy_unsigned_entry_falls_through_to_
    remote below)."""
    client, mock_redis, mock_http = iam_client
    pre_pr3_cached_entry = {
        "user_id": "7",
        "email": "u@test.com",
        "roles": ["admin"],
        "permissions": ["write"],
        "valid": True,
    }
    body = json.dumps(pre_pr3_cached_entry)
    mock_redis.get.return_value = f"{_sign_cache_entry('tok', body)}:{body}"

    result = await client.validate("tok")

    assert result == pre_pr3_cached_entry  # returned as-is, cache hit skips remote entirely
    mock_http.post.assert_not_called()
    # Downstream code reading org context off a cache-hit result must use
    # .get() with a default -- this dict genuinely has no org_id key at
    # all, distinguishing it from a fresh v2 response where org_id is
    # explicitly present as None.
    assert pre_pr3_cached_entry.get("org_id") is None


async def test_validate_cache_hit_with_legacy_unsigned_entry_falls_through_to_remote(iam_client):
    """PHI P1-5: a cache entry written before this fix existed (raw JSON,
    no HMAC prefix at all -- the exact shape the OLD version of this test
    asserted was trusted outright) must now be rejected and fall through to
    a real /auth/validate round trip, not returned as a trusted identity.
    This is the deliberate contract change this remediation makes: a
    pre-fix entry self-heals (gets evicted, re-cached signed on next
    validate) instead of being grandfathered in as trusted."""
    client, mock_redis, mock_http = iam_client
    legacy_unsigned_entry = {
        "user_id": "7", "email": "u@test.com", "roles": ["admin"],
        "permissions": ["write"], "valid": True,
    }
    mock_redis.get.return_value = json.dumps(legacy_unsigned_entry)
    resp = MagicMock()
    resp.json.return_value = {
        "valid": True, "user_id": "7", "email": "u@test.com",
        "roles": ["admin"], "permissions": ["write"],
    }
    mock_http.post.return_value = resp

    result = await client.validate("tok")

    mock_redis.delete.assert_called_once_with("gateway:iam:tok")
    mock_http.post.assert_called_once()
    assert result["user_id"] == "7"


async def test_validate_remote_invalid_evicts_and_returns_none(iam_client):
    """A {"valid": False} remote response returns None and evicts any
    stale cache entry for the token."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {"valid": False}
    mock_http.post.return_value = resp
    result = await client.validate("tok")
    assert result is None
    mock_redis.delete.assert_called_once_with("gateway:iam:tok")


async def test_validate_timeout_first_attempt_retries_and_succeeds(iam_client):
    """A timeout on the first /auth/validate attempt is retried once and,
    on success, returns the second attempt's result."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {
        "valid": True,
        "user_id": "55",
        "email": "",
        "roles": [],
        "permissions": [],
    }
    mock_http.post.side_effect = [httpx.TimeoutException("t/o"), resp]
    result = await client.validate("tok")
    assert result is not None
    assert result["user_id"] == "55"


async def test_validate_timeout_both_attempts_returns_none(iam_client):
    """A timeout on both /auth/validate attempts fails closed: None, not
    an unhandled exception."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    mock_http.post.side_effect = httpx.TimeoutException("t/o")
    assert await client.validate("tok") is None


async def test_validate_generic_exception_returns_none(iam_client):
    """Any non-timeout exception from the remote call also fails closed
    to None rather than propagating."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    mock_http.post.side_effect = RuntimeError("network error")
    assert await client.validate("tok") is None


async def test_subscribe_invalidation_calls_callback_on_message(iam_client):
    """Each pubsub "message" event with a JSON {user_id, token} payload
    invokes the callback with those two values, in order; the initial
    "subscribe" ack event is ignored."""
    client, mock_redis, _ = iam_client
    received = []

    async def on_invalidate(user_id, token):
        received.append((user_id, token))

    messages = [
        {"type": "subscribe", "data": 1},
        {"type": "message", "data": json.dumps({"user_id": "u1", "token": "t1"})},
        {"type": "message", "data": json.dumps({"user_id": "u2", "token": "t2"})},
    ]

    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()

    async def listen_gen():
        for msg in messages:
            yield msg

    mock_pubsub.listen = listen_gen
    mock_redis.pubsub.return_value = mock_pubsub

    await client.subscribe_invalidation(on_invalidate)

    assert received == [("u1", "t1"), ("u2", "t2")]


async def test_subscribe_invalidation_bad_json_silenced(iam_client):
    """A non-JSON message payload is swallowed -- the callback is never
    invoked and no exception escapes."""
    client, mock_redis, _ = iam_client
    called = []

    async def on_invalidate(user_id, token):
        called.append(True)

    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()

    async def listen_gen():
        yield {"type": "message", "data": "not-json"}

    mock_pubsub.listen = listen_gen
    mock_redis.pubsub.return_value = mock_pubsub

    await client.subscribe_invalidation(on_invalidate)

    assert called == []


async def test_subscribe_invalidation_callback_exception_silenced(iam_client):
    """An exception raised by the caller's own callback must not escape
    subscribe_invalidation() or abort the listen loop."""
    client, mock_redis, _ = iam_client

    async def on_invalidate(user_id, token):
        raise RuntimeError("callback error")

    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()

    async def listen_gen():
        yield {"type": "message", "data": json.dumps({"user_id": "u", "token": "t"})}

    mock_pubsub.listen = listen_gen
    mock_redis.pubsub.return_value = mock_pubsub

    await client.subscribe_invalidation(on_invalidate)  # must not raise


async def test_subscribe_invalidation_missing_fields_defaults(iam_client):
    """A message payload missing user_id/token entirely still invokes the
    callback, defaulting both to empty strings rather than raising a
    KeyError."""
    client, mock_redis, _ = iam_client
    received = []

    async def on_invalidate(user_id, token):
        received.append((user_id, token))

    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()

    async def listen_gen():
        yield {"type": "message", "data": json.dumps({})}

    mock_pubsub.listen = listen_gen
    mock_redis.pubsub.return_value = mock_pubsub

    await client.subscribe_invalidation(on_invalidate)

    assert received == [("", "")]


# ---------------------------------------------------------------------------
# IAM Foundation gateway integration: local decode_token() pre-check
# (RS256/JWKS-or-HS256 signature + expiry), delegated to the shared
# omnibioai-iam-client package, ahead of the pre-existing remote-validate
# flow every other test in this file exercises via the iam_client fixture's
# default-succeeding stub.
# ---------------------------------------------------------------------------

async def test_validate_local_decode_failure_returns_none_without_remote_call(iam_client):
    """A token that fails local signature/expiry verification must be
    rejected immediately -- 401-equivalent None -- without ever reaching
    the remote /auth/validate call."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    client._shared.decode_token = AsyncMock(side_effect=Exception("bad signature"))

    result = await client.validate("tok")

    assert result is None
    mock_http.post.assert_not_called()


async def test_validate_local_decode_success_proceeds_to_remote_call(iam_client):
    """A token that passes local verification still isn't trusted on its
    own -- the remote call remains authoritative for revocation, so it
    must still run."""
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {
        "valid": True,
        "user_id": "1",
        "email": "u@test.com",
        "roles": [],
        "permissions": [],
    }
    mock_http.post.return_value = resp

    result = await client.validate("tok")

    assert result is not None
    mock_http.post.assert_called_once()


# ---------------------------------------------------------------------------
# PHI P1-5 remediation: IAM Redis-cache integrity (HMAC signing).
#
# Mirrors omnibioai-tes's tests/test_iam_integration.py::TestCacheIntegrity
# (the reference pattern for this fix across the platform) rather than
# inventing a different shape. Uses a real in-memory fake Redis (see
# _FakeAsyncRedis above) instead of the plain-value AsyncMock the rest of
# this file uses, since roundtrip/tamper/replay scenarios need genuine
# read-your-own-write state, not a fixed canned return value.
# ---------------------------------------------------------------------------

@pytest.fixture
def signed_cache_client():
    """A real IAMClient backed by _FakeAsyncRedis (genuine read-your-own-
    write state, unlike the plain-value AsyncMock the rest of this file
    uses), returned as (client, fake_redis, mock_http)."""
    fake_redis = _FakeAsyncRedis()
    mock_http = AsyncMock()
    with (
        patch("app.services.iam_client.aioredis.from_url", return_value=fake_redis),
        patch("app.services.iam_client.httpx.AsyncClient", return_value=mock_http),
    ):
        client = IAMClient("http://iam-service", "redis://localhost")
    client._shared = AsyncMock()
    client._shared.decode_token = AsyncMock(return_value={"sub": "test-user", "roles": [], "permissions": []})
    return client, fake_redis, mock_http


class TestCacheIntegrity:
    """PHI P1-5: HMAC-signed IAM cache entries -- a valid roundtrip must
    still work, and every way an entry could be forged, tampered,
    cross-secret, or replayed must be rejected as a clean cache miss."""

    async def test_roundtrip_returns_exactly_what_was_cached(self, signed_cache_client):
        """A value written via _set_cached and read back via _get_cached
        round-trips unchanged."""
        client, _, _ = signed_cache_client
        user = {"user_id": "u1", "org_id": "org_a", "permissions": ["write"], "valid": True}
        await client._set_cached("tok-1", user)
        assert await client._get_cached("tok-1") == user

    async def test_entry_written_directly_to_redis_is_rejected(self, signed_cache_client):
        """The exact live-proven attack class (TES PR #22): something with
        Redis write access (not this process) sets `gateway:iam:<token>` to
        attacker-chosen JSON with no valid MAC prefix -- must be treated as
        a cache miss, not a trusted identity, and evicted so a second,
        cheaper read can't accidentally trust it either."""
        client, fake_redis, _ = signed_cache_client
        forged = json.dumps({"user_id": "attacker", "org_id": "any-org", "roles": ["admin"], "permissions": ["write"], "valid": True})
        await fake_redis.setex("gateway:iam:forged-token", 60, forged)
        assert await client._get_cached("forged-token") is None
        assert "gateway:iam:forged-token" not in fake_redis.store

    async def test_legacy_unsigned_entry_from_before_this_fix_is_a_clean_miss(self, signed_cache_client):
        """A raw-JSON entry with no MAC prefix at all (the pre-fix shape)
        is rejected as a cache miss, not trusted as a legacy format."""
        client, fake_redis, _ = signed_cache_client
        await fake_redis.setex("gateway:iam:old-token", 60, json.dumps({"user_id": "u1", "valid": True}))
        assert await client._get_cached("old-token") is None

    async def test_tampered_body_with_stale_mac_is_rejected(self, signed_cache_client):
        """Flip a byte in an otherwise legitimately-signed entry's body
        (e.g. escalate permissions after the fact) -- the MAC no longer
        matches and the entry must be rejected, not silently accepted with
        the tampered value."""
        client, fake_redis, _ = signed_cache_client
        user = {"user_id": "u1", "org_id": "org_a", "roles": [], "permissions": [], "valid": True}
        await client._set_cached("tok-2", user)
        raw = fake_redis.store["gateway:iam:tok-2"]
        mac, _, body = raw.partition(":")
        tampered_body = body.replace('"permissions": []', '"permissions": ["admin"]')
        fake_redis.store["gateway:iam:tok-2"] = f"{mac}:{tampered_body}"
        assert await client._get_cached("tok-2") is None

    async def test_wrong_key_signed_entry_is_rejected(self, signed_cache_client, monkeypatch):
        """An entry legitimately signed under a *different* JWT_SECRET (a
        cross-secret/cross-environment or rotated-secret entry) must not
        verify here."""
        client, fake_redis, _ = signed_cache_client
        with patch("app.services.iam_client.Config.JWT_SECRET", "a-different-secret"):
            await client._set_cached("tok-3", {"user_id": "u1", "valid": True})
        assert await client._get_cached("tok-3") is None

    async def test_cross_token_replay_is_rejected(self, signed_cache_client):
        """An attacker with Redis read+write access reads a legitimately
        signed entry cached under someone else's real token and copies it
        verbatim onto a token of their own choosing. Binding the token into
        the MAC (not just the body) must reject this."""
        client, fake_redis, _ = signed_cache_client
        real_user = {"user_id": "victim", "org_id": "org_a", "roles": [], "permissions": ["write"], "valid": True}
        await client._set_cached("victim-real-token", real_user)
        stolen_blob = fake_redis.store["gateway:iam:victim-real-token"]
        await fake_redis.setex("gateway:iam:attacker-chosen-token", 60, stolen_blob)
        assert await client._get_cached("attacker-chosen-token") is None
        assert await client._get_cached("victim-real-token") == real_user

    async def test_validate_falls_through_to_real_check_when_cache_is_forged(self, signed_cache_client):
        """End-to-end through validate(): a forged cache entry must not
        short-circuit local decode / remote /auth/validate -- it must
        behave exactly like an ordinary cache miss, and the attacker-chosen
        roles/org_id/user_id in the forged entry must never become the
        value validate() returns."""
        client, fake_redis, mock_http = signed_cache_client
        forged = json.dumps({"user_id": "attacker", "org_id": "any-org", "roles": ["superadmin"], "permissions": ["*"], "valid": True})
        await fake_redis.setex("gateway:iam:forged-token", 60, forged)

        resp = MagicMock()
        resp.json.return_value = {
            "valid": True, "user_id": "real-user", "email": "u@test.com",
            "roles": ["user"], "permissions": ["read"],
        }
        mock_http.post.return_value = resp

        result = await client.validate("forged-token")

        client._shared.decode_token.assert_awaited_once()
        mock_http.post.assert_called_once()
        assert result["user_id"] == "real-user"
        assert result["roles"] == ["user"]
        assert "attacker" not in json.dumps(result)
        assert "superadmin" not in json.dumps(result)

    async def test_validate_cache_miss_still_authenticates_normally(self, signed_cache_client):
        """An ordinary cache miss still validates remotely, and the result
        is re-cached signed so a second validate() is a genuine hit
        without a second remote call."""
        client, fake_redis, mock_http = signed_cache_client
        resp = MagicMock()
        resp.json.return_value = {
            "valid": True, "user_id": "u1", "email": "u@test.com",
            "roles": [], "permissions": [],
        }
        mock_http.post.return_value = resp

        result = await client.validate("fresh-token")

        assert result["user_id"] == "u1"
        mock_http.post.assert_called_once()
        # Re-cached, and now signed -- a second validate() is a genuine hit.
        second = await client.validate("fresh-token")
        assert second == result
        mock_http.post.assert_called_once()  # not called again

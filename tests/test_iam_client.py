"""Tests for app/services/iam_client.py — IAMClient unit tests."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.iam_client import IAMClient


@pytest.fixture
def iam_client():
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
    client, mock_redis, _ = iam_client
    user = {"user_id": "42", "valid": True}
    mock_redis.get.return_value = json.dumps(user)
    result = await client._get_cached("tok")
    assert result == user
    mock_redis.get.assert_called_once_with("gateway:iam:tok")


async def test_get_cached_miss_returns_none(iam_client):
    client, mock_redis, _ = iam_client
    mock_redis.get.return_value = None
    assert await client._get_cached("tok") is None


async def test_get_cached_redis_error_returns_none(iam_client):
    client, mock_redis, _ = iam_client
    mock_redis.get.side_effect = ConnectionError("redis down")
    assert await client._get_cached("tok") is None


async def test_set_cached_calls_setex(iam_client):
    client, mock_redis, _ = iam_client
    user = {"user_id": "1"}
    await client._set_cached("tok", user, ttl=60)
    mock_redis.setex.assert_called_once_with("gateway:iam:tok", 60, json.dumps(user))


async def test_set_cached_default_ttl(iam_client):
    client, mock_redis, _ = iam_client
    await client._set_cached("tok", {"user_id": "1"})
    args = mock_redis.setex.call_args[0]
    assert args[1] == 300


async def test_set_cached_redis_error_silenced(iam_client):
    client, mock_redis, _ = iam_client
    mock_redis.setex.side_effect = RuntimeError("redis down")
    await client._set_cached("tok", {"user_id": "1"})  # must not raise


async def test_evict_calls_delete(iam_client):
    client, mock_redis, _ = iam_client
    await client.evict("tok")
    mock_redis.delete.assert_called_once_with("gateway:iam:tok")


async def test_evict_redis_error_silenced(iam_client):
    client, mock_redis, _ = iam_client
    mock_redis.delete.side_effect = RuntimeError("redis down")
    await client.evict("tok")  # must not raise


async def test_validate_cache_hit_returns_cached(iam_client):
    client, mock_redis, mock_http = iam_client
    user = {"user_id": "7", "valid": True}
    mock_redis.get.return_value = json.dumps(user)
    result = await client.validate("tok")
    assert result == user
    mock_http.post.assert_not_called()


async def test_validate_remote_valid_returns_user(iam_client):
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
    """Redis mixed-version cache compatibility: a cache entry written by a
    gateway process running BEFORE this change (no org_id/org_role/
    schema_version keys at all in the stored JSON, not even null values)
    must still be read back and used successfully -- this is the actual
    scenario during a rolling deploy, where old and new gateway instances'
    cache writes coexist in the same Redis for up to the 300s TTL."""
    client, mock_redis, mock_http = iam_client
    pre_pr3_cached_entry = {
        "user_id": "7",
        "email": "u@test.com",
        "roles": ["admin"],
        "permissions": ["write"],
        "valid": True,
    }
    mock_redis.get.return_value = json.dumps(pre_pr3_cached_entry)

    result = await client.validate("tok")

    assert result == pre_pr3_cached_entry  # returned as-is, cache hit skips remote entirely
    mock_http.post.assert_not_called()
    # Downstream code reading org context off a cache-hit result must use
    # .get() with a default -- this dict genuinely has no org_id key at
    # all, distinguishing it from a fresh v2 response where org_id is
    # explicitly present as None.
    assert pre_pr3_cached_entry.get("org_id") is None


async def test_validate_remote_invalid_evicts_and_returns_none(iam_client):
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    resp = MagicMock()
    resp.json.return_value = {"valid": False}
    mock_http.post.return_value = resp
    result = await client.validate("tok")
    assert result is None
    mock_redis.delete.assert_called_once_with("gateway:iam:tok")


async def test_validate_timeout_first_attempt_retries_and_succeeds(iam_client):
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
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    mock_http.post.side_effect = httpx.TimeoutException("t/o")
    assert await client.validate("tok") is None


async def test_validate_generic_exception_returns_none(iam_client):
    client, mock_redis, mock_http = iam_client
    mock_redis.get.return_value = None
    mock_http.post.side_effect = RuntimeError("network error")
    assert await client.validate("tok") is None


async def test_subscribe_invalidation_calls_callback_on_message(iam_client):
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

"""omni_sk_ API keys at the gateway: IAMClient.validate_api_key exchanges a
key at omnibioai-auth for a short-lived access token, caches the result under
the key's hash (HMAC-signed, TTL bounded by the token's expiry), rejects every
failure closed, and is disabled without API_KEY_EXCHANGE_SECRET. AuthMiddleware
routes omni_sk_ bearers to it, forwards the minted JWT (never the key)
downstream with token_type=api_key, and revocation messages evict the cache.
"""
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import app.main as _main_mod
from app.core.config import Config
from app.services.iam_client import IAMClient, _sign_cache_entry, api_key_hash, is_api_key

KEY = "omni_sk_" + "a" * 40
EXCHANGE = {
    "access_token": "minted.jwt.token",
    "expires_in": 300,
    "api_key_id": 7,
    "organization_id": 42,
    "user_id": 5,
    "permissions": ["dataset.read"],
}


class _FakeAsyncRedis:
    def __init__(self):
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key):
        return self.store.get(key)

    async def setex(self, key, ttl, value):
        self.store[key] = value
        self.ttls[key] = ttl

    async def delete(self, key):
        self.store.pop(key, None)


def _response(status, body):
    res = MagicMock()
    res.status_code = status
    res.json.return_value = body
    return res


@pytest.fixture
def exchange_secret(monkeypatch):
    monkeypatch.setattr(Config, "API_KEY_EXCHANGE_SECRET", "s3cret")


@pytest.fixture
def iam():
    redis = _FakeAsyncRedis()
    http = AsyncMock()
    with (
        patch("app.services.iam_client.aioredis.from_url", return_value=redis),
        patch("app.services.iam_client.httpx.AsyncClient", return_value=http),
    ):
        client = IAMClient("http://iam-service", "redis://localhost")
    return client, redis, http


def test_key_helpers():
    assert is_api_key(KEY) and not is_api_key("eyJhbGciOi.jwt.token")
    assert len(api_key_hash(KEY)) == 64 and KEY not in api_key_hash(KEY)


def test_disabled_without_exchange_secret(iam, monkeypatch):
    client, _, http = iam
    monkeypatch.setattr(Config, "API_KEY_EXCHANGE_SECRET", "")
    assert asyncio.run(client.validate_api_key(KEY)) is None
    http.post.assert_not_called()


def test_non_key_token_is_rejected_without_a_call(iam, exchange_secret):
    client, _, http = iam
    assert asyncio.run(client.validate_api_key("not-a-key")) is None
    http.post.assert_not_called()


def test_exchange_success_builds_identity_and_caches_by_hash(iam, exchange_secret):
    client, redis, http = iam
    http.post.return_value = _response(200, EXCHANGE)

    user = asyncio.run(client.validate_api_key(KEY))
    assert user["user_id"] == "5" and user["org_id"] == "42"
    assert user["permissions"] == ["dataset.read"]
    assert user["token_type"] == "api_key" and user["api_key_id"] == 7
    assert user["access_token"] == "minted.jwt.token"

    url = http.post.call_args.args[0]
    assert url == "http://iam-service/auth/api-keys/exchange"
    assert http.post.call_args.kwargs["headers"] == {"X-Api-Key-Exchange-Secret": "s3cret"}
    assert http.post.call_args.kwargs["json"] == {"api_key": KEY}

    cache_key = f"gateway:apikey:{api_key_hash(KEY)}"
    assert list(redis.store) == [cache_key]
    assert KEY not in cache_key and KEY not in redis.store[cache_key]
    assert redis.ttls[cache_key] == min(Config.API_KEY_CACHE_TTL, 300 - 30)

    http.post.reset_mock()
    assert asyncio.run(client.validate_api_key(KEY)) == user
    http.post.assert_not_called()


def test_cache_ttl_never_outlives_minted_token(iam, exchange_secret):
    client, redis, http = iam
    http.post.return_value = _response(200, {**EXCHANGE, "expires_in": 20})
    assert asyncio.run(client.validate_api_key(KEY)) is not None
    assert redis.store == {}


@pytest.mark.parametrize("status", [401, 403, 503, 500])
def test_exchange_failure_is_rejected_and_evicted(iam, exchange_secret, status):
    client, redis, http = iam
    redis.store[f"gateway:apikey:{api_key_hash(KEY)}"] = "stale"
    http.post.return_value = _response(status, {"detail": "nope"})
    assert asyncio.run(client.validate_api_key(KEY)) is None
    assert redis.store == {}


def test_timeout_retries_once_then_fails_closed(iam, exchange_secret):
    client, _, http = iam
    http.post.side_effect = httpx.TimeoutException("slow")
    assert asyncio.run(client.validate_api_key(KEY)) is None
    assert http.post.call_count == 2


def test_timeout_then_success(iam, exchange_secret):
    client, _, http = iam
    http.post.side_effect = [httpx.TimeoutException("slow"), _response(200, EXCHANGE)]
    assert asyncio.run(client.validate_api_key(KEY))["api_key_id"] == 7


def test_malformed_exchange_response_fails_closed(iam, exchange_secret):
    client, _, http = iam
    http.post.return_value = _response(200, {"unexpected": True})
    assert asyncio.run(client.validate_api_key(KEY)) is None


def test_tampered_or_replayed_cache_entry_is_not_trusted(iam, exchange_secret):
    client, redis, http = iam
    key_hash = api_key_hash(KEY)
    forged = json.dumps({"user_id": "1", "org_id": "999", "access_token": "forged", "api_key_id": 1})
    redis.store[f"gateway:apikey:{key_hash}"] = f"deadbeef:{forged}"
    http.post.return_value = _response(401, {})
    assert asyncio.run(client.validate_api_key(KEY)) is None

    other_hash = api_key_hash("omni_sk_" + "b" * 40)
    redis.store[f"gateway:apikey:{key_hash}"] = f"{_sign_cache_entry(f'apikey:{other_hash}', forged)}:{forged}"
    assert asyncio.run(client.validate_api_key(KEY)) is None


def test_evict_api_key_and_cache_errors_are_swallowed(iam, exchange_secret):
    client, redis, _ = iam
    redis.store[f"gateway:apikey:{api_key_hash(KEY)}"] = "x"
    asyncio.run(client.evict_api_key(api_key_hash(KEY)))
    assert redis.store == {}

    broken = MagicMock()
    broken.get = AsyncMock(side_effect=Exception("down"))
    broken.setex = AsyncMock(side_effect=Exception("down"))
    broken.delete = AsyncMock(side_effect=Exception("down"))
    client.redis = broken
    assert asyncio.run(client._get_cached_api_key("h")) is None
    asyncio.run(client._set_cached_api_key("h", {}, 30))
    asyncio.run(client.evict_api_key("h"))


def test_subscribe_invalidation_passes_api_key_hash(iam):
    client, _, _ = iam
    messages = [
        {"type": "subscribe"},
        {"type": "message", "data": json.dumps({"api_key_hash": "abc"})},
        {"type": "message", "data": json.dumps({"user_id": "u", "token": "t"})},
    ]

    async def listen():
        for m in messages:
            yield m

    pubsub = MagicMock()
    pubsub.subscribe = AsyncMock()
    pubsub.listen = listen
    client.redis = MagicMock()
    client.redis.pubsub.return_value = pubsub
    seen = []

    async def on_invalidate(user_id, token, api_key_hash=""):
        seen.append((user_id, token, api_key_hash))

    asyncio.run(client.subscribe_invalidation(on_invalidate))
    assert seen == [("", "", "abc"), ("u", "t", "")]


def test_invalidation_loop_evicts_api_key_cache():
    captured = []

    async def fake_subscribe(cb):
        captured.append(cb)
        raise asyncio.CancelledError

    with (
        patch.object(_main_mod.iam, "subscribe_invalidation", fake_subscribe),
        patch.object(_main_mod.iam, "evict", AsyncMock()) as evict,
        patch.object(_main_mod.iam, "evict_api_key", AsyncMock()) as evict_key,
    ):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(_main_mod._invalidation_loop())
        asyncio.run(captured[0]("", "", "hash1"))
    evict.assert_not_called()
    evict_key.assert_awaited_once_with("hash1")


API_KEY_USER = {
    "user_id": "5",
    "email": "",
    "roles": [],
    "permissions": ["dataset.read"],
    "org_id": "42",
    "org_role": [],
    "token_type": "api_key",
    "api_key_id": 7,
    "access_token": "minted.jwt.token",
}


def test_middleware_rejects_invalid_api_key(client):
    with (
        patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=None)) as vk,
        patch.object(_main_mod.iam, "validate", AsyncMock()) as v,
    ):
        resp = client.get("/rag/query", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid api key"}
    vk.assert_awaited_once_with(KEY)
    v.assert_not_called()


def test_middleware_forwards_minted_token_not_the_key(client):
    with (
        patch.object(_main_mod.iam, "validate_api_key", AsyncMock(return_value=API_KEY_USER)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(_main_mod.hpc, "evaluate", AsyncMock(return_value={"allow": True})),
        patch("app.routes.gateway.proxy.forward", AsyncMock(return_value=(200, {"ok": True}))) as forward,
    ):
        resp = client.get("/rag/query", headers={"Authorization": f"Bearer {KEY}"})
    assert resp.status_code == 200
    headers = forward.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer minted.jwt.token"
    assert KEY not in json.dumps(headers)
    assert headers["X-Token-Type"] == "api_key"
    assert headers["X-Client-ID"] == "api_key:7"
    assert headers["X-Organization-ID"] == "42"
    assert headers["X-Permissions"] == "dataset.read"

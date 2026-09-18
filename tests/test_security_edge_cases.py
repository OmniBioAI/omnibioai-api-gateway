"""Additional fail-closed checks at the IAM/network boundary: a cached
identity value that isn't valid JSON must be treated as a cache miss
rather than trusted or crashing, and a remote validation response that
lacks the fields IAMClient._shared.decode_token needs must fail closed
(return None) instead of returning a partially-populated identity.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.iam_client import IAMClient


@pytest.fixture
def client():
    """A raw IAMClient built via __new__ (bypassing __init__/its real
    Redis+httpx setup) with redis/http/_shared all replaced by mocks, so
    each test can drive cache/remote-validation behavior directly."""
    instance = IAMClient.__new__(IAMClient)
    instance.base_url = "http://iam"
    instance.redis = MagicMock()
    instance.redis.get = AsyncMock()
    instance.redis.setex = AsyncMock()
    instance.redis.delete = AsyncMock()
    instance.http = MagicMock()
    instance.http.post = AsyncMock()
    instance._shared = MagicMock()
    instance._shared.decode_token = AsyncMock(return_value={"sub": "u"})
    return instance


@pytest.mark.asyncio
async def test_malformed_cached_identity_is_treated_as_cache_miss(client):
    """A cached value that fails JSON parsing must be ignored (returns
    None), never raise or be trusted as a valid cached identity."""
    client.redis.get.return_value = "not-json"

    assert await client._get_cached("token") is None


@pytest.mark.asyncio
async def test_remote_payload_missing_required_identity_fails_closed(client):
    """A remote /validate response reporting valid=True but missing
    user_id must fail closed (validate() returns None, via the KeyError
    on data["user_id"] being caught by the broad except), after local
    JWT decoding (decode_token) has already run."""
    client.redis.get.return_value = None
    response = MagicMock()
    response.json.return_value = {"valid": True}
    client.http.post.return_value = response

    assert await client.validate("token") is None
    client._shared.decode_token.assert_awaited_once()


@pytest.mark.asyncio
async def test_empty_cached_value_falls_through_to_remote_validation(client):
    """A cache miss (redis.get returns None) must fall through to the
    remote /auth/validate call and return the identity it provides."""
    client.redis.get.return_value = None
    response = MagicMock()
    response.json.return_value = {"valid": True, "user_id": "u"}
    client.http.post.return_value = response

    result = await client.validate("token")

    assert result["user_id"] == "u"
    client.http.post.assert_awaited_once()

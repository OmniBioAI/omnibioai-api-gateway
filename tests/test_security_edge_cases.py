"""Additional fail-closed checks at the IAM/network boundary."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.iam_client import IAMClient


@pytest.fixture
def client():
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
    client.redis.get.return_value = "not-json"

    assert await client._get_cached("token") is None


@pytest.mark.asyncio
async def test_remote_payload_missing_required_identity_fails_closed(client):
    client.redis.get.return_value = None
    response = MagicMock()
    response.json.return_value = {"valid": True}
    client.http.post.return_value = response

    assert await client.validate("token") is None
    client._shared.decode_token.assert_awaited_once()


@pytest.mark.asyncio
async def test_empty_cached_value_falls_through_to_remote_validation(client):
    client.redis.get.return_value = None
    response = MagicMock()
    response.json.return_value = {"valid": True, "user_id": "u"}
    client.http.post.return_value = response

    result = await client.validate("token")

    assert result["user_id"] == "u"
    client.http.post.assert_awaited_once()

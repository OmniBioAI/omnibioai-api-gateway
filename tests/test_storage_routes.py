"""Public storage aliases preserve IAM context and stream transfer bodies."""

import asyncio
import os
import tracemalloc
from unittest.mock import AsyncMock, patch

import httpx
import app.main as main
from app.routes import storage


class _BodyStream(httpx.AsyncByteStream):
    def __init__(self, body=b""):
        self.body = body

    async def __aiter__(self):
        yield self.body


def _authorized(valid_user):
    policy = AsyncMock(return_value={"allowed": True})
    return (
        patch.object(main.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(main.policy, "evaluate", policy),
        policy,
    )


def test_storage_aliases_use_full_auth_and_preserve_contract_headers(
    client, valid_user
):
    seen = []

    async def upstream(request):
        body = await request.aread()
        seen.append((request, body))
        headers = {
            "Content-Type": "application/json",
            "Content-Length": "11",
            "Content-Disposition": 'attachment; filename="x"',
            "X-Checksum-SHA256": "abc",
            "Connection": "close",
        }
        return httpx.Response(
            201, stream=_BodyStream(b'{"ok":true}'), headers=headers
        )

    transport = httpx.MockTransport(upstream)
    proxy = httpx.AsyncClient(transport=transport, follow_redirects=False)
    auth, policy_patch, _ = _authorized(valid_user)
    with auth, policy_patch, patch.object(storage, "_client", proxy):
        response = client.post(
            "/v1/storage/artifacts",
            content=b'{"name":"x"}',
            headers={
                "Authorization": "Bearer user-token",
                "Content-Type": "application/json",
                "Idempotency-Key": "idem-1",
                "X-Checksum-SHA256": "abc",
                "Connection": "X-Remove-Me",
                "X-Remove-Me": "attacker-controlled",
            },
        )
    asyncio.run(proxy.aclose())

    request, body = seen[0]
    assert request.url.path == "/plugins/artifact_manager/artifacts"
    assert body == b'{"name":"x"}'
    assert request.headers["authorization"] == "Bearer user-token"
    assert request.headers["idempotency-key"] == "idem-1"
    assert request.headers["x-checksum-sha256"] == "abc"
    # httpx may add its own transport-level Connection header, but the
    # caller's nominated hop-by-hop extension must never be forwarded.
    assert "x-remove-me" not in request.headers
    assert response.status_code == 201
    assert response.headers["content-disposition"] == 'attachment; filename="x"'
    assert response.headers["x-checksum-sha256"] == "abc"
    assert "connection" not in response.headers


def test_storage_alias_rewrites_and_permission_context(client, valid_user):
    paths = []

    async def upstream(request):
        paths.append((request.method, request.url.path, request.url.query))
        return httpx.Response(
            200,
            stream=_BodyStream(b'{"ok":true}'),
            headers={"Content-Type": "application/json"},
        )

    proxy = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    auth, policy_patch, policy = _authorized(valid_user)
    with auth, policy_patch, patch.object(storage, "_client", proxy):
        assert client.get(
            "/v1/storage/usage", headers={"Authorization": "Bearer t"}
        ).status_code == 200
        assert client.get(
            "/v1/storage/artifacts/a/download?raw=1",
            headers={"Authorization": "Bearer t"},
        ).status_code == 200
        assert client.request(
            "DELETE",
            "/v1/storage/artifacts/a/reservation",
            headers={"Authorization": "Bearer t"},
        ).status_code == 200
    asyncio.run(proxy.aclose())

    assert paths == [
        ("GET", "/api/storage/me/usage", b""),
        ("GET", "/plugins/artifact_manager/artifacts/a/download", b"raw=1"),
        ("DELETE", "/plugins/artifact_manager/artifacts/a/reservation", b""),
    ]
    assert policy.await_count == 3
    assert all(
        call.kwargs["required_permission"] == "workflow.execute"
        and call.kwargs["service"] == "workbench"
        for call in policy.await_args_list
    )


def test_storage_missing_auth_is_rejected_before_upstream(client):
    with patch.object(storage._client, "send", AsyncMock()) as send:
        response = client.get("/v1/storage/usage")
    assert response.status_code == 401
    send.assert_not_awaited()


def test_declared_oversize_is_rejected_before_upstream(
    client, valid_user, monkeypatch
):
    monkeypatch.setattr(storage.Config, "STORAGE_MAX_REQUEST_BYTES", 10)
    auth, policy_patch, _ = _authorized(valid_user)
    with auth, policy_patch, patch.object(storage._client, "send", AsyncMock()) as send:
        response = client.post(
            "/v1/storage/artifacts",
            content=b"12345678901",
            headers={"Authorization": "Bearer t"},
        )
    assert response.status_code == 413
    send.assert_not_awaited()


def test_200mb_sparse_upload_is_consumed_with_bounded_memory(tmp_path, monkeypatch):
    size = 200 * 1024 * 1024
    sparse = tmp_path / "large.bin"
    with sparse.open("wb") as handle:
        handle.seek(size - 1)
        handle.write(b"\0")

    class FileRequest:
        async def stream(self):
            with sparse.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    yield chunk

    monkeypatch.setattr(storage.Config, "STORAGE_MAX_REQUEST_BYTES", size)

    async def consume():
        total = 0
        async for chunk in storage._limited_body(FileRequest()):
            total += len(chunk)
        return total

    tracemalloc.start()
    total = asyncio.run(consume())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert total == size
    assert peak < 8 * 1024 * 1024
    assert os.stat(sparse).st_size == size


def test_200mb_download_iterator_has_bounded_memory():
    size = 200 * 1024 * 1024
    chunk = b"x" * (1024 * 1024)

    class RepeatedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(200):
                yield chunk

    response = httpx.Response(
        200,
        headers={"Content-Length": str(size)},
        stream=RepeatedStream(),
    )

    async def consume():
        total = 0
        async for part in response.aiter_raw():
            total += len(part)
        return total

    tracemalloc.start()
    total = asyncio.run(consume())
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert total == size
    assert peak < 8 * 1024 * 1024


def test_storage_proxy_never_follows_redirects(client, valid_user):
    async def upstream(request):
        return httpx.Response(
            307,
            stream=_BodyStream(),
            headers={"Location": "https://elsewhere.test/x"},
        )

    proxy = httpx.AsyncClient(
        transport=httpx.MockTransport(upstream), follow_redirects=False
    )
    auth, policy_patch, _ = _authorized(valid_user)
    with auth, policy_patch, patch.object(storage, "_client", proxy):
        response = client.get(
            "/v1/storage/artifacts/a/download",
            headers={"Authorization": "Bearer t"},
        )
    asyncio.run(proxy.aclose())
    assert response.status_code == 307
    assert response.headers["location"] == "https://elsewhere.test/x"

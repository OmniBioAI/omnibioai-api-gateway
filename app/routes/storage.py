"""Authenticated, streaming public aliases for Workbench storage APIs."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.background import BackgroundTask

from app.core.config import Config
from app.core.router import SERVICE_MAP
from app.routes.gateway import build_upstream_headers


router = APIRouter()

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_timeout = httpx.Timeout(
    connect=15.0,
    read=float(Config.STORAGE_TRANSFER_TIMEOUT),
    write=float(Config.STORAGE_TRANSFER_TIMEOUT),
    pool=15.0,
)
_client = httpx.AsyncClient(timeout=_timeout, follow_redirects=False)


class _RequestTooLarge(Exception):
    pass


def _filtered_headers(headers) -> dict[str, str]:
    connection_tokens = {
        token.strip().lower()
        for token in headers.get("connection", "").split(",")
        if token.strip()
    }
    blocked = _HOP_BY_HOP | connection_tokens | {"host"}
    return {key: value for key, value in headers.items() if key.lower() not in blocked}


async def _limited_body(request: Request) -> AsyncIterator[bytes]:
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > Config.STORAGE_MAX_REQUEST_BYTES:
            raise _RequestTooLarge
        yield chunk


def _too_large():
    return JSONResponse(
        {
            "error": "request_too_large",
            "message": (
                "Storage request exceeds the configured maximum of "
                f"{Config.STORAGE_MAX_REQUEST_BYTES} bytes."
            ),
        },
        status_code=413,
    )


async def _forward(request: Request, upstream_path: str):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > Config.STORAGE_MAX_REQUEST_BYTES:
                return _too_large()
        except ValueError:
            return JSONResponse(
                {"error": "invalid_content_length"}, status_code=400
            )

    url = f"{SERVICE_MAP['workbench']}/{upstream_path.lstrip('/')}"
    if request.url.query:
        url = f"{url}?{request.url.query}"

    headers = _filtered_headers(build_upstream_headers(request))
    # build_upstream_headers deliberately removes Content-Length for the
    # generic JSON proxy. Storage is byte-for-byte streaming, so preserve it.
    if content_length:
        headers["Content-Length"] = content_length

    upstream = _client.build_request(
        request.method,
        url,
        headers=headers,
        content=_limited_body(request),
    )
    try:
        response = await _client.send(upstream, stream=True, follow_redirects=False)
    except _RequestTooLarge:
        return _too_large()
    except httpx.HTTPError:
        return JSONResponse({"error": "upstream_failure"}, status_code=502)

    response_headers = _filtered_headers(response.headers)
    return StreamingResponse(
        response.aiter_raw(),
        status_code=response.status_code,
        headers=response_headers,
        background=BackgroundTask(response.aclose),
    )


@router.api_route("/v1/storage/artifacts", methods=["GET", "POST"])
async def artifacts_collection(request: Request):
    return await _forward(request, "/plugins/artifact_manager/artifacts")


@router.api_route(
    "/v1/storage/artifacts/{artifact_id}", methods=["GET", "DELETE"]
)
async def artifact_detail(artifact_id: str, request: Request):
    return await _forward(
        request, f"/plugins/artifact_manager/artifacts/{artifact_id}"
    )


@router.api_route(
    "/v1/storage/artifacts/{artifact_id}/reservation",
    methods=["POST", "DELETE"],
)
async def artifact_reservation(artifact_id: str, request: Request):
    return await _forward(
        request,
        f"/plugins/artifact_manager/artifacts/{artifact_id}/reservation",
    )


@router.post("/v1/storage/artifacts/{artifact_id}/upload")
async def artifact_upload(artifact_id: str, request: Request):
    return await _forward(
        request, f"/plugins/artifact_manager/artifacts/{artifact_id}/upload"
    )


@router.get("/v1/storage/artifacts/{artifact_id}/download")
async def artifact_download(artifact_id: str, request: Request):
    return await _forward(
        request, f"/plugins/artifact_manager/artifacts/{artifact_id}/download"
    )


@router.get("/v1/storage/usage")
async def storage_usage(request: Request):
    return await _forward(request, "/api/storage/me/usage")

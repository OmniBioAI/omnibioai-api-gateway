"""Narrow public ingress relay to Auth's durable research-inquiry API."""

import ipaddress
from uuid import UUID

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from app.core.config import Config

router = APIRouter()
_upstream_client = httpx.AsyncClient
MAX_REQUEST_BYTES = 16_384
SAFE_RESPONSE_HEADERS = {"content-type", "cache-control", "retry-after", "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers", "vary"}


def _unavailable(status=503):
    return JSONResponse({"error": "Inquiry service unavailable"}, status_code=status, headers={"Cache-Control": "no-store"})


def _client_ip(request: Request) -> str:
    peer_text = request.client.host if request.client else ""
    try:
        peer = ipaddress.ip_address(peer_text)
    except ValueError:
        return "unknown"
    if any(peer in network for network in Config.RESEARCH_INQUIRY_TRUSTED_PROXIES):
        forwarded = request.headers.get("CF-Connecting-IP", "")
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            return "unknown"
    return str(peer)


@router.api_route("/api/v1/research-inquiries", methods=["POST", "OPTIONS"])
async def research_inquiries(request: Request):
    if not Config.RESEARCH_INQUIRY_BACKEND_URL:
        return JSONResponse({"error": "Inquiry service unavailable"}, status_code=503, headers={"Cache-Control": "no-store"})
    declared = request.headers.get("content-length")
    if declared and (not declared.isdecimal() or int(declared) > MAX_REQUEST_BYTES):
        return JSONResponse({"error": "Request is too large"}, status_code=413, headers={"Cache-Control": "no-store"})
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_REQUEST_BYTES:
            return JSONResponse({"error": "Request is too large"}, status_code=413, headers={"Cache-Control": "no-store"})
        body.extend(chunk)
    target = f"{Config.RESEARCH_INQUIRY_BACKEND_URL}/api/v1/research-inquiries"
    headers = {
        "Accept": "application/json",
        "Origin": request.headers.get("origin", ""),
        "CF-Connecting-IP": _client_ip(request),
        "X-Trace-ID": getattr(request.state, "trace_id", ""),
    }
    if request.headers.get("content-type"):
        headers["Content-Type"] = request.headers["content-type"]
    if request.method == "OPTIONS":
        for name in ("access-control-request-method", "access-control-request-headers"):
            if request.headers.get(name):
                headers[name] = request.headers[name]
    try:
        async with _upstream_client(timeout=10, follow_redirects=False) as client:
            upstream = await client.request(request.method, target, headers=headers, content=bytes(body))
    except httpx.HTTPError:
        return JSONResponse({"error": "Inquiry service unavailable"}, status_code=503, headers={"Cache-Control": "no-store"})
    response_headers = {name: value for name, value in upstream.headers.items() if name.lower() in SAFE_RESPONSE_HEADERS}
    response_headers["cache-control"] = "no-store"
    if request.method == "OPTIONS":
        if upstream.status_code not in {200, 400}:
            return _unavailable()
        return Response("OK" if upstream.status_code == 200 else "CORS preflight denied",
                        status_code=upstream.status_code, headers=response_headers)
    if upstream.status_code >= 500 or upstream.status_code not in {201, 204, 400, 403, 409, 413, 415, 422, 429}:
        return _unavailable()
    content_type = upstream.headers.get("content-type", "")
    if "application/json" not in content_type and upstream.status_code != 204:
        return JSONResponse({"error": "Inquiry service unavailable"}, status_code=502, headers={"Cache-Control": "no-store"})
    if upstream.status_code != 204:
        try:
            data = upstream.json()
            if not isinstance(data, dict):
                raise ValueError
            if upstream.status_code == 201:
                UUID(data["inquiry_id"])
                if data.get("status") != "received" or not isinstance(data.get("submitted_at"), str):
                    raise ValueError
                data = {key: data[key] for key in ("status", "inquiry_id", "submitted_at")}
            else:
                # Auth owns the public error contract; discard incidental/internal keys.
                data = {key: data[key] for key in ("error", "field_errors") if key in data}
        except (ValueError, TypeError, KeyError):
            return _unavailable(502)
        return JSONResponse(data, status_code=upstream.status_code, headers=response_headers)
    return Response(status_code=204, headers=response_headers)

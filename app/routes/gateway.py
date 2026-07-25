import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.router import resolve_service
from app.core.proxy import ProxyClient
from app.services.audit_client import _emit

router = APIRouter()
proxy = ProxyClient()


@router.api_route("/{service}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway(service: str, path: str, request: Request):
    target = resolve_service(service)

    if not target:
        return {"error": "unknown service"}

    url = f"{target}/{path}"

    user = getattr(request.state, "user", None)
    trace_id = getattr(request.state, "trace_id", "")
    user_id = user.get("user_id", "") if user else ""

    body = None
    try:
        body = await request.json()
    except Exception:
        body = None

    # Attach internal S2S headers to upstream call
    upstream_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length")
    }
    upstream_headers["X-Internal-Service"] = "gateway"
    upstream_headers["X-Trace-Id"] = trace_id
    upstream_headers["X-User-Id"] = user_id

    status, response = await proxy.forward(
        url=url,
        method=request.method,
        headers=upstream_headers,
        body=body,
    )

    # Non-blocking upstream audit
    try:
        asyncio.create_task(_emit({
            "service": "gateway",
            "event_type": "upstream_forward",
            "user_id": user_id,
            "action": f"{request.method} {service}/{path}",
            "decision": "allow" if status < 400 else "deny",
            "trace_id": trace_id,
            "status_code": status,
        }))
    except Exception:
        pass

    return JSONResponse(content=response, status_code=status)

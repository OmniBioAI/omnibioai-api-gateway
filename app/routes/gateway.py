import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.router import resolve_service
from app.core.proxy import ProxyClient
from app.services.audit_client import _emit, build_audit_event

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
    token = getattr(request.state, "token", None)

    body = None
    try:
        body = await request.json()
    except Exception:
        body = None

    # Attach internal S2S headers to upstream call. "authorization" is
    # excluded from this generic passthrough (rather than left to flow
    # through implicitly) so the explicit Authorization assignment below
    # is the single source of truth -- a plain dict can hold both
    # "authorization" and "Authorization" as distinct keys (Python dict
    # keys are case-sensitive; HTTP header names aren't), which would
    # otherwise risk sending two Authorization headers on the wire.
    upstream_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "authorization")
    }
    upstream_headers["X-Internal-Service"] = "gateway"
    upstream_headers["X-Trace-Id"] = trace_id
    upstream_headers["X-User-Id"] = user_id
    if token:
        # SSO Phase 2 PR4: forward the original, already-validated bearer
        # token downstream (from request.state.token -- the exact string
        # AuthMiddleware verified, not a re-parse of the raw header) so a
        # downstream service can independently verify identity instead of
        # trusting the unsigned X-User-Id above. X-User-Id/X-Trace-Id/
        # X-Internal-Service are unchanged and still sent, for backward
        # compatibility with anything already reading them.
        upstream_headers["Authorization"] = f"Bearer {token}"

    status, response = await proxy.forward(
        url=url,
        method=request.method,
        headers=upstream_headers,
        body=body,
    )

    # Non-blocking upstream audit
    try:
        asyncio.create_task(_emit(build_audit_event(
            service="gateway",
            event_type="upstream_forward",
            user_id=user_id,
            action=f"{request.method} {service}/{path}",
            decision="allow" if status < 400 else "deny",
            trace_id=trace_id,
            context={"status_code": status},
        )))
    except Exception:
        pass

    return JSONResponse(content=response, status_code=status)

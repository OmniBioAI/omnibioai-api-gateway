import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.core.router import resolve_service
from app.core.proxy import ProxyClient
from app.services.audit_client import _emit, build_audit_event

router = APIRouter()
proxy = ProxyClient()

# Tenant-isolation audit finding: this used to list only "host"/
# "content-length"/"authorization" -- every *other* identity header the
# gateway itself sets below (X-Organization-ID, X-User-Id, X-Client-ID,
# X-Permissions, X-Token-Type, X-Trace-Id, X-Internal-Service) was left
# to flow through from the client unmodified, then have the gateway's
# own value assigned under the differently-cased dict key
# `"X-Organization-ID"` (capital X) right after. Since Python dict keys
# are case-sensitive but HTTP header names aren't, a client-supplied
# `x-organization-id: <victim-org>` and the gateway's own
# `X-Organization-ID: <real-org>` both survived as distinct dict
# entries and were sent as two separate header lines on the wire
# (verified directly against httpx, the library `ProxyClient` uses) --
# a downstream service that reads this header case-insensitively and
# takes the first/only value, or naively splits on comma and takes
# index 0, would receive the attacker-controlled value instead of the
# gateway's own. Every downstream service audited so far
# (omnibioai-rag, omnibioai-tes, omnibioai-model-registry) independently
# re-verifies the forwarded JWT and never reads these headers for
# authorization at all, so this was not exploitable against any
# *current* consumer -- but nothing stops a future one from trusting
# them, and the header this gateway sets is the one place that trust
# boundary is supposed to be enforced. Now excludes every header name
# the gateway sets itself, the same treatment "authorization" already
# got -- module-level since it's a fixed set, not per-request state.
_RESERVED_UPSTREAM_HEADERS = frozenset({
    "host", "content-length", "authorization",
    "x-internal-service", "x-trace-id", "x-user-id",
    "x-organization-id", "x-client-id", "x-permissions", "x-token-type",
})


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
    identity = getattr(request.state, "identity", None)

    body = None
    try:
        body = await request.json()
    except Exception:
        body = None

    # See _RESERVED_UPSTREAM_HEADERS above for why every gateway-set
    # identity header must be excluded here, not just authorization.
    upstream_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in _RESERVED_UPSTREAM_HEADERS
    }
    upstream_headers["X-Internal-Service"] = "gateway"
    upstream_headers["X-Trace-Id"] = trace_id
    upstream_headers["X-User-Id"] = user_id
    # IAM Foundation gateway integration (Step 7): identity propagation
    # headers derived from request.state.identity, additive alongside the
    # pre-existing X-User-Id/X-Trace-Id/X-Internal-Service above -- none
    # of those are renamed or removed. client_id/token_type are always
    # None/"user" today since service-token support is deferred (see
    # this PR's report); the headers still exist now so a downstream
    # service can start reading them ahead of that landing, rather than
    # needing another gateway change when it does. X-Permissions is
    # comma-joined -- every permission name is already constrained to
    # `[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*` by omnibioai-auth's own registry
    # validation, so a plain comma-join is safe and unambiguous here,
    # unlike sending JSON in a header value.
    upstream_headers["X-Organization-ID"] = str(identity.get("organization_id") or "") if identity else ""
    upstream_headers["X-Client-ID"] = str(identity.get("client_id") or "") if identity else ""
    upstream_headers["X-Permissions"] = ",".join(identity.get("permissions", [])) if identity else ""
    upstream_headers["X-Token-Type"] = identity.get("token_type", "") if identity else ""
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

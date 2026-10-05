"""
OmniBioAI app.middleware.hpc.

Purpose:
    Defines HPCMiddleware HTTP request middleware.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.hpc_policy_client import HPCPolicyClient
from app.services.audit_client import build_audit_event, fire_audit

_SKIP_PATHS = {"/health", "/", "/version"}
# M17: see app/middleware/auth.py's own _SKIP_PREFIXES comment. Already
# true in effect here too -- "mcp" is not a registered HPC compute
# service, so is_compute_service("mcp") already falls through to
# call_next below -- but explicit, like the other two middlewares,
# rather than relying on that incidentally being the case.
_SKIP_PREFIXES = ("/mcp",)


class HPCMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, hpc: HPCPolicyClient):
        super().__init__(app)
        self.hpc = hpc

    async def dispatch(self, request, call_next):
        if request.url.path in _SKIP_PATHS or request.url.path.startswith(_SKIP_PREFIXES):
            return await call_next(request)

        parts = request.url.path.strip("/").split("/")
        service = parts[0] if parts else ""

        if not self.hpc.is_compute_service(service):
            return await call_next(request)

        user = getattr(request.state, "user", None)
        trace_id = getattr(request.state, "trace_id", "")
        user_id = user.get("user_id", "") if user else ""
        identity = getattr(request.state, "identity", None)
        organization_id = identity.get("organization_id") if identity else None
        roles = user.get("roles", []) if user else []

        decision = await self.hpc.evaluate(
            user_id=user_id,
            service=service,
            trace_id=trace_id,
            roles=roles,
        )

        if not decision.get("allow", False):
            fire_audit(build_audit_event(
                service="gateway",
                event_type="hpc_denied",
                user_id=user_id,
                organization_id=organization_id,
                tenant_scope="organization" if organization_id is not None else "unknown",
                action=f"{request.method} {request.url.path}",
                decision="deny",
                reason=decision.get("reason", "hpc_quota_exceeded"),
                trace_id=trace_id,
            ))
            return JSONResponse(
                {"error": "HPC quota exceeded", "reason": decision.get("reason")},
                status_code=403,
            )

        return await call_next(request)

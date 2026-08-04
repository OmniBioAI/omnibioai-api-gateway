from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.hpc_policy_client import HPCPolicyClient
from app.services.audit_client import build_audit_event, fire_audit

_SKIP_PATHS = {"/health", "/", "/version"}


class HPCMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, hpc: HPCPolicyClient):
        super().__init__(app)
        self.hpc = hpc

    async def dispatch(self, request, call_next):
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        parts = request.url.path.strip("/").split("/")
        service = parts[0] if parts else ""

        if not self.hpc.is_compute_service(service):
            return await call_next(request)

        user = getattr(request.state, "user", None)
        trace_id = getattr(request.state, "trace_id", "")
        user_id = user.get("user_id", "") if user else ""

        decision = await self.hpc.evaluate(
            user_id=user_id,
            service=service,
            trace_id=trace_id,
        )

        if not decision.get("allow", False):
            fire_audit(build_audit_event(
                service="gateway",
                event_type="hpc_denied",
                user_id=user_id,
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

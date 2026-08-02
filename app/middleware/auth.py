from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.iam_client import IAMClient
from app.services.audit_client import build_audit_event, fire_audit

_SKIP_PATHS = {"/health", "/"}


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, iam: IAMClient):
        super().__init__(app)
        self.iam = iam

    async def dispatch(self, request, call_next):
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        trace_id = getattr(request.state, "trace_id", "")

        if not token:
            fire_audit(build_audit_event(
                service="gateway",
                event_type="auth_failed",
                action=f"{request.method} {request.url.path}",
                decision="deny",
                reason="missing_token",
                trace_id=trace_id,
            ))
            return JSONResponse({"error": "missing token"}, status_code=401)

        user = await self.iam.validate(token)

        if not user:
            fire_audit(build_audit_event(
                service="gateway",
                event_type="auth_failed",
                action=f"{request.method} {request.url.path}",
                decision="deny",
                reason="invalid_token",
                trace_id=trace_id,
            ))
            return JSONResponse({"error": "invalid token"}, status_code=401)

        request.state.user = user
        request.state.token = token
        return await call_next(request)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.iam_client import IAMClient
from app.services.audit_client import build_audit_event, fire_audit

_SKIP_PATHS = {"/health", "/", "/version"}


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
        # IAM Foundation gateway integration (Step 3): the canonical
        # identity shape downstream gateway code (permission derivation,
        # header propagation) reads from -- request.state.user above is
        # kept unchanged for existing consumers (PolicyMiddleware,
        # HPCMiddleware, gateway.py, auth_verify.py) rather than migrated,
        # to avoid touching working code outside this PR's scope.
        # client_id/token_type are fixed for now: service (client_credentials)
        # token support is deferred to a follow-up PR pending IAM/iam-client
        # changes (see this PR's report) -- every identity built here is a
        # user token.
        request.state.identity = {
            "user_id": user.get("user_id"),
            "organization_id": user.get("org_id"),
            "client_id": None,
            "permissions": user.get("permissions", []),
            "token_type": "user",
        }
        return await call_next(request)

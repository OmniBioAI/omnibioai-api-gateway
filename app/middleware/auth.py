"""
OmniBioAI app.middleware.auth.

Purpose:
    Defines AuthMiddleware HTTP request middleware.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.services.iam_client import IAMClient, is_api_key
from app.services.audit_client import build_audit_event, fire_audit

# /docs and /openapi.json are exempted deliberately: the OpenAPI spec is
# public metadata describing the API's shape, not an access path to any
# data or action, so it doesn't need a token — matching how auth-service,
# security-audit, and toolserver all expose their own /docs pages.
# Every actual API call still goes through the token check below.
_SKIP_PATHS = {"/health", "/", "/version", "/docs", "/openapi.json"}
# M17: the mounted MCP Streamable HTTP app (app/services/mcp_server.py)
# is a prefix, not one exact path, and gates itself -- see
# app/services/mcp_auth.py's MCPBearerAuthASGIMiddleware, wrapping that
# mount directly. Skipped here (and in PolicyMiddleware/HPCMiddleware)
# so this request/response-oriented middleware never buffers or blocks
# that app's own long-lived streaming session.
_SKIP_PREFIXES = ("/mcp",)


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, iam: IAMClient):
        super().__init__(app)
        self.iam = iam

    async def dispatch(self, request, call_next):
        if request.url.path in _SKIP_PATHS or request.url.path.startswith(_SKIP_PREFIXES):
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

        api_key = is_api_key(token)
        user = await (self.iam.validate_api_key(token) if api_key else self.iam.validate(token))

        if not user:
            fire_audit(build_audit_event(
                service="gateway",
                event_type="auth_failed",
                action=f"{request.method} {request.url.path}",
                decision="deny",
                reason="invalid_api_key" if api_key else "invalid_token",
                trace_id=trace_id,
            ))
            return JSONResponse({"error": "invalid api key" if api_key else "invalid token"}, status_code=401)

        request.state.user = user
        # For an API key, the token forwarded downstream is the short-lived
        # JWT auth minted for it -- the raw omni_sk_ key never leaves the
        # gateway (gateway.py forwards request.state.token as Bearer).
        request.state.token = user["access_token"] if api_key else token
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
            "client_id": f"api_key:{user['api_key_id']}" if api_key else None,
            "permissions": user.get("permissions", []),
            "token_type": "api_key" if api_key else "user",
            # M13: only ever True for an api_key identity (test mode is a
            # property of the omni_sk_ key itself, not a session).
            "test_mode": bool(user.get("test_mode", False)) if api_key else False,
        }
        return await call_next(request)

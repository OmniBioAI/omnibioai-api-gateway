from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.router import resolve_required_permission
from app.services.policy_client import PolicyClient
from app.services.audit_client import build_audit_event, fire_audit

#  /auth/verify (SSO Phase 2 PR8) is a pure identity-verification check --
# there's no application "resource" being accessed for the policy engine
# to evaluate an ABAC/RBAC decision against, so it's skip-listed here the
# same way /health and / already are. Without this, an authenticated
# request would depend on the policy engine's default decision for an
# unmodeled synthetic path -- untested, unspecified behavior that could
# 403 a validly authenticated caller and break nginx's auth_request gate.
_SKIP_PATHS = {"/health", "/", "/auth/verify", "/version"}


class PolicyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, policy: PolicyClient):
        super().__init__(app)
        self.policy = policy

    async def dispatch(self, request, call_next):
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        user = getattr(request.state, "user", None)
        trace_id = getattr(request.state, "trace_id", "")

        if not user:
            return JSONResponse({"error": "forbidden"}, status_code=403)

        # IAM Foundation gateway integration: the gateway derives which
        # IAM permission this request's target service requires (from
        # SERVICE_MAP -- see app/core/router.py) and hands that to the
        # policy engine as authoritative context; it does NOT decide
        # allow/deny itself. That decision-making stays exactly where it
        # already lived, in PolicyClient.evaluate's remote call below --
        # this only makes its input richer than the previous auto-derived
        # "post.samples.123"-style action string, for services this
        # gateway actually knows the IAM meaning of.
        service = request.url.path.strip("/").split("/", 1)[0]
        required_permission = resolve_required_permission(service)

        identity = getattr(request.state, "identity", None)
        fire_audit(build_audit_event(
            service="gateway",
            event_type="iam_auth_success",
            user_id=user.get("user_id"),
            action=required_permission or f"{request.method.lower()}.{request.url.path.strip('/').replace('/', '.')}",
            resource=request.url.path,
            decision="allow",
            trace_id=trace_id,
            context={
                "organization_id": identity.get("organization_id") if identity else None,
                "service": service,
            },
        ))

        decision = await self.policy.evaluate(
            user=user,
            path=request.url.path,
            method=request.method,
            trace_id=trace_id,
            required_permission=required_permission,
            service=service,
        )

        if not decision.get("allowed", False):
            fire_audit(build_audit_event(
                service="gateway",
                event_type="policy_denied",
                user_id=user.get("user_id"),
                action=f"{request.method} {request.url.path}",
                decision="deny",
                reason=decision.get("reason", "policy_block"),
                trace_id=trace_id,
            ))
            return JSONResponse(
                {"error": "forbidden", "reason": decision.get("reason")},
                status_code=403,
            )

        return await call_next(request)

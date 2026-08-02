import asyncio
import time

from starlette.middleware.base import BaseHTTPMiddleware

from app.services.audit_client import _emit, build_audit_event, fire_audit


class AuditMiddleware(BaseHTTPMiddleware):
    """
    Non-blocking audit middleware.
    Captures every request that passed auth/policy/hpc and logs the outcome.
    Uses asyncio.create_task so it never blocks the response.
    """

    async def dispatch(self, request, call_next):
        start = time.time()
        response = await call_next(request)
        latency_ms = int((time.time() - start) * 1000)

        user = getattr(request.state, "user", None)
        trace_id = getattr(request.state, "trace_id", "")

        fire_audit(build_audit_event(
            service="gateway",
            event_type="request",
            user_id=user.get("user_id") if user else None,
            action=f"{request.method} {request.url.path}",
            decision="allow" if response.status_code < 400 else "deny",
            trace_id=trace_id,
            context={
                "endpoint": str(request.url),
                "latency_ms": latency_ms,
                "status_code": response.status_code,
            },
        ))

        return response


# kept for app/core/security.py import compatibility
async def audit_log(event: dict):
    fire_audit(event)

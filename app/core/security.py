import uuid
from app.middleware.audit import audit_log
from app.services.audit_client import build_audit_event


def generate_trace_id() -> str:
    return str(uuid.uuid4())


async def attach_trace(request):
    trace_id = generate_trace_id()
    request.state.trace_id = trace_id

    # PR4.5: this previously emitted {"event": ..., "path": ..., "method":
    # ...} -- a shape with no service/event_type at all, which would have
    # failed AuditEvent validation outright rather than merely losing
    # fields. path/method now live in context, preserved rather than
    # dropped.
    await audit_log(build_audit_event(
        service="gateway",
        event_type="trace_created",
        action=f"{request.method} {request.url.path}",
        trace_id=trace_id,
        context={"path": request.url.path, "method": request.method},
    ))

    return trace_id
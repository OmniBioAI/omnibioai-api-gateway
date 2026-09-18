"""
Tests for app/core/security.py.

generate_trace_id() must return a valid UUID4 string and be globally unique.
attach_trace() must set request.state.trace_id and return the trace id.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from app.core.security import generate_trace_id


def test_generate_trace_id_is_valid_uuid():
    """generate_trace_id() returns a string parseable as a valid UUID."""
    tid = generate_trace_id()
    uuid.UUID(tid)  # raises ValueError if not a valid UUID


def test_generate_trace_id_returns_string():
    """generate_trace_id()'s return value is a str."""
    assert isinstance(generate_trace_id(), str)


def test_generate_trace_id_is_unique():
    """100 calls to generate_trace_id() produce 100 distinct values."""
    ids = {generate_trace_id() for _ in range(100)}
    assert len(ids) == 100


async def test_attach_trace_sets_state_and_returns_trace_id():
    """attach_trace() sets request.state.trace_id, returns that same
    trace id, and emits a "trace_created" audit event shaped as the
    shared AuditEvent contract (service/event_type/action/context)."""
    from app.core.security import attach_trace

    request = MagicMock()
    request.url.path = "/workbench/run"
    request.method = "POST"
    request.state = MagicMock()

    with patch("app.core.security.audit_log", new_callable=AsyncMock) as mock_audit:
        trace_id = await attach_trace(request)

    assert isinstance(trace_id, str)
    uuid.UUID(trace_id)
    assert request.state.trace_id == trace_id
    mock_audit.assert_called_once()
    event = mock_audit.call_args[0][0]
    # PR4.5: shape is now the shared AuditEvent contract (build_audit_event)
    # rather than the old {"event": ..., "path": ..., "method": ...} --
    # which had no service/event_type at all and would have failed
    # AuditEvent validation outright.
    assert event["service"] == "gateway"
    assert event["event_type"] == "trace_created"
    assert event["trace_id"] == trace_id
    assert event["action"] == "POST /workbench/run"
    assert event["context"] == {"path": "/workbench/run", "method": "POST"}
    assert event["event_id"]
    assert event["timestamp"]

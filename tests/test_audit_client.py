"""Tests for app/services/audit_client.py and app/middleware/audit.py audit_log."""
import asyncio
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, patch


async def test_fire_audit_in_running_loop_creates_task():
    """fire_audit must schedule _emit via create_task when a loop is running."""
    from app.services.audit_client import fire_audit

    with patch("app.services.audit_client._emit", new_callable=AsyncMock) as mock_emit:
        with patch("app.services.audit_client.asyncio.create_task") as mock_create:
            fire_audit({"event": "test"})
            mock_create.assert_called_once()


async def test_fire_audit_exception_silenced():
    """fire_audit must never raise even when asyncio explodes."""
    from app.services.audit_client import fire_audit

    with patch("app.services.audit_client.asyncio.get_event_loop", side_effect=RuntimeError("no loop")):
        fire_audit({"event": "test"})  # must not raise


async def test_audit_log_calls_fire_audit():
    """audit_log (middleware compat wrapper) must delegate to fire_audit."""
    from app.services.audit_client import audit_log, fire_audit

    with patch("app.services.audit_client.fire_audit") as mock_fire:
        await audit_log({"event": "request"})
        mock_fire.assert_called_once_with({"event": "request"})


async def test_middleware_audit_log_calls_fire_audit():
    """app/middleware/audit.py audit_log must call fire_audit."""
    from app.middleware.audit import audit_log

    with patch("app.middleware.audit.fire_audit") as mock_fire:
        await audit_log({"event": "trace_created"})
        mock_fire.assert_called_once_with({"event": "trace_created"})


async def test_emit_calls_redis_xadd():
    """_emit must call xadd on the module-level redis with the event payload."""
    import json
    from app.services import audit_client

    mock_redis = AsyncMock()
    original = audit_client._redis
    audit_client._redis = mock_redis
    try:
        await audit_client._emit({"event": "e1", "data": 42})
        mock_redis.xadd.assert_called_once()
        args, kwargs = mock_redis.xadd.call_args
        assert args[0] == "audit:events"
        payload = json.loads(args[1]["data"])
        assert payload["event"] == "e1"
    finally:
        audit_client._redis = original


async def test_emit_xadd_error_silenced():
    """_emit must swallow redis errors."""
    from app.services import audit_client

    mock_redis = AsyncMock()
    mock_redis.xadd.side_effect = RuntimeError("redis down")
    original = audit_client._redis
    audit_client._redis = mock_redis
    try:
        await audit_client._emit({"event": "e1"})  # must not raise
    finally:
        audit_client._redis = original


# ---------------------------------------------------------------------------
# PR4.5: build_audit_event -- the single audit-event contract every
# producer in this repo must build its payload through.
# ---------------------------------------------------------------------------

def test_build_audit_event_contains_all_contract_fields():
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request")

    assert set(event.keys()) == {
        "event_id", "timestamp", "service", "event_type", "user_id",
        "action", "resource", "decision", "reason", "trace_id", "context",
    }


def test_build_audit_event_generates_unique_event_id_per_call():
    """Each call must mint its own event_id -- this is what keeps a
    retried/redelivered Redis message's identity stable across a *single*
    emission while still being distinct from every other real event."""
    from app.services.audit_client import build_audit_event

    e1 = build_audit_event(service="gateway", event_type="request")
    e2 = build_audit_event(service="gateway", event_type="request")

    assert e1["event_id"] != e2["event_id"]
    uuid.UUID(e1["event_id"])  # raises ValueError if not a valid UUID


def test_build_audit_event_timestamp_is_iso8601():
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request")

    # Must round-trip through fromisoformat without raising.
    datetime.fromisoformat(event["timestamp"])


def test_build_audit_event_required_fields_set():
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="policy_denied")

    assert event["service"] == "gateway"
    assert event["event_type"] == "policy_denied"


def test_build_audit_event_optional_fields_default_none_or_empty():
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request")

    assert event["user_id"] is None
    assert event["action"] == ""
    assert event["resource"] is None
    assert event["decision"] is None
    assert event["reason"] is None
    assert event["trace_id"] is None
    assert event["context"] == {}


def test_build_audit_event_passes_through_all_optional_fields():
    from app.services.audit_client import build_audit_event

    event = build_audit_event(
        service="gateway",
        event_type="policy_denied",
        action="GET /workbench/run",
        user_id="u1",
        resource="workbench",
        decision="deny",
        reason="no_permission",
        trace_id="trace-abc",
        context={"extra": "data"},
    )

    assert event["action"] == "GET /workbench/run"
    assert event["user_id"] == "u1"
    assert event["resource"] == "workbench"
    assert event["decision"] == "deny"
    assert event["reason"] == "no_permission"
    assert event["trace_id"] == "trace-abc"
    assert event["context"] == {"extra": "data"}


def test_build_audit_event_context_none_becomes_empty_dict():
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request", context=None)

    assert event["context"] == {}


def test_build_audit_event_context_defaults_are_independent_dicts():
    """Guards against a mutable-default-argument bug (the exact class of
    bug PR4.1 fixed for AuditEvent.event_id/timestamp in the other repo):
    two calls that both omit `context` must not end up sharing the same
    dict object."""
    from app.services.audit_client import build_audit_event

    e1 = build_audit_event(service="gateway", event_type="request")
    e2 = build_audit_event(service="gateway", event_type="request")

    e1["context"]["leaked"] = True
    assert "leaked" not in e2["context"]

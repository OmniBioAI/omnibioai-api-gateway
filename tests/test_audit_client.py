"""fire_audit() must schedule/emit best-effort and never raise into its
caller regardless of what fails (no running loop, scheduling failure,
Redis XADD failure), while still making every drop visible via a logged
"DROPPED" line rather than silently discarding the event. build_audit_event()
must produce the one audit-event contract every producer in this repo
uses: a fixed field set, fresh UUID/ISO-8601 timestamp per call, safe
defaults, tenant fields that are trusted top-level data (never read back
from the caller-controlled `context`), and independent (never shared)
default dicts across calls.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""
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


# ---------------------------------------------------------------------------
# V2-002 (Track E2): previously, fire_audit() with no running event loop
# did nothing at all -- no exception, no log, no task, the event simply
# ceased to exist. Both new failure paths below must now be observable.
# ---------------------------------------------------------------------------

def test_fire_audit_with_no_running_loop_logs_the_drop_instead_of_silently_dropping(capsys):
    """V2-002: when get_event_loop() returns a non-running loop, fire_audit
    must not schedule anything, but it must print a "DROPPED" line naming
    the event_id rather than discarding the event with no trace at all."""
    from app.services.audit_client import fire_audit

    fake_loop = type("FakeLoop", (), {"is_running": lambda self: False})()
    with patch("app.services.audit_client.asyncio.get_event_loop", return_value=fake_loop), \
         patch("app.services.audit_client.asyncio.create_task") as mock_create:
        fire_audit({"event_id": "evt-no-loop", "service": "gateway", "event_type": "test"})

    mock_create.assert_not_called()  # confirms the exact old no-op path was reached
    captured = capsys.readouterr()
    assert "DROPPED" in captured.out
    assert "evt-no-loop" in captured.out


def test_fire_audit_scheduling_failure_after_get_event_loop_is_also_logged(capsys):
    """Distinct from the RuntimeError-from-get_event_loop() case above --
    this covers a failure raised *after* a loop is obtained (e.g.
    create_task itself raising), which must also be visible, not folded
    into a bare `except: pass`."""
    from app.services.audit_client import fire_audit

    fake_loop = type("FakeLoop", (), {"is_running": lambda self: True})()
    with patch("app.services.audit_client.asyncio.get_event_loop", return_value=fake_loop), \
         patch("app.services.audit_client.asyncio.create_task", side_effect=RuntimeError("no running event loop")):
        fire_audit({"event_id": "evt-sched-fail", "service": "gateway", "event_type": "test"})

    captured = capsys.readouterr()
    assert "DROPPED" in captured.out
    assert "evt-sched-fail" in captured.out


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


async def test_emit_signature_covers_tenant_fields():
    """The signature _emit attaches is computed over the exact wire "data"
    string, so tenant fields (organization_id here) are covered by it just
    like every other field -- confirmed by recomputing the same signature
    independently via sign_audit_event()."""
    import json
    from app.services import audit_client

    mock_redis = AsyncMock()
    original = audit_client._redis
    audit_client._redis = mock_redis
    try:
        event = audit_client.build_audit_event(
            service="gateway", event_type="request",
            organization_id="org-verified", tenant_scope="organization",
        )
        await audit_client._emit(event)
        data = mock_redis.xadd.call_args.args[1]["data"]
        assert json.loads(data)["organization_id"] == "org-verified"
        assert audit_client.sign_audit_event("gateway", data, audit_client.Config.JWT_SECRET) == mock_redis.xadd.call_args.args[1]["sig"]
    finally:
        audit_client._redis = original


async def test_emit_xadd_error_silenced():
    """_emit must swallow redis errors (never raise into the caller)."""
    from app.services import audit_client

    mock_redis = AsyncMock()
    mock_redis.xadd.side_effect = RuntimeError("redis down")
    original = audit_client._redis
    audit_client._redis = mock_redis
    try:
        await audit_client._emit({"event": "e1"})  # must not raise
    finally:
        audit_client._redis = original


async def test_emit_xadd_error_is_logged_not_silently_dropped(capsys):
    """V2-002 (Track E2): previously `except Exception: pass` -- an XADD
    failure must now be visible with enough safe identifying detail
    (event_id/service/event_type) to investigate, without dumping the
    full event payload/context."""
    from app.services import audit_client

    mock_redis = AsyncMock()
    mock_redis.xadd.side_effect = RuntimeError("redis connection refused")
    original = audit_client._redis
    audit_client._redis = mock_redis
    try:
        await audit_client._emit({
            "event_id": "evt-xadd-fail", "service": "gateway", "event_type": "policy_denied",
        })
    finally:
        audit_client._redis = original

    captured = capsys.readouterr()
    assert "evt-xadd-fail" in captured.out
    assert "gateway" in captured.out
    assert "redis connection refused" in captured.out


# ---------------------------------------------------------------------------
# PR4.5: build_audit_event -- the single audit-event contract every
# producer in this repo must build its payload through.
# ---------------------------------------------------------------------------

def test_build_audit_event_contains_all_contract_fields():
    """build_audit_event()'s output has exactly the CONTRACT_FIELDS set
    used by every producer in this repo -- no more, no less."""
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request")

    assert set(event.keys()) == {
        "event_id", "timestamp", "service", "event_type", "user_id",
        "organization_id", "tenant_scope", "action", "resource", "decision",
        "reason", "trace_id", "context",
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
    """The generated "timestamp" field is a valid ISO-8601 string."""
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request")

    # Must round-trip through fromisoformat without raising.
    datetime.fromisoformat(event["timestamp"])


def test_build_audit_event_required_fields_set():
    """The caller-supplied service/event_type land unchanged on the event."""
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="policy_denied")

    assert event["service"] == "gateway"
    assert event["event_type"] == "policy_denied"


def test_build_audit_event_optional_fields_default_none_or_empty():
    """Every optional field has a safe default when the caller omits it:
    None for identity/detail fields, "unknown" for tenant_scope, "" for
    action, {} for context."""
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request")

    assert event["user_id"] is None
    assert event["organization_id"] is None
    assert event["tenant_scope"] == "unknown"
    assert event["action"] == ""
    assert event["resource"] is None
    assert event["decision"] is None
    assert event["reason"] is None
    assert event["trace_id"] is None
    assert event["context"] == {}


def test_build_audit_event_passes_through_all_optional_fields():
    """Every optional keyword argument the caller does supply reaches the
    output event unchanged."""
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


def test_tenant_fields_are_top_level_and_context_is_not_authority():
    """organization_id/tenant_scope are trusted top-level fields set by the
    caller directly, never read back out of the caller-controlled
    `context` dict -- a mismatched organization_id inside context is left
    alone and does not override the real, top-level value."""
    from app.services.audit_client import build_audit_event

    event = build_audit_event(
        service="gateway",
        event_type="request",
        organization_id="org-verified",
        tenant_scope="organization",
        context={"organization_id": "org-untrusted"},
    )

    assert event["organization_id"] == "org-verified"
    assert event["tenant_scope"] == "organization"
    assert event["context"]["organization_id"] == "org-untrusted"


def test_missing_tenant_defaults_to_unknown_not_global():
    """When a caller omits tenant_scope entirely, the event defaults to
    "unknown" rather than something that could be misread as a
    platform-wide/"global" scope."""
    from app.services.audit_client import build_audit_event

    event = build_audit_event(service="gateway", event_type="request")

    assert event["organization_id"] is None
    assert event["tenant_scope"] == "unknown"


def test_build_audit_event_context_none_becomes_empty_dict():
    """Passing context=None explicitly normalizes to {}, not None."""
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

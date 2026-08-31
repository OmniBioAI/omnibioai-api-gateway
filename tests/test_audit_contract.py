"""PR4.5: proves every producer in this service (all 7 fire_audit/_emit/
audit_log call sites -- middleware/audit.py, middleware/hpc.py,
middleware/auth.py x2, middleware/policy.py, routes/gateway.py,
core/security.py) emits a contract-compliant payload on the wire, end to
end through the real middleware stack and the real JSON serialization
_emit performs -- not just that build_audit_event() itself is correct in
isolation (see test_audit_client.py for that).

"No duplicate schema paths remain" (PR4.5 requirement) is checked two
ways: this file's CONTRACT_FIELDS assertion, applied identically to every
producer regardless of which module/middleware emitted it: and a static
grep-style check that every fire_audit/_emit/audit_log call site in the
codebase routes through build_audit_event.
"""
import ast
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import app.main as _main_mod
import app.services.audit_client as _audit_client_mod

CONTRACT_FIELDS = {
    "event_id", "timestamp", "service", "event_type", "user_id",
    "organization_id", "tenant_scope", "action", "resource", "decision",
    "reason", "trace_id", "context",
}

REPO_ROOT = Path(__file__).resolve().parent.parent


def _captured_events(mock_xadd) -> list[dict]:
    events = []
    for call in mock_xadd.call_args_list:
        args, kwargs = call
        raw = args[1]["data"] if len(args) > 1 else kwargs["data"]
        events.append(json.loads(raw))
    return events


def _assert_contract_compliant(event: dict):
    assert set(event.keys()) == CONTRACT_FIELDS, event.keys()
    assert event["event_id"], "event_id must be non-empty"
    assert event["timestamp"], "timestamp must be non-empty"
    import uuid as _uuid
    _uuid.UUID(event["event_id"])  # valid UUID
    from datetime import datetime as _dt
    _dt.fromisoformat(event["timestamp"])  # valid ISO-8601


# ---------------------------------------------------------------------------
# Per-producer contract conformance, via real requests through the app
# ---------------------------------------------------------------------------

def test_audit_middleware_request_event_is_contract_compliant(client, authed):
    with patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")) as mock_xadd:
        client.get("/workbench/ping", headers={"Authorization": "Bearer token"})

    events = [e for e in _captured_events(mock_xadd) if e["event_type"] == "request"]
    assert events, "expected an AuditMiddleware 'request' event"
    event = events[0]
    _assert_contract_compliant(event)
    assert event["service"] == "gateway"
    assert "endpoint" in event["context"]
    assert "latency_ms" in event["context"]
    assert "status_code" in event["context"]


def test_hpc_middleware_denial_event_is_contract_compliant(client, valid_user):
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(_main_mod.policy, "evaluate", AsyncMock(return_value={"allowed": True})),
        patch.object(
            _main_mod.hpc, "evaluate",
            AsyncMock(return_value={"allow": False, "reason": "quota_exceeded"}),
        ),
        patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")) as mock_xadd,
    ):
        client.get("/workbench/", headers={"Authorization": "Bearer token"})

    events = [e for e in _captured_events(mock_xadd) if e["event_type"] == "hpc_denied"]
    assert events
    event = events[0]
    _assert_contract_compliant(event)
    assert event["decision"] == "deny"
    assert event["reason"] == "quota_exceeded"


def test_auth_middleware_missing_token_event_is_contract_compliant(client):
    with patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")) as mock_xadd:
        client.get("/workbench/")

    events = [e for e in _captured_events(mock_xadd) if e["event_type"] == "auth_failed"]
    assert events
    event = events[0]
    _assert_contract_compliant(event)
    assert event["reason"] == "missing_token"


def test_auth_middleware_invalid_token_event_is_contract_compliant(client):
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=None)),
        patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")) as mock_xadd,
    ):
        client.get("/workbench/", headers={"Authorization": "Bearer invalid"})

    events = [e for e in _captured_events(mock_xadd) if e["event_type"] == "auth_failed"]
    assert events
    _assert_contract_compliant(events[0])
    assert events[0]["reason"] == "invalid_token"


def test_policy_middleware_denial_event_is_contract_compliant(client, valid_user):
    with (
        patch.object(_main_mod.iam, "validate", AsyncMock(return_value=valid_user)),
        patch.object(
            _main_mod.policy, "evaluate",
            AsyncMock(return_value={"allowed": False, "reason": "no_permission"}),
        ),
        patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")) as mock_xadd,
    ):
        client.get("/workbench/", headers={"Authorization": "Bearer token"})

    events = [e for e in _captured_events(mock_xadd) if e["event_type"] == "policy_denied"]
    assert events
    event = events[0]
    _assert_contract_compliant(event)
    assert event["decision"] == "deny"
    assert event["reason"] == "no_permission"


def test_gateway_upstream_forward_event_is_contract_compliant(client, authed):
    with patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")) as mock_xadd:
        client.get("/workbench/ping", headers={"Authorization": "Bearer token"})

    events = [e for e in _captured_events(mock_xadd) if e["event_type"] == "upstream_forward"]
    assert events, "expected a gateway.py 'upstream_forward' event"
    event = events[0]
    _assert_contract_compliant(event)
    assert "status_code" in event["context"]


async def test_security_trace_created_event_is_contract_compliant():
    """core/security.py::attach_trace is not wired into the live middleware
    stack (TraceMiddleware generates trace_id inline and never calls it --
    confirmed by grep: nothing outside its own test imports app.core.security),
    so this exercises it directly rather than via an HTTP request, matching
    tests/test_security.py's existing approach for this module."""
    from unittest.mock import MagicMock
    from app.core.security import attach_trace

    request = MagicMock()
    request.url.path = "/workbench/run"
    request.method = "POST"
    request.state = MagicMock()

    with patch.object(_audit_client_mod._redis, "xadd", AsyncMock(return_value="0-0")) as mock_xadd:
        await attach_trace(request)
        # fire_audit schedules _emit via asyncio.create_task rather than
        # awaiting it -- give that task a turn on the loop before asserting.
        await asyncio.sleep(0)

    events = [e for e in _captured_events(mock_xadd) if e["event_type"] == "trace_created"]
    assert events, "expected a core/security.py 'trace_created' event"
    event = events[0]
    _assert_contract_compliant(event)
    assert event["service"] == "gateway"
    assert "path" in event["context"]
    assert "method" in event["context"]


# ---------------------------------------------------------------------------
# No duplicate schema paths: every producer routes through build_audit_event
# ---------------------------------------------------------------------------

def _files_calling_audit_transport() -> dict[Path, ast.Module]:
    """Every .py file under app/ that calls fire_audit/_emit/audit_log."""
    hits = {}
    for path in (REPO_ROOT / "app").rglob("*.py"):
        source = path.read_text()
        if any(name in source for name in ("fire_audit(", "_emit(", "audit_log(")):
            hits[path] = ast.parse(source, filename=str(path))
    return hits


def test_every_audit_transport_call_site_uses_build_audit_event():
    """Statically verifies there is exactly one place in this repo that
    shapes an audit-event dict (build_audit_event itself, inside
    audit_client.py) -- every *call site* of fire_audit/_emit/audit_log
    passes its result straight through rather than constructing a dict
    literal of its own."""
    offending = []

    for path, tree in _files_calling_audit_transport().items():
        is_audit_client_module = path.name == "audit_client.py"
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            if name not in ("fire_audit", "_emit", "audit_log"):
                continue
            if is_audit_client_module and path.name == "audit_client.py":
                # fire_audit's own internal audit_log()->fire_audit(event)
                # delegation and _emit's definition live here; not a
                # dict-shaping call site.
                continue
            if not node.args:
                continue
            arg = node.args[0]
            # Acceptable: build_audit_event(...) call, or a bare name/attr
            # (a variable already built elsewhere, e.g. audit_log(event)
            # delegating a caller's own build_audit_event(...) result).
            if isinstance(arg, ast.Call):
                call_name = arg.func.id if isinstance(arg.func, ast.Name) else getattr(arg.func, "attr", None)
                if call_name != "build_audit_event":
                    offending.append(f"{path.relative_to(REPO_ROOT)}: {name}() called with {call_name}(...) instead of build_audit_event(...)")
            elif isinstance(arg, ast.Dict):
                offending.append(f"{path.relative_to(REPO_ROOT)}: {name}() called with a raw dict literal instead of build_audit_event(...)")

    assert offending == [], "\n".join(offending)

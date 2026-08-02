import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import redis.asyncio as aioredis

from app.core.config import Config

_redis = aioredis.from_url(Config.AUDIT_REDIS, decode_responses=True)
STREAM = "audit:events"


# ---------------------------------------------------------------------------
# PR4.5: single audit-event contract. Every call site in this service that
# writes to `audit:events` must build its payload through this function --
# not hand-roll a dict -- so there is exactly one place in this repo that
# defines the on-the-wire shape.
#
# Field names and types mirror omnibioai-security-audit's AuditEvent
# (audit/models.py) exactly: event_id, timestamp, service, event_type,
# user_id, action, resource, decision, reason, trace_id, context. That repo
# is not a dependency of this one (separate deployable, no shared package),
# so this is a parallel, hand-kept-in-sync definition, not a shared import
# -- see PR4.5's report for why, and the cross-repo regression tests in
# both repos that catch drift between the two.
#
# Before PR4.5, callers built ad-hoc dicts directly (6 call sites, 3
# different shapes -- audit.py/hpc.py/auth.py/policy.py/gateway.py were
# close but missing event_id/timestamp and carrying fields AuditEvent
# doesn't model (endpoint, latency_ms, status_code); core/security.py used
# an entirely different key set with no `service`/`event_type` at all, which
# would have failed AuditEvent validation outright). Two concrete bugs that
# fixes: (1) leaving event_id/timestamp unset meant the worker's parser
# would default fresh ones on every parse attempt (audit/models.py's
# Field(default_factory=...)), so a retried/redelivered Redis message got a
# *different* event_id each time -- defeating PR4.2's Sink dedup-on-
# event_id guarantee and silently duplicating rows; (2) any field not in
# AuditEvent's schema was silently dropped by Pydantic's default "ignore
# extra fields" behavior (endpoint/latency_ms/status_code/path/method never
# reached the database at all).
# ---------------------------------------------------------------------------


def build_audit_event(
    *,
    service: str,
    event_type: str,
    action: str = "",
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    decision: Optional[str] = None,
    reason: Optional[str] = None,
    trace_id: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
) -> dict:
    """Builds one audit:events-stream payload, contract-compliant with
    AuditEvent. `event_id`/`timestamp` are generated here -- at emission
    time, once -- rather than left for the consumer to default, so the
    same event keeps the same identity across Redis retries/redelivery.
    Anything gateway-specific that doesn't fit the shared contract
    (endpoint, latency_ms, status_code, ...) belongs in `context`, not as
    a new top-level key.
    """
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "event_type": event_type,
        "user_id": user_id,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "trace_id": trace_id,
        "context": context or {},
    }


async def _emit(event: dict):
    try:
        await _redis.xadd(
            STREAM,
            {"data": json.dumps(event, default=str)},
            maxlen=1_000_000,
            approximate=True,
        )
    except Exception:
        pass


def fire_audit(event: dict):
    """Schedule a non-blocking audit write. Never raises."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(_emit(event))
    except Exception:
        pass


async def audit_log(event: dict):
    """Async fire-and-forget wrapper kept for import compatibility."""
    fire_audit(event)

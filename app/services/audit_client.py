import asyncio
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import redis.asyncio as aioredis

from app.core.config import Config

_redis = aioredis.from_url(Config.AUDIT_REDIS, decode_responses=True)
STREAM = "audit:events"


# ---------------------------------------------------------------------------
# HIPAA PR3b: producer-side signing. Hand-ported from
# omnibioai-security-audit's audit/signing.py::sign_audit_event -- that
# repo is not a dependency of this one (separate deployable, no shared
# package, same tradeoff already accepted for build_audit_event's contract
# above), so this is a parallel, hand-kept-in-sync copy of the *signing*
# half only. Only the consumer needs verify_audit_event; a producer never
# needs to verify its own signature.
#
# Byte-for-byte identical construction to the original: domain-separated
# HMAC-SHA256 key derivation, "v1\n<service>\n<data>" as the signed
# message. Must stay in sync with that module or every event this service
# signs will fail the consumer's verify_audit_event() -- there is no
# import-time check that would catch drift, only the cross-repo signing
# tests (this file's own, and the two contract-reconciliation suites in
# each repo) exercising real HMAC values against each other's fixtures.
# ---------------------------------------------------------------------------
_SIGNING_DOMAIN_LABEL = "omnibioai-audit-events"
_SIGNING_VERSION = "v1"


def _signing_key(secret: str) -> bytes:
    return hashlib.sha256(f"{_SIGNING_DOMAIN_LABEL}:{secret}".encode()).digest()


def _signing_message(version: str, service: str, data: str) -> bytes:
    return f"{version}\n{service}\n{data}".encode()


def sign_audit_event(service: str, data: str, secret: str) -> str:
    """Returns the `sig` field value for one audit event: `"v1:<hex-hmac>"`.

    `data` must be the *exact* string that will be written to the stream's
    `data` field -- not a re-serialization -- since the MAC covers those
    exact bytes. See _emit() below: `data` is computed once and the same
    string is both signed and published, never re-encoded in between.
    """
    if not service:
        raise ValueError("service must be a non-empty string")
    if data is None:
        raise ValueError("data must not be None")
    mac = hmac.new(
        _signing_key(secret), _signing_message(_SIGNING_VERSION, service, data), hashlib.sha256
    ).hexdigest()
    return f"{_SIGNING_VERSION}:{mac}"


# ---------------------------------------------------------------------------
# PR4.5: single audit-event contract. Every call site in this service that
# writes to `audit:events` must build its payload through this function --
# not hand-roll a dict -- so there is exactly one place in this repo that
# defines the on-the-wire shape.
#
# Field names and types mirror omnibioai-security-audit's AuditEvent
# (audit/models.py) exactly: event_id, timestamp, service, event_type,
# user_id, organization_id, tenant_scope, action, resource, decision, reason,
# trace_id, context. That repo
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
    organization_id: Optional[str] = None,
    tenant_scope: str = "unknown",
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
        "organization_id": organization_id,
        "tenant_scope": tenant_scope,
        "action": action,
        "resource": resource,
        "decision": decision,
        "reason": reason,
        "trace_id": trace_id,
        "context": context or {},
    }


async def _emit(event: dict):
    try:
        # `data` is computed exactly once and both signed and published as
        # that same string -- signing a dict and separately re-serializing
        # it for the wire would let JSON key-order/whitespace differences
        # desync the signature from what the consumer actually verifies.
        data = json.dumps(event, default=str)
        fields = {"data": data}
        service = event.get("service")
        if service:
            fields["sig"] = sign_audit_event(service, data, Config.JWT_SECRET)
        await _redis.xadd(
            STREAM,
            fields,
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

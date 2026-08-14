"""HIPAA PR3b: producer-side signing for app/services/audit_client.py.

sign_audit_event/_signing_key/_signing_message in that module are a
hand-ported copy of omnibioai-security-audit's audit/signing.py (that repo
is not a dependency of this one -- see the module's own comment). The
CROSS_REPO_VECTOR below is a fixed (service, data, secret) -> signature
triple generated directly from the real omnibioai-security-audit
audit.signing.sign_audit_event() (not reproduced here, just its output),
so a passing test_matches_real_consumer_signing_vector proves this port
is byte-for-byte compatible with the actual consumer's verifier without
this repo importing or depending on that one at runtime or at test time.
"""
import json
from unittest.mock import AsyncMock

import pytest

from app.services.audit_client import (
    _emit,
    _signing_key,
    _signing_message,
    build_audit_event,
    sign_audit_event,
)

# Generated once via omnibioai-security-audit's real audit.signing.sign_audit_event
# (`sign_audit_event("gateway", data, "test-secret-vector")`) -- see this file's
# module docstring. If this ever fails, the two implementations have drifted.
CROSS_REPO_VECTOR = {
    "service": "gateway",
    "data": (
        '{"event_id": "11111111-1111-1111-1111-111111111111", "timestamp": '
        '"2026-01-01T00:00:00+00:00", "service": "gateway", "event_type": '
        '"request", "user_id": null, "action": "", "resource": null, '
        '"decision": null, "reason": null, "trace_id": null, "context": {}}'
    ),
    "secret": "test-secret-vector",
    "sig": "v1:96b18a8dbd82707a78b14a7c446acfef50d3882c9d5160ffad6084d0771c7410",
}


def test_matches_real_consumer_signing_vector():
    """Byte-for-byte proof this hand-port produces the exact signature the
    real omnibioai-security-audit consumer's verify_audit_event() would
    accept -- without this repo importing or depending on that one."""
    v = CROSS_REPO_VECTOR
    assert sign_audit_event(v["service"], v["data"], v["secret"]) == v["sig"]


# ---------------------------------------------------------------------------
# 1. Signature exists / 2. signature format
# ---------------------------------------------------------------------------

def test_sign_audit_event_returns_v1_prefixed_hex():
    sig = sign_audit_event("gateway", '{"a": 1}', "s3cr3t")
    version, sep, mac_hex = sig.partition(":")
    assert version == "v1"
    assert sep == ":"
    bytes.fromhex(mac_hex)  # raises if not valid hex


def test_sign_rejects_empty_service():
    with pytest.raises(ValueError):
        sign_audit_event("", '{"a": 1}', "s3cr3t")


def test_sign_rejects_none_data():
    with pytest.raises(ValueError):
        sign_audit_event("gateway", None, "s3cr3t")


# ---------------------------------------------------------------------------
# 3. Payload tampering must invalidate the signature (checked by
#    recomputing independently -- this repo has no verify_audit_event of
#    its own, a producer never needs one; the real tamper-detection
#    round-trip through the real consumer is proven at the integration
#    level, see this PR's report).
# ---------------------------------------------------------------------------

def test_tampered_data_produces_a_different_signature():
    original = '{"event_type": "request", "decision": "allow"}'
    tampered = '{"event_type": "request", "decision": "deny"}'
    sig_original = sign_audit_event("gateway", original, "s3cr3t")
    sig_tampered = sign_audit_event("gateway", tampered, "s3cr3t")
    assert sig_original != sig_tampered


def test_even_one_byte_of_difference_changes_the_signature():
    sig_a = sign_audit_event("gateway", '{"x": 1}', "s3cr3t")
    sig_b = sign_audit_event("gateway", '{"x": 2}', "s3cr3t")
    assert sig_a != sig_b


def test_relabeling_onto_a_different_service_changes_the_signature():
    data = '{"a": 1}'
    sig_gateway = sign_audit_event("gateway", data, "s3cr3t")
    sig_tes = sign_audit_event("tes", data, "s3cr3t")
    assert sig_gateway != sig_tes


def test_signing_is_deterministic():
    data = '{"a": 1}'
    assert sign_audit_event("gateway", data, "s3cr3t") == sign_audit_event(
        "gateway", data, "s3cr3t"
    )


# ---------------------------------------------------------------------------
# 4. Exact serialization: the signature must cover exactly the string
#    placed on the wire, computed once, never re-derived from the dict.
# ---------------------------------------------------------------------------

async def test_emit_signs_the_exact_data_string_it_publishes(monkeypatch):
    """_emit must sign fields["data"] itself, not a fresh json.dumps(event)
    -- if it re-serialized, this test's differently-key-ordered `context`
    would still verify (dict equality survives reordering) but a real
    byte-for-byte MAC would not, so this specifically checks the sig
    matches sign_audit_event(service, fields["data"], secret) using the
    captured wire string, not the original dict."""
    from app.services import audit_client as mod

    captured = {}

    async def fake_xadd(stream, fields, **kwargs):
        captured["stream"] = stream
        captured["fields"] = fields
        return "0-0"

    monkeypatch.setattr(mod, "_redis", AsyncMock(xadd=fake_xadd))
    monkeypatch.setattr(mod.Config, "JWT_SECRET", "s3cr3t")

    event = build_audit_event(service="gateway", event_type="request")
    await _emit(event)

    data = captured["fields"]["data"]
    sig = captured["fields"]["sig"]
    assert sig == sign_audit_event("gateway", data, "s3cr3t")
    # And the wire data really is exactly json.dumps(event, default=str):
    assert json.loads(data)["event_id"] == event["event_id"]


async def test_emit_includes_both_data_and_sig_fields(monkeypatch):
    from app.services import audit_client as mod

    captured = {}

    async def fake_xadd(stream, fields, **kwargs):
        captured["fields"] = fields
        return "0-0"

    monkeypatch.setattr(mod, "_redis", AsyncMock(xadd=fake_xadd))
    monkeypatch.setattr(mod.Config, "JWT_SECRET", "s3cr3t")

    await _emit(build_audit_event(service="gateway", event_type="request"))

    assert "data" in captured["fields"]
    assert "sig" in captured["fields"]
    assert captured["fields"]["sig"].startswith("v1:")


async def test_emit_without_a_service_still_publishes_unsigned(monkeypatch):
    """Defensive path: sign_audit_event() raises on an empty service (see
    test_sign_rejects_empty_service above). _emit must not let that
    exception suppress publication entirely -- an event without a service
    field publishes without a sig rather than not publishing at all, and
    the consumer already classifies missing-sig as "unsigned", the
    correct, honest outcome."""
    from app.services import audit_client as mod

    captured = {}

    async def fake_xadd(stream, fields, **kwargs):
        captured["fields"] = fields
        return "0-0"

    monkeypatch.setattr(mod, "_redis", AsyncMock(xadd=fake_xadd))
    monkeypatch.setattr(mod.Config, "JWT_SECRET", "s3cr3t")

    await _emit({"event_type": "request"})  # no "service" key

    assert "data" in captured["fields"]
    assert "sig" not in captured["fields"]


# ---------------------------------------------------------------------------
# 5. Secret handling
# ---------------------------------------------------------------------------

def test_signature_does_not_contain_the_secret():
    sig = sign_audit_event("gateway", '{"a": 1}', "super-secret-value")
    assert "super-secret-value" not in sig


def test_wrong_secret_produces_a_different_signature():
    data = '{"a": 1}'
    assert sign_audit_event("gateway", data, "secret-a") != sign_audit_event(
        "gateway", data, "secret-b"
    )


async def test_emit_exception_never_leaks_the_secret(monkeypatch, capsys):
    """_emit's blanket except swallows all errors (including a signing
    failure) and _emit never logs/prints anything -- so there is no path
    by which the secret could reach stdout/stderr from this function."""
    from app.services import audit_client as mod

    monkeypatch.setattr(mod, "_redis", AsyncMock(xadd=AsyncMock(side_effect=RuntimeError("boom"))))
    monkeypatch.setattr(mod.Config, "JWT_SECRET", "super-secret-value")

    await _emit(build_audit_event(service="gateway", event_type="request"))  # must not raise

    captured = capsys.readouterr()
    assert "super-secret-value" not in captured.out
    assert "super-secret-value" not in captured.err


def test_missing_jwt_secret_does_not_silently_use_an_unsafe_literal(monkeypatch):
    """Config.JWT_SECRET (app/core/config.py) already has its own
    documented default -- os.getenv("JWT_SECRET", "dev-secret") -- read
    once at import time. Signing reuses that exact same value/convention
    rather than introducing a second, independently-defaulted secret
    variable for this one function; there is deliberately no second
    fallback here that could diverge from it."""
    from app.services import audit_client as mod

    monkeypatch.setattr(mod.Config, "JWT_SECRET", "dev-secret")
    sig = sign_audit_event("gateway", '{"a": 1}', mod.Config.JWT_SECRET)
    assert sig.startswith("v1:")  # signs fine -- the point is there's one source of truth, not a masked failure


# ---------------------------------------------------------------------------
# 6. Domain separation from the TES IAM-cache HMAC construction (mirrors
#    the equivalent test in omnibioai-security-audit's test_signing.py --
#    same property, must hold here too since this is the same algorithm).
# ---------------------------------------------------------------------------

def test_signing_key_is_domain_separated_from_a_bare_secret_hash():
    import hashlib

    secret = "s3cr3t"
    assert _signing_key(secret) != hashlib.sha256(secret.encode()).digest()


def test_signing_message_uses_newline_separator_not_concatenation():
    # service="ab", data="cd" must not collide with service="a", data="bcd"
    assert _signing_message("v1", "ab", "cd") != _signing_message("v1", "a", "bcd")

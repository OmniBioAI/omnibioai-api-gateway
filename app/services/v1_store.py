"""Redis-backed state for the public /v1 API: per-caller rate limits,
Idempotency-Key records, prepaid/free quota counters, and billable usage
events. Every method fails *open* on Redis errors except where noted: a
Redis outage must not take the paid API down, and every failure here is
logged in the response path rather than silently changing a decision.
"""
import hashlib
import json
import math
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import Config
from app.services.outbox import Outbox

_PREFIX = "gateway:v1:"
# How long an in-progress idempotency claim blocks a duplicate. Longer than
# the slowest expected answer, short enough that a crashed request does not
# lock the key for long.
_IN_PROGRESS_TTL = 120


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def request_fingerprint(body) -> str:
    """Stable hash of a JSON request body, for detecting an Idempotency-Key
    reused with a different request."""
    return _sha(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str))


class MemoryStore:
    """In-process stand-in for the handful of Redis commands V1Store uses,
    with per-key expiry. Used when V1_REDIS_URL is unset: one gateway
    process then enforces rate limits and idempotency on its own."""

    MAX_KEYS = 100_000

    def __init__(self, clock=time.monotonic):
        self._data: dict[str, tuple[str, Optional[float]]] = {}
        self._clock = clock

    def _live(self, key):
        item = self._data.get(key)
        if item is None:
            return None
        value, expires = item
        if expires is not None and expires <= self._clock():
            del self._data[key]
            return None
        return value

    def _prune(self):
        if len(self._data) < self.MAX_KEYS:
            return
        now = self._clock()
        for key in [k for k, (_, exp) in self._data.items() if exp is not None and exp <= now]:
            del self._data[key]
        if len(self._data) >= self.MAX_KEYS:
            # Still full of live keys: drop the oldest-inserted tenth.
            for key in list(self._data)[: self.MAX_KEYS // 10]:
                del self._data[key]

    def _put(self, key, value, ttl=None, keep_ttl=False):
        expires = self._data[key][1] if keep_ttl and key in self._data else (
            self._clock() + ttl if ttl else None)
        self._prune()
        self._data[key] = (str(value), expires)

    async def incr(self, key):
        value = int(self._live(key) or 0) + 1
        self._put(key, value, keep_ttl=True)
        return value

    async def decr(self, key):
        value = int(self._live(key) or 0) - 1
        self._put(key, value, keep_ttl=True)
        return value

    async def expire(self, key, ttl):
        if self._live(key) is None:
            return False
        self._data[key] = (self._data[key][0], self._clock() + ttl)
        return True

    async def get(self, key):
        return self._live(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and self._live(key) is not None:
            return None
        self._put(key, value, ttl=ex)
        return True

    async def delete(self, key):
        self._data.pop(key, None)


class V1Store:
    def __init__(self, redis_url: str, usage_redis_url: str, outbox_path: str = Config.USAGE_OUTBOX_PATH):
        self.redis = aioredis.from_url(redis_url, decode_responses=True) if redis_url else MemoryStore()
        self.usage_redis = aioredis.from_url(usage_redis_url, decode_responses=True)
        self.outbox = Outbox(outbox_path)

    # ---------------- rate limit (token bucket) ----------------------------
    async def hit_rate_limit(self, subject: str, limit: int) -> tuple[bool, int, int]:
        """Design audit gap #7 ("fixed one-minute window... rather than a
        token bucket"): `limit` tokens refill continuously over 60 seconds
        (rate = limit/60 tokens/sec), bucket capacity = limit -- a caller
        can burst its full per-minute allowance at once, then it refills
        smoothly, rather than the old fixed window's hard reset-at-:00
        boundary, which let a caller spend its whole budget in the last
        second of one window and again in the first second of the next:
        up to 2x `limit` requests in under two seconds, never caught by a
        window that only ever compares against *one* window's count at a
        time. Returns (allowed, remaining, seconds_until_next_token) --
        remaining is the floored token count after this request; the third
        value is 0 whenever a request is allowed (another token is already
        available right now) and otherwise how long until the bucket has
        earned back at least one, used for X-RateLimit-Reset/Retry-After.

        Not atomic against a concurrent request for the *same* subject on
        a real Redis backend (a plain GET then SET, no Lua script) -- a
        request landing in that window could read the same token count and
        both deduct from it, each believing it got a distinct token. A
        bounded, accepted imperfection (the practical cost is occasionally
        allowing one extra request under true concurrent load for one
        subject), not a new class of risk: nothing here is billing-
        critical the way reserve_quota's own atomic DECR had to be. Fails
        open on a Redis error, same posture as every other method here.
        """
        if limit <= 0:
            return False, 0, 60
        rate = limit / 60.0
        now = time.time()
        key = f"{_PREFIX}rltb:{subject}"
        try:
            raw = await self.redis.get(key)
            if raw is None:
                tokens, last = float(limit), now
            else:
                tokens, last = json.loads(raw)
            tokens = min(float(limit), tokens + max(0.0, now - last) * rate)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            await self.redis.set(key, json.dumps([tokens, now]), ex=120)
        except Exception:
            return True, limit, 0
        reset = 0 if tokens >= 1.0 else max(1, math.ceil((1.0 - tokens) / rate))
        return allowed, int(tokens), reset

    # ---------------- concurrent-request limit ------------------------------
    def _concurrency_key(self, subject: str) -> str:
        return f"{_PREFIX}conc:{subject}"

    async def acquire_concurrency_slot(self, subject: str, limit: int) -> bool:
        """Design audit gap #7 ("concurrent-answer limits are absent"):
        atomically increments the in-flight-request counter for `subject`
        (an API key, a user session, or f"org:{org_id}") and reports
        whether the new count is within `limit`. If not, immediately
        decrements back out -- a caller denied a slot never holds one, so
        it must call release_concurrency_slot only when this returns True
        (the same reserve-then-release pairing reserve_quota/release_quota
        already established for the billing quota counter). The TTL is a
        safety net only, for the case a crash skips the matching release --
        every normal request releases its own slot long before 300s.
        Fails open (True) on a Redis error.
        """
        key = self._concurrency_key(subject)
        try:
            count = await self.redis.incr(key)
            await self.redis.expire(key, 300)
        except Exception:
            return True
        if count > limit:
            try:
                await self.redis.decr(key)
            except Exception:
                pass
            return False
        return True

    async def release_concurrency_slot(self, subject: str) -> None:
        """Releases a slot acquired by acquire_concurrency_slot. Must only
        be called for a subject that call actually returned True for --
        calling it for a denied acquisition would double-release (the
        denial already decremented back out itself)."""
        try:
            await self.redis.decr(self._concurrency_key(subject))
        except Exception:
            pass

    # ---------------- rate limit override (maintained by omnibioai-billing)
    def _org_rate_limit_key(self, org_id: str) -> str:
        # Nested under the same "quota:" prefix omnibioai-billing's
        # gateway_quota_sync_service.py already writes allowance keys
        # to -- deliberately not a new "ratelimit:" top-level prefix,
        # so this reuses that service's existing Redis ACL grant
        # (~gateway:v1:quota:*) exactly as-is. See that module's own
        # docstring for the full reasoning.
        return f"{_PREFIX}quota:{org_id}:ratelimit"

    async def rate_limit_for_org(self, org_id: str) -> Optional[int]:
        """The org's plan-specific requests-per-minute override, or
        None when no plan override is set (every plan this platform
        currently seeds leaves it unset -- a real number is a product
        decision, not an engineering one) or on a Redis error. Callers
        fall back to the configured global default in either case."""
        try:
            raw = await self.redis.get(self._org_rate_limit_key(org_id))
        except Exception:
            return None
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    # ---------------- quota (maintained by omnibioai-billing) -------------
    def _quota_key(self, org_id: str, resource: str) -> str:
        return f"{_PREFIX}quota:{org_id}:{resource}"

    async def quota_remaining(self, org_id: str, resource: str) -> Optional[int]:
        """Units the org may still use, or None when billing has not set a
        quota (unmetered). Fails open (None) on Redis errors."""
        try:
            raw = await self.redis.get(self._quota_key(org_id, resource))
        except Exception:
            return None
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            return None

    async def reserve_quota(self, org_id: str, resource: str) -> bool:
        """Atomically reserve one unit of `resource` for `org_id` before
        doing the work it would bill for, and report whether the
        reservation succeeded. Replaces the old quota_remaining()-then-
        later-consume_quota() pair, which read the counter, did the
        (slow) upstream call, and only decremented afterward -- any
        number of concurrent requests could all observe "1 remaining"
        before any of them decremented, and all of them would then
        succeed, overrunning the quota by however many were in flight
        at once. Redis's DECR is atomic, so only as many concurrent
        reservations as there are units left can ever observe a
        non-negative result here; the rest observe negative and
        compensate back to zero immediately (never below zero, and
        never creating a key that did not already exist -- an org
        without a quota key stays unmetered, exactly like before).

        Fails open (reservation succeeds) on a Redis error, the same
        posture every other method in this class takes: an outage must
        never block a paid request, only leave this particular overrun
        protection briefly unenforced until Redis recovers.
        """
        key = self._quota_key(org_id, resource)
        try:
            if await self.redis.get(key) is None:
                return True  # unmetered: no quota key set for this org/resource
            value = await self.redis.decr(key)
        except Exception:
            return True
        if value < 0:
            try:
                await self.redis.incr(key)
            except Exception:
                pass
            return False
        return True

    async def release_quota(self, org_id: str, resource: str) -> None:
        """Refund a reservation made by reserve_quota() for a call that was
        then not actually billable (the upstream request failed) -- the
        reservation already decremented optimistically, before knowing
        whether the call would succeed. Never creates the key: mirrors
        reserve_quota's own "only adjust an existing counter" rule."""
        key = self._quota_key(org_id, resource)
        try:
            if await self.redis.get(key) is not None:
                await self.redis.incr(key)
        except Exception:
            pass

    # ---------------- idempotency ----------------------------------------
    def _idem_key(self, subject: str, idempotency_key: str) -> str:
        return f"{_PREFIX}idem:{subject}:{_sha(idempotency_key)}"

    async def idempotency_begin(self, subject: str, idempotency_key: str, fingerprint: str) -> dict:
        """Claim an Idempotency-Key. Returns one of:
        {"state": "new"}                    -- caller should run the request
        {"state": "replay", "status", "body"} -- return the stored result
        {"state": "in_progress"}            -- a duplicate is still running
        {"state": "mismatch"}               -- key reused for another request
        Fails open ({"state": "new"}) on Redis errors."""
        key = self._idem_key(subject, idempotency_key)
        claim = json.dumps({"state": "in_progress", "fingerprint": fingerprint})
        try:
            if await self.redis.set(key, claim, nx=True, ex=_IN_PROGRESS_TTL):
                return {"state": "new"}
            raw = await self.redis.get(key)
        except Exception:
            return {"state": "new"}
        if raw is None:
            return {"state": "in_progress"}
        record = json.loads(raw)
        if record.get("fingerprint") != fingerprint:
            return {"state": "mismatch"}
        if record.get("state") == "done":
            return {"state": "replay", "status": record["status"], "body": record["body"]}
        return {"state": "in_progress"}

    async def idempotency_finish(self, subject: str, idempotency_key: str, fingerprint: str, status: int, body) -> None:
        """Store a successful result for replay, or release the claim so a
        failed request can be retried with the same key."""
        key = self._idem_key(subject, idempotency_key)
        try:
            if 200 <= status < 300:
                record = {"state": "done", "fingerprint": fingerprint, "status": status, "body": body}
                await self.redis.set(key, json.dumps(record), ex=Config.V1_IDEMPOTENCY_TTL)
            else:
                await self.redis.delete(key)
        except Exception:
            pass

    # ---------------- billable usage -------------------------------------
    async def _xadd_usage_event(self, event: dict) -> bool:
        try:
            await self.usage_redis.xadd(
                Config.USAGE_STREAM, {"data": json.dumps(event)}, maxlen=1_000_000, approximate=True,
            )
            return True
        except Exception:
            return False

    async def emit_usage(self, *, org_id: str, user_id: str, resource: str, trace_id: str,
                         dedup_key: str, metadata: dict, quantity: int = 1, unit: str = "requests") -> bool:
        """XADD one billable usage event in omnibioai-usage-client's wire
        format. event_id is derived from dedup_key, so a replayed or
        re-emitted request maps to the same id and billing counts it once.

        quantity/unit default to 1/"requests" (unchanged from before
        M16) -- a BYOK-routed call's llm.tokens.input/output events (see
        app/routes/v1.py) pass the real token count and unit="tokens"
        instead; dedup_key must be distinct per resource in that case
        (e.g. f"{request_id}:tokens:input"), since this method's own
        event_id is derived from it and two different resources sharing
        one dedup_key would collide.

        A successful answer has already been returned to the caller by
        the time this runs -- a lost event here is lost revenue, never
        an overcharge, so an XADD failure writes to the local outbox
        instead of discarding the event. Opportunistically drains any
        already-pending outbox events first: once Redis recovers, the
        very next successful call flushes the backlog rather than
        waiting on a separate scheduler."""
        event = {
            "event_id": str(uuid.UUID(_sha(dedup_key)[:32])),
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            "organization_id": str(org_id),
            "service": "api",
            "resource": resource,
            "action": "completed",
            "quantity": quantity,
            "unit": unit,
            "user_id": str(user_id) if user_id else None,
            "trace_id": trace_id or None,
            "metadata": {**metadata, "billable": True},
        }
        await self.outbox.drain(self._xadd_usage_event)
        if await self._xadd_usage_event(event):
            return True
        self.outbox.write(event)
        return False

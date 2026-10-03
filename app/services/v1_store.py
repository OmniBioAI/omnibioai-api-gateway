"""Redis-backed state for the public /v1 API: per-caller rate limits,
Idempotency-Key records, prepaid/free quota counters, and billable usage
events. Every method fails *open* on Redis errors except where noted: a
Redis outage must not take the paid API down, and every failure here is
logged in the response path rather than silently changing a decision.
"""
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import Config

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
    def __init__(self, redis_url: str, usage_redis_url: str):
        self.redis = aioredis.from_url(redis_url, decode_responses=True) if redis_url else MemoryStore()
        self.usage_redis = aioredis.from_url(usage_redis_url, decode_responses=True)

    # ---------------- rate limit (fixed one-minute window) ----------------
    async def hit_rate_limit(self, subject: str, limit: int) -> tuple[bool, int, int]:
        """Count one request for `subject`. Returns (allowed, remaining,
        seconds_until_reset). Fails open on Redis errors."""
        now = int(time.time())
        window = now // 60
        reset = 60 - (now % 60)
        key = f"{_PREFIX}rl:{subject}:{window}"
        try:
            count = await self.redis.incr(key)
            if count == 1:
                await self.redis.expire(key, 61)
        except Exception:
            return True, limit, reset
        return count <= limit, max(0, limit - count), reset

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

    async def consume_quota(self, org_id: str, resource: str) -> None:
        """Decrement an existing quota after a billed success. Never creates
        the key: an org without a quota stays unmetered here."""
        key = self._quota_key(org_id, resource)
        try:
            if await self.redis.get(key) is not None:
                await self.redis.decr(key)
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
    async def emit_usage(self, *, org_id: str, user_id: str, resource: str, trace_id: str,
                         dedup_key: str, metadata: dict) -> bool:
        """XADD one billable usage event in omnibioai-usage-client's wire
        format. event_id is derived from dedup_key, so a replayed or
        re-emitted request maps to the same id and billing counts it once."""
        event = {
            "event_id": str(uuid.UUID(_sha(dedup_key)[:32])),
            "timestamp": datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            "organization_id": str(org_id),
            "service": "api",
            "resource": resource,
            "action": "completed",
            "quantity": 1,
            "unit": "requests",
            "user_id": str(user_id) if user_id else None,
            "trace_id": trace_id or None,
            "metadata": {**metadata, "billable": True},
        }
        try:
            await self.usage_redis.xadd(
                Config.USAGE_STREAM, {"data": json.dumps(event)}, maxlen=1_000_000, approximate=True,
            )
            return True
        except Exception:
            return False

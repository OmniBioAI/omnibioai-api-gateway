"""Local durability for billable usage events that failed to reach Redis.

V1Store.emit_usage (app/services/v1_store.py) is on the hot path of an
already-answered, successful public-API request: it must never raise,
and historically a Redis outage at exactly that moment meant the event
was silently discarded (the caller already got their answer and was
never charged). This module gives that one failure mode a second
chance -- a local, file-backed SQLite table, drained back into Redis
once it recovers, so a transient outage becomes a delayed write instead
of a permanently lost event.

A lost event must never become an overcharge either way: drain reuses
each event's own deterministic event_id (derived from the same
dedup_key V1Store.emit_usage already hashes), so even a duplicate drain
attempt lands on the same id omnibioai-billing's consumer already
deduplicates by.

Every method here fails open, the same posture V1Store's own Redis
calls take: a broken outbox (disk full, corrupt file) must not take the
API down -- it only means that one event is lost instead of delayed,
exactly the pre-existing risk this module is narrowing, never widening.
"""
import json
import logging
import sqlite3
import threading
import time

logger = logging.getLogger("gateway.usage_outbox")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    created_at REAL NOT NULL
)
"""

# One file, one lock: SQLite itself serializes writers, but the
# check-then-act drain loop (SELECT, then DELETE each flushed row) needs
# its own mutex so two concurrent requests draining at once can't both
# "see" and re-flush the same row.
_lock = threading.Lock()


class Outbox:
    def __init__(self, path: str):
        self.path = path

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.execute(_SCHEMA)
        return conn

    def write(self, event: dict) -> None:
        """Persist one event that failed to XADD. Never raises."""
        try:
            with _lock, self._connect() as conn:
                conn.execute(
                    "INSERT INTO pending_events (event_id, payload, created_at) VALUES (?, ?, ?)",
                    (event["event_id"], json.dumps(event), time.time()),
                )
        except Exception:
            logger.warning("usage_outbox: failed to persist event %s", event.get("event_id"), exc_info=True)

    def pending_count(self) -> int:
        try:
            with self._connect() as conn:
                (count,) = conn.execute("SELECT COUNT(*) FROM pending_events").fetchone()
            return int(count)
        except Exception:
            return 0

    async def drain(self, flush) -> int:
        """Attempt to re-send every pending event via
        `await flush(event) -> bool`, oldest first. Stops at the first
        failure (Redis is still down -- no point burning through the
        rest) and never raises. Returns the number successfully flushed.
        The SQLite calls here are blocking, but local-file-sized; left
        synchronous rather than threaded off, same tradeoff this module's
        write() already makes."""
        flushed = 0
        try:
            with _lock:
                with self._connect() as conn:
                    rows = conn.execute(
                        "SELECT id, payload FROM pending_events ORDER BY id ASC"
                    ).fetchall()
                for row_id, payload in rows:
                    try:
                        ok = await flush(json.loads(payload))
                    except Exception:
                        ok = False
                    if not ok:
                        break
                    with self._connect() as conn:
                        conn.execute("DELETE FROM pending_events WHERE id = ?", (row_id,))
                    flushed += 1
        except Exception:
            logger.warning("usage_outbox: drain failed", exc_info=True)
        return flushed

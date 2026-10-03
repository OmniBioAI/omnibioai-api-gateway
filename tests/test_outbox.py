"""app/services/outbox.py: local durability for a usage event that
failed to reach Redis. write() never raises on a broken path; drain()
flushes oldest-first, stops at the first failure, and never raises.
"""
import asyncio

from app.services.outbox import Outbox


def _event(event_id="evt-1"):
    return {"event_id": event_id, "organization_id": "42", "resource": "literature.answer"}


def test_write_then_drain_flushes_and_removes(tmp_path):
    outbox = Outbox(str(tmp_path / "o.db"))
    outbox.write(_event())
    assert outbox.pending_count() == 1

    flushed_events = []

    async def flush(event):
        flushed_events.append(event)
        return True

    flushed = asyncio.run(outbox.drain(flush))
    assert flushed == 1
    assert flushed_events == [_event()]
    assert outbox.pending_count() == 0


def test_drain_stops_at_first_failure_and_keeps_later_events(tmp_path):
    outbox = Outbox(str(tmp_path / "o.db"))
    outbox.write(_event("evt-1"))
    outbox.write(_event("evt-2"))

    async def flush(event):
        return False  # Redis still down

    flushed = asyncio.run(outbox.drain(flush))
    assert flushed == 0
    assert outbox.pending_count() == 2


def test_drain_flushes_oldest_first_in_order(tmp_path):
    outbox = Outbox(str(tmp_path / "o.db"))
    outbox.write(_event("evt-1"))
    outbox.write(_event("evt-2"))
    outbox.write(_event("evt-3"))

    seen = []

    async def flush(event):
        seen.append(event["event_id"])
        return True

    flushed = asyncio.run(outbox.drain(flush))
    assert flushed == 3
    assert seen == ["evt-1", "evt-2", "evt-3"]
    assert outbox.pending_count() == 0


def test_drain_on_empty_outbox_is_a_noop(tmp_path):
    outbox = Outbox(str(tmp_path / "o.db"))

    async def flush(event):
        raise AssertionError("must not be called")

    assert asyncio.run(outbox.drain(flush)) == 0


def test_flush_raising_is_treated_as_failure_not_propagated(tmp_path):
    outbox = Outbox(str(tmp_path / "o.db"))
    outbox.write(_event())

    async def flush(event):
        raise ConnectionError("redis down")

    flushed = asyncio.run(outbox.drain(flush))  # must not raise
    assert flushed == 0
    assert outbox.pending_count() == 1


def test_write_to_unwritable_path_does_not_raise():
    outbox = Outbox("/nonexistent-dir-xyz/outbox.db")
    outbox.write(_event())  # must not raise
    assert outbox.pending_count() == 0


def test_pending_count_on_unwritable_path_returns_zero():
    outbox = Outbox("/nonexistent-dir-xyz/outbox.db")
    assert outbox.pending_count() == 0

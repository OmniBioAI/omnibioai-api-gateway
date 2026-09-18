"""Covers app/main.py's background IAM-cache invalidation loop: that a
non-empty token in an invalidation message evicts the right cache entry,
an empty token is a no-op, and the loop resubscribes after the
subscription itself raises instead of dying silently.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""
import asyncio
from unittest.mock import AsyncMock, patch

import app.main as _main_mod


async def test_invalidation_loop_evicts_token_when_present():
    """on_invalidate must call iam.evict(token) when token is non-empty."""
    captured = []
    done = asyncio.Event()

    async def fake_subscribe(cb):
        captured.append(cb)
        done.set()
        await asyncio.Future()  # block until cancelled

    with (
        patch.object(_main_mod.iam, "subscribe_invalidation", fake_subscribe),
        patch.object(_main_mod.iam, "evict", AsyncMock()) as mock_evict,
    ):
        task = asyncio.create_task(_main_mod._invalidation_loop())
        await done.wait()

        on_invalidate = captured[0]
        await on_invalidate("user1", "tok-abc")  # token present → evict
        await on_invalidate("user2", "")          # empty token → no evict

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    mock_evict.assert_called_once_with("tok-abc")


async def test_invalidation_loop_restarts_on_exception():
    """_invalidation_loop must restart subscribe_invalidation after an exception."""
    call_count = [0]
    stop = asyncio.Event()

    async def fake_subscribe(cb):
        call_count[0] += 1
        if call_count[0] >= 2:
            stop.set()
            await asyncio.Future()  # block
        raise RuntimeError("redis lost")

    with (
        patch.object(_main_mod.iam, "subscribe_invalidation", fake_subscribe),
        patch("app.main.asyncio.sleep", AsyncMock()),  # skip real sleep
    ):
        task = asyncio.create_task(_main_mod._invalidation_loop())
        await stop.wait()
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert call_count[0] >= 2

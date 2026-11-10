"""The usage outbox must live on persistent storage in the container image.

Pending events are billable usage that failed to reach Redis; a container's
writable layer (and /tmp) is discarded on every recreate.
"""
import asyncio
from pathlib import Path

from app.services.outbox import Outbox

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def test_image_points_the_outbox_at_its_state_directory():
    text = DOCKERFILE.read_text()
    assert "USAGE_OUTBOX_PATH=/var/lib/omnibioai-gateway/usage_outbox.db" in text
    assert "install -d -o omnibioai -g omnibioai -m 0700 /var/lib/omnibioai-gateway" in text
    # Created before dropping privileges, so the service user owns it.
    assert text.index("/var/lib/omnibioai-gateway") < text.index("USER omnibioai")


def test_pending_events_survive_a_new_process_on_the_same_path(tmp_path):
    path = str(tmp_path / "state" / "usage_outbox.db")
    (tmp_path / "state").mkdir()
    Outbox(path).write({"event_id": "evt-1", "units": 3})
    restarted = Outbox(path)
    assert restarted.pending_count() == 1
    flushed = []

    async def flush(event):
        flushed.append(event["event_id"])
        return True

    assert asyncio.run(restarted.drain(flush)) == 1
    assert flushed == ["evt-1"] and Outbox(path).pending_count() == 0

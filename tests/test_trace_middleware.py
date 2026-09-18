"""
Tests for TraceMiddleware (app/middleware/s2s.py).

Every response must carry X-Trace-Id.
An X-Trace-Id sent in the request must be echoed back unchanged.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""


def test_trace_id_present_in_response(client):
    """Every response carries an x-trace-id header."""
    resp = client.get("/health")
    assert "x-trace-id" in resp.headers


def test_trace_id_is_not_empty(client):
    """The x-trace-id header value is never blank/whitespace-only."""
    resp = client.get("/health")
    assert resp.headers["x-trace-id"].strip() != ""


def test_incoming_trace_id_propagated(client):
    """An X-Trace-Id supplied by the caller is echoed back unchanged."""
    resp = client.get("/health", headers={"X-Trace-Id": "test-trace-abc-123"})
    assert resp.headers.get("x-trace-id") == "test-trace-abc-123"


def test_missing_trace_id_auto_generated(client):
    """If client sends no X-Trace-Id the gateway generates a UUID."""
    import uuid

    resp = client.get("/health")
    tid = resp.headers.get("x-trace-id", "")
    uuid.UUID(tid)  # raises if not a valid UUID

"""/health and /version must both be reachable with no Authorization
header at all -- both routes are on every middleware's auth skip-list,
so they stay usable as liveness/version probes even when IAM is down.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""


def test_health_returns_ok(client):
    """/health responds 200 with {"status": "ok"}."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_no_auth_required(client):
    """/health succeeds with no Authorization header (middleware skip-list)."""
    # /health is in the middleware skip-list; no Authorization header needed.
    resp = client.get("/health")
    assert resp.status_code == 200


def test_version_returns_200(client):
    """/version responds 200 and reports this gateway's own service name."""
    resp = client.get("/version")
    assert resp.status_code == 200
    assert resp.json().get("service") == "omnibioai-api-gateway"


def test_version_no_auth_required(client):
    """/version succeeds with no Authorization header (middleware skip-list)."""
    # /version is in every middleware's skip-list (IAM Foundation gateway
    # integration, Step 5); no Authorization header needed.
    resp = client.get("/version")
    assert resp.status_code == 200

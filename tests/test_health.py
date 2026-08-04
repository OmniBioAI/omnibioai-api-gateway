def test_health_returns_ok(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_no_auth_required(client):
    # /health is in the middleware skip-list; no Authorization header needed.
    resp = client.get("/health")
    assert resp.status_code == 200


def test_version_returns_200(client):
    resp = client.get("/version")
    assert resp.status_code == 200
    assert resp.json().get("service") == "omnibioai-api-gateway"


def test_version_no_auth_required(client):
    # /version is in every middleware's skip-list (IAM Foundation gateway
    # integration, Step 5); no Authorization header needed.
    resp = client.get("/version")
    assert resp.status_code == 200

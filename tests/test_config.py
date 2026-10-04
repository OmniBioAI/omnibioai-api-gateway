"""
Tests for app/core/config.py.

Config reads settings from environment variables at class-definition time.
All required fields must exist and env-overrides must work.

Developer:
    Manish Kumar <manish@omnibioai.org>
"""
import importlib

from app.core.config import Config


def test_config_has_required_fields():
    """Config declares every URL/secret field the gateway depends on."""
    for attr in ("IAM_URL", "POLICY_URL", "HPC_URL", "REDIS_URL", "JWT_SECRET"):
        assert hasattr(Config, attr), f"Config missing {attr}"


def test_config_has_service_secret():
    """Config declares SERVICE_SECRET (service-to-service auth)."""
    assert hasattr(Config, "SERVICE_SECRET")


def test_config_has_route_timeout():
    """Config.ROUTE_TIMEOUT exists and is an int."""
    assert hasattr(Config, "ROUTE_TIMEOUT")
    assert isinstance(Config.ROUTE_TIMEOUT, int)


def test_config_reads_iam_url_from_env(monkeypatch):
    """Setting IAM_URL before the module is (re)loaded overrides the default."""
    monkeypatch.setenv("IAM_URL", "http://test-iam:9999")
    import app.core.config as cfg_module

    importlib.reload(cfg_module)
    assert cfg_module.Config.IAM_URL == "http://test-iam:9999"
    # Restore so other tests see the default
    monkeypatch.delenv("IAM_URL", raising=False)
    importlib.reload(cfg_module)


def test_v1_idempotency_ttl_is_capped_at_30_days_even_if_configured_higher(monkeypatch):
    """M18 (design audit gap #11): the idempotency-replay cache holds
    the real answer text/citations, so its TTL is the de facto
    enforcement of the 30-day deletion policy -- a misconfigured env
    var must not be able to silently violate that."""
    monkeypatch.setenv("V1_IDEMPOTENCY_TTL", str(60 * 24 * 60 * 60))  # 60 days
    import app.core.config as cfg_module

    importlib.reload(cfg_module)
    assert cfg_module.Config.V1_IDEMPOTENCY_TTL == 30 * 24 * 60 * 60
    monkeypatch.delenv("V1_IDEMPOTENCY_TTL", raising=False)
    importlib.reload(cfg_module)


def test_v1_idempotency_ttl_below_the_30_day_cap_is_unaffected(monkeypatch):
    monkeypatch.setenv("V1_IDEMPOTENCY_TTL", "60")
    import app.core.config as cfg_module

    importlib.reload(cfg_module)
    assert cfg_module.Config.V1_IDEMPOTENCY_TTL == 60
    monkeypatch.delenv("V1_IDEMPOTENCY_TTL", raising=False)
    importlib.reload(cfg_module)


def test_config_defaults_are_set():
    """IAM_URL/REDIS_URL/JWT_SECRET all have non-empty defaults, so the
    gateway can start with no environment variables configured."""
    # Default values are defined so the gateway can start without any env vars.
    assert Config.IAM_URL != ""
    assert Config.REDIS_URL != ""
    assert Config.JWT_SECRET != ""

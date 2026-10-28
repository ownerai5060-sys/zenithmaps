"""Pytest fixtures for the Zenith platform API."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure sdk/python is importable even when pytest.ini pythonpath is ignored.
_SDK = Path(__file__).resolve().parents[1] / "sdk" / "python"
if str(_SDK) not in sys.path:
    sys.path.insert(0, str(_SDK))

from api.catalog import reset_catalog_version  # noqa: E402
from api.config import get_settings  # noqa: E402
from api.consent import get_consent_store  # noqa: E402
from api.keystore import get_keystore  # noqa: E402
from api.main import create_app  # noqa: E402
from api.metrics import get_metrics  # noqa: E402
from api.oauth import get_token_store  # noqa: E402
from api.oidc import get_jwks_cache  # noqa: E402
from api.rate_limit import get_rate_limiter, reset_rate_limiter  # noqa: E402
from api.session_store import reset_session_store  # noqa: E402
from api.webhook_log import get_delivery_log  # noqa: E402
from api.webhook_retry import get_retry_queue  # noqa: E402
from api.webhooks import get_webhook_registry  # noqa: E402

DEMO_API_KEY = "zenith_demo_key_layers_read"
ADMIN_API_KEY = "zenith_admin_key_manage"


@pytest.fixture(autouse=True)
def _test_env(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> None:
    """Deterministic settings for unit tests (no live upstream probes)."""
    monkeypatch.setenv("ZENITH_HEALTH_CHECK_UPSTREAMS", "false")
    monkeypatch.setenv("ZENITH_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("ZENITH_RATE_LIMIT_REQUESTS", "1000")
    monkeypatch.setenv("ZENITH_RATE_LIMIT_WINDOW_S", "60")
    monkeypatch.setenv("ZENITH_RATE_LIMIT_BACKEND", "memory")
    monkeypatch.setenv("ZENITH_PROMETHEUS_ENABLED", "true")
    monkeypatch.setenv("ZENITH_OTEL_ENABLED", "false")
    monkeypatch.setenv("ZENITH_OAUTH_ENABLED", "true")
    monkeypatch.delenv("ZENITH_REDIS_URL", raising=False)
    monkeypatch.delenv("ZENITH_DATABASE_URL", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_JWKS_URL", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_ISSUER", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_CLIENT_ID", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_AUTHORIZE_URL", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_TOKEN_URL", raising=False)
    monkeypatch.delenv("ZENITH_OIDC_REDIRECT_URI", raising=False)
    # Ephemeral vault + webhook log + SSO session store.
    vault = tmp_path_factory.mktemp("vault") / "keys.sqlite"
    whlog = tmp_path_factory.mktemp("whlog") / "deliveries.sqlite"
    sess = tmp_path_factory.mktemp("sso") / "sessions.sqlite"
    monkeypatch.setenv("ZENITH_KEY_VAULT_PATH", str(vault))
    monkeypatch.setenv("ZENITH_WEBHOOK_LOG_PATH", str(whlog))
    monkeypatch.setenv("ZENITH_WEBHOOK_SIGNING_SECRET", "test-webhook-secret")
    monkeypatch.setenv("ZENITH_SESSION_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("ZENITH_SESSION_STORE_PATH", str(sess))
    monkeypatch.setenv("ZENITH_OAUTH_CONSENT_ENABLED", "true")
    get_settings.cache_clear()
    reset_rate_limiter()
    get_rate_limiter().reset()
    get_metrics().reset()
    get_token_store().reset()
    get_jwks_cache().reset()
    get_consent_store().reset()
    reset_session_store()
    get_keystore().reset_and_seed()
    get_delivery_log().configure(str(whlog))
    get_webhook_registry().configure(str(whlog))
    get_retry_queue().configure(str(whlog))
    get_webhook_registry().reset()
    get_retry_queue().reset()
    get_delivery_log().reset()
    reset_catalog_version(1)
    yield
    get_settings.cache_clear()
    reset_rate_limiter()
    get_rate_limiter().reset()
    get_metrics().reset()
    get_token_store().reset()
    get_jwks_cache().reset()
    get_consent_store().reset()
    reset_session_store()
    get_keystore().reset_and_seed()
    get_webhook_registry().reset()
    get_retry_queue().reset()
    get_delivery_log().reset()
    reset_catalog_version(1)


@pytest.fixture()
def client() -> TestClient:
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


@pytest.fixture()
def auth_headers() -> dict[str, str]:
    return {"X-API-Key": DEMO_API_KEY}


@pytest.fixture()
def admin_headers() -> dict[str, str]:
    return {"X-API-Key": ADMIN_API_KEY}


@pytest.fixture()
def low_rate_limit_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Client with a tiny rate limit for S3 tests."""
    monkeypatch.setenv("ZENITH_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("ZENITH_RATE_LIMIT_REQUESTS", "3")
    monkeypatch.setenv("ZENITH_RATE_LIMIT_WINDOW_S", "60")
    monkeypatch.setenv("ZENITH_RATE_LIMIT_BACKEND", "memory")
    get_settings.cache_clear()
    reset_rate_limiter()
    get_rate_limiter().reset()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()
    reset_rate_limiter()
    get_rate_limiter().reset()

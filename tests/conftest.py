"""Pytest fixtures for the Zenith platform API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.keystore import get_keystore
from api.main import create_app
from api.metrics import get_metrics
from api.oauth import get_token_store
from api.rate_limit import get_rate_limiter, reset_rate_limiter

DEMO_API_KEY = "zenith_demo_key_layers_read"
ADMIN_API_KEY = "zenith_admin_key_manage"


@pytest.fixture(autouse=True)
def _test_env(monkeypatch: pytest.MonkeyPatch) -> None:
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
    get_settings.cache_clear()
    reset_rate_limiter()
    get_rate_limiter().reset()
    get_metrics().reset()
    get_token_store().reset()
    get_keystore().reset_and_seed()
    yield
    get_settings.cache_clear()
    reset_rate_limiter()
    get_rate_limiter().reset()
    get_metrics().reset()
    get_token_store().reset()
    get_keystore().reset_and_seed()


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

"""Runtime configuration for the Zenith platform API.

Secrets and allowlists are loaded from environment variables so local demos
and staging can differ without code changes. Demo API keys below are stubs
suitable for development only — never use them in production.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import FrozenSet, Literal


@dataclass(frozen=True)
class ApiKeyRecord:
    """One issued API key and its granted scopes."""

    key_id: str
    secret: str
    scopes: FrozenSet[str]
    label: str = ""


RateLimitBackendName = Literal["memory", "redis", "auto"]


@dataclass(frozen=True)
class Settings:
    """Application settings (auth, allowlist, CORS, rate limit, observability)."""

    app_name: str = "Zenith Maps Platform API"
    api_version: str = "v1"
    # Comma-separated browser origins allowed to call the API (M7).
    cors_origins: tuple[str, ...] = (
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8501",
        "http://127.0.0.1:8501",
    )
    # Hostnames (lowercase, no port) that may appear in WMS/tile URLs (M6).
    wms_allowed_hosts: FrozenSet[str] = frozenset(
        {
            "services.terrascope.be",
        }
    )
    # Optional layer-name allowlist per host. Empty set = any layer on that host.
    wms_allowed_layers: FrozenSet[str] = frozenset(
        {
            "WORLDCOVER_2020_MAP",
            "WORLDCOVER_2021_MAP",
        }
    )
    api_keys: tuple[ApiKeyRecord, ...] = field(default_factory=tuple)
    # When True, reject any outbound/proxy pattern that is not allowlisted.
    enforce_wms_allowlist: bool = True
    # Per-API-key fixed-window rate limit (S3 + distributed backend).
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 120
    rate_limit_window_s: int = 60
    rate_limit_backend: RateLimitBackendName = "auto"
    redis_url: str = ""
    # Health upstream probes (S2). Set false in unit tests / offline CI.
    health_check_upstreams: bool = True
    # Public base URL used in docs / legend graphic absolute links (optional).
    public_base_url: str = "http://127.0.0.1:8000"
    # OAuth2 client-credentials stub.
    oauth_enabled: bool = True
    oauth_token_ttl_s: int = 3600
    # Observability (env-driven).
    prometheus_enabled: bool = True
    otel_enabled: bool = False
    otel_service_name: str = "zenith-api"
    otel_exporter_otlp_endpoint: str = ""


def _parse_csv(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None or value.strip() == "":
        return default
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _default_demo_keys() -> tuple[ApiKeyRecord, ...]:
    """Workable stub keys for local/external-app demos (M3).

    Override with ZENITH_API_KEYS JSON for real deployments:
    [{"key_id":"demo","secret":"...","scopes":["layers:read"],"label":"Demo"}]
    """
    return (
        ApiKeyRecord(
            key_id="demo",
            secret="zenith_demo_key_layers_read",
            scopes=frozenset({"layers:read"}),
            label="Demo third-party app (layers:read)",
        ),
        ApiKeyRecord(
            key_id="readonly",
            secret="zenith_readonly_key",
            scopes=frozenset({"layers:read"}),
            label="Read-only integration key",
        ),
        ApiKeyRecord(
            key_id="admin",
            secret="zenith_admin_key_manage",
            scopes=frozenset({"layers:read", "admin:keys"}),
            label="Admin key management (local/sandbox only)",
        ),
    )


def _load_api_keys_from_env() -> tuple[ApiKeyRecord, ...] | None:
    raw = os.getenv("ZENITH_API_KEYS")
    if not raw:
        return None
    data = json.loads(raw)
    records: list[ApiKeyRecord] = []
    for item in data:
        records.append(
            ApiKeyRecord(
                key_id=str(item["key_id"]),
                secret=str(item["secret"]),
                scopes=frozenset(item.get("scopes", ["layers:read"])),
                label=str(item.get("label", "")),
            )
        )
    return tuple(records)


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() not in {"0", "false", "no"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings built from env + safe defaults."""
    keys = _load_api_keys_from_env() or _default_demo_keys()
    cors = _parse_csv(
        os.getenv("ZENITH_CORS_ORIGINS"),
        (
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:8501",
            "http://127.0.0.1:8501",
        ),
    )
    hosts = _parse_csv(
        os.getenv("ZENITH_WMS_ALLOWED_HOSTS"),
        ("services.terrascope.be",),
    )
    layers = _parse_csv(
        os.getenv("ZENITH_WMS_ALLOWED_LAYERS"),
        ("WORLDCOVER_2020_MAP", "WORLDCOVER_2021_MAP"),
    )
    backend_raw = (os.getenv("ZENITH_RATE_LIMIT_BACKEND") or "auto").strip().lower()
    if backend_raw not in {"memory", "redis", "auto"}:
        backend_raw = "auto"

    return Settings(
        cors_origins=cors,
        wms_allowed_hosts=frozenset(h.lower() for h in hosts),
        wms_allowed_layers=frozenset(layers),
        api_keys=keys,
        enforce_wms_allowlist=_bool("ZENITH_ENFORCE_WMS_ALLOWLIST", True),
        rate_limit_enabled=_bool("ZENITH_RATE_LIMIT_ENABLED", True),
        rate_limit_requests=_int("ZENITH_RATE_LIMIT_REQUESTS", 120),
        rate_limit_window_s=_int("ZENITH_RATE_LIMIT_WINDOW_S", 60),
        rate_limit_backend=backend_raw,  # type: ignore[arg-type]
        redis_url=os.getenv("ZENITH_REDIS_URL", "").strip(),
        health_check_upstreams=_bool("ZENITH_HEALTH_CHECK_UPSTREAMS", True),
        public_base_url=os.getenv("ZENITH_PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip(
            "/"
        ),
        oauth_enabled=_bool("ZENITH_OAUTH_ENABLED", True),
        oauth_token_ttl_s=_int("ZENITH_OAUTH_TOKEN_TTL_S", 3600),
        prometheus_enabled=_bool("ZENITH_PROMETHEUS_ENABLED", True),
        otel_enabled=_bool("ZENITH_OTEL_ENABLED", False),
        otel_service_name=os.getenv("ZENITH_OTEL_SERVICE_NAME", "zenith-api").strip()
        or "zenith-api",
        otel_exporter_otlp_endpoint=os.getenv(
            "ZENITH_OTEL_EXPORTER_OTLP_ENDPOINT", ""
        ).strip(),
    )

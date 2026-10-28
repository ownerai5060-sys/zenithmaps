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
SessionStoreBackendName = Literal["memory", "sqlite", "redis", "auto"]


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
    # Hostnames (lowercase, no port) that may appear in WMS/tile URLs (M6/N4).
    # Includes catalog XYZ hosts already referenced by curated layers — not
    # an open CDN invent list.
    wms_allowed_hosts: FrozenSet[str] = frozenset(
        {
            "services.terrascope.be",
            "a.tile.opentopomap.org",
            "b.tile.opentopomap.org",
            "c.tile.opentopomap.org",
        }
    )
    # When True, non-local webhook callback URLs must use https (N3).
    webhooks_require_https: bool = True
    # Optional egress host allowlist for webhook callbacks. Empty = any public
    # https host (still blocks private/metadata). Production should set this.
    webhook_allowed_hosts: FrozenSet[str] = frozenset()
    # Optional CDN base URL allowlist (policy stub — Zenith does not host CDN).
    # Comma-separated absolute https bases, e.g. https://tiles.example.com
    tile_cdn_base_urls: tuple[str, ...] = ()
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
    # Durable key vault (SQLite path). Empty = in-process memory only.
    key_vault_path: str = ""
    # WFS-lite: optional PostGIS DSN; empty → fixtures / stubs.
    database_url: str = ""
    features_table: str = "zenith_features"
    # OIDC / JWT via JWKS (optional alongside opaque OAuth stub tokens).
    oidc_jwks_url: str = ""
    oidc_audience: str = ""
    oidc_issuer: str = ""
    oidc_default_scopes: str = "layers:read"
    # OIDC confidential-client / auth-code + refresh (external IdP or local stub).
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_authorize_url: str = ""
    oidc_token_url: str = ""
    oidc_redirect_uri: str = "http://127.0.0.1:8000/oauth/callback"
    oidc_scopes: str = "openid layers:read"
    oauth_refresh_ttl_s: int = 86400
    # When True, /oauth/authorize requires PKCE S256 (code_challenge).
    # When False, PKCE is still enforced whenever a challenge was supplied.
    oidc_pkce_required: bool = False
    # HttpOnly cookie used by the static key portal after OIDC / stub login.
    # Cookie value is an opaque SSO session_id (looked up in session store).
    portal_cookie_name: str = "zenith_portal_token"
    portal_pkce_cookie_name: str = "zenith_pkce_verifier"
    # Non-HttpOnly double-submit CSRF cookie (readable by portal JS).
    portal_csrf_cookie_name: str = "zenith_portal_csrf"
    # auto | true | false — Secure flag for portal session/CSRF/PKCE cookies.
    portal_cookie_secure: str = "auto"
    # Optional Domain attribute for portal cookies (e.g. ".example.com") so
    # Streamlit + API on sibling hosts can share the SSO session cookie.
    # Empty = host-only (default; safest for local demos).
    portal_cookie_domain: str = ""
    # Enforce CSRF double-submit for portal-cookie mutating requests.
    portal_csrf_enabled: bool = True
    # Shared SSO session + IdP refresh store (cluster-friendly).
    session_store_backend: SessionStoreBackendName = "auto"
    # SQLite/file path when backend is sqlite or auto (fallback).
    session_store_path: str = ""
    # Local-stub auth-code with redirect_uri shows a consent HTML form first.
    oauth_consent_enabled: bool = True
    # Optional in-process rotation ticker (prefer cron CLI in multi-replica).
    rotation_scheduler_enabled: bool = False
    rotation_scheduler_interval_s: float = 3600.0
    # Webhook durability + HMAC signing stub.
    # Same SQLite path holds subscriptions, delivery log, and retry queue.
    webhook_log_path: str = ""
    webhook_signing_secret: str = ""
    # Retry worker (exponential backoff for failed deliveries).
    webhook_retry_enabled: bool = True
    webhook_retry_max_attempts: int = 5
    webhook_retry_base_delay_s: float = 2.0
    webhook_retry_max_delay_s: float = 300.0


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
            key_id="operator",
            secret="zenith_operator_key_read",
            scopes=frozenset({"layers:read", "keys:read"}),
            label="Portal operator (list keys only; local/sandbox)",
        ),
        ApiKeyRecord(
            key_id="admin",
            secret="zenith_admin_key_manage",
            scopes=frozenset({"layers:read", "keys:read", "admin:keys"}),
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


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return float(raw)


def _session_backend(raw: str | None) -> SessionStoreBackendName:
    value = (raw or "auto").strip().lower()
    if value not in {"memory", "sqlite", "redis", "auto"}:
        return "auto"
    return value  # type: ignore[return-value]


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
        (
            "services.terrascope.be",
            "a.tile.opentopomap.org",
            "b.tile.opentopomap.org",
            "c.tile.opentopomap.org",
        ),
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
        webhooks_require_https=_bool("ZENITH_WEBHOOKS_REQUIRE_HTTPS", True),
        webhook_allowed_hosts=frozenset(
            h.lower()
            for h in _parse_csv(os.getenv("ZENITH_WEBHOOK_ALLOWED_HOSTS"), ())
        ),
        tile_cdn_base_urls=_parse_csv(
            os.getenv("ZENITH_TILE_CDN_BASE_URLS"), ()
        ),
        key_vault_path=os.getenv("ZENITH_KEY_VAULT_PATH", "").strip(),
        database_url=os.getenv("ZENITH_DATABASE_URL", "").strip(),
        features_table=(
            os.getenv("ZENITH_FEATURES_TABLE", "zenith_features").strip()
            or "zenith_features"
        ),
        oidc_jwks_url=os.getenv("ZENITH_OIDC_JWKS_URL", "").strip(),
        oidc_audience=os.getenv("ZENITH_OIDC_AUDIENCE", "").strip(),
        oidc_issuer=os.getenv("ZENITH_OIDC_ISSUER", "").strip(),
        oidc_default_scopes=(
            os.getenv("ZENITH_OIDC_DEFAULT_SCOPES", "layers:read").strip()
            or "layers:read"
        ),
        oidc_client_id=os.getenv("ZENITH_OIDC_CLIENT_ID", "").strip(),
        oidc_client_secret=os.getenv("ZENITH_OIDC_CLIENT_SECRET", "").strip(),
        oidc_authorize_url=os.getenv("ZENITH_OIDC_AUTHORIZE_URL", "").strip(),
        oidc_token_url=os.getenv("ZENITH_OIDC_TOKEN_URL", "").strip(),
        oidc_redirect_uri=(
            os.getenv(
                "ZENITH_OIDC_REDIRECT_URI", "http://127.0.0.1:8000/oauth/callback"
            ).strip()
            or "http://127.0.0.1:8000/oauth/callback"
        ),
        oidc_scopes=(
            os.getenv("ZENITH_OIDC_SCOPES", "openid layers:read").strip()
            or "openid layers:read"
        ),
        oauth_refresh_ttl_s=_int("ZENITH_OAUTH_REFRESH_TTL_S", 86400),
        oidc_pkce_required=_bool("ZENITH_OIDC_PKCE_REQUIRED", False),
        portal_cookie_name=(
            os.getenv("ZENITH_PORTAL_COOKIE_NAME", "zenith_portal_token").strip()
            or "zenith_portal_token"
        ),
        portal_pkce_cookie_name=(
            os.getenv(
                "ZENITH_PORTAL_PKCE_COOKIE_NAME", "zenith_pkce_verifier"
            ).strip()
            or "zenith_pkce_verifier"
        ),
        portal_csrf_cookie_name=(
            os.getenv(
                "ZENITH_PORTAL_CSRF_COOKIE_NAME", "zenith_portal_csrf"
            ).strip()
            or "zenith_portal_csrf"
        ),
        portal_cookie_secure=(
            os.getenv("ZENITH_PORTAL_COOKIE_SECURE", "auto").strip().lower()
            or "auto"
        ),
        portal_cookie_domain=os.getenv("ZENITH_PORTAL_COOKIE_DOMAIN", "").strip(),
        portal_csrf_enabled=_bool("ZENITH_PORTAL_CSRF_ENABLED", True),
        session_store_backend=_session_backend(
            os.getenv("ZENITH_SESSION_STORE_BACKEND", "auto")
        ),
        session_store_path=os.getenv("ZENITH_SESSION_STORE_PATH", "").strip(),
        oauth_consent_enabled=_bool("ZENITH_OAUTH_CONSENT_ENABLED", True),
        rotation_scheduler_enabled=_bool("ZENITH_ROTATION_SCHEDULER_ENABLED", False),
        rotation_scheduler_interval_s=_float(
            "ZENITH_ROTATION_SCHEDULER_INTERVAL_S", 3600.0
        ),
        webhook_log_path=os.getenv("ZENITH_WEBHOOK_LOG_PATH", "").strip(),
        webhook_signing_secret=os.getenv("ZENITH_WEBHOOK_SIGNING_SECRET", "").strip(),
        webhook_retry_enabled=_bool("ZENITH_WEBHOOK_RETRY_ENABLED", True),
        webhook_retry_max_attempts=_int("ZENITH_WEBHOOK_RETRY_MAX_ATTEMPTS", 5),
        webhook_retry_base_delay_s=_float("ZENITH_WEBHOOK_RETRY_BASE_DELAY_S", 2.0),
        webhook_retry_max_delay_s=_float("ZENITH_WEBHOOK_RETRY_MAX_DELAY_S", 300.0),
    )

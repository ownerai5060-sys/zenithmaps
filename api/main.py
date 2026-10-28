"""Zenith Maps Platform API entrypoint (M1–O3 + K1–K2 + PKCE / portal RBAC).

Architecture decision (M1)
--------------------------
This repository remains the **UI demo** (Streamlit + leafmap under ``Home.py``
and ``pages/``). The durable integration surface for external apps lives in
this FastAPI package (``api/``) and is versioned under ``/api/v1``.

Run locally::

    uvicorn api.main:app --reload --port 8000

Interactive OpenAPI docs: http://127.0.0.1:8000/docs
Key portal (static): http://127.0.0.1:8000/admin/key-portal
Portal SSO (PKCE): http://127.0.0.1:8000/oauth/portal/login
"""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from api import __version__
from api.config import get_settings
from api.errors import (
    REQUEST_ID_HEADER,
    ApiError,
    api_error_handler,
    get_request_id,
    http_exception_handler,
    new_request_id,
    unhandled_exception_handler,
    validation_exception_handler,
)
from api.catalog import reset_catalog_version
from api.keystore import get_keystore
from api.metrics import get_metrics
from api.consent import get_consent_store
from api.oauth import get_token_store
from api.oidc import get_jwks_cache
from api.otel import setup_otel
from api.rate_limit import RateLimitHeaderMiddleware, reset_rate_limiter
from api.routers import (
    admin_keys,
    features,
    health,
    layers,
    oauth,
    security,
    tiles,
    webhooks,
)
from api.session_store import configure_session_store, get_session_store
from api.webhook_log import get_delivery_log
from api.webhook_retry import get_retry_queue
from api.webhooks import get_webhook_registry


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request_id to every request/response (M5)."""

    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get(REQUEST_ID_HEADER)
        request_id = incoming.strip() if incoming else new_request_id()
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    """Record per-request latency and error counts (S2 + Prometheus)."""

    async def dispatch(self, request: Request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        latency_ms = (time.perf_counter() - started) * 1000
        is_error = response.status_code >= 500
        get_metrics().record(
            latency_ms=latency_ms,
            is_error=is_error,
            path=request.url.path,
        )
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Eagerly load settings so misconfigured env fails at startup.
    settings = get_settings()
    get_metrics().reset()
    get_keystore().reset_and_seed(settings.api_keys)
    get_token_store().reset()
    get_jwks_cache().reset()
    get_consent_store().reset()
    # Shared SSO session + IdP refresh (Redis / SQLite / memory).
    configure_session_store(settings)
    get_session_store().reset()
    # Shared SQLite: subscriptions + delivery log + retry queue.
    get_delivery_log().configure(settings.webhook_log_path)
    get_webhook_registry().configure(settings.webhook_log_path)
    get_retry_queue().configure(settings.webhook_log_path)
    reset_catalog_version(1)
    reset_rate_limiter(settings)
    setup_otel(app, settings)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Stable HTTP API for Zenith Maps catalog, layer metadata, structured "
            "legends, allowlisted GetLegendGraphic, WFS-lite GeoJSON features "
            "(fixtures / optional PostGIS), allowlisted catalog tile URL "
            "discovery, durable API-key vault, key portal UI with light RBAC "
            "(keys:read vs admin:keys) + PKCE S256 portal SSO (shared session "
            "store: Redis/SQLite/memory; IdP refresh persisted server-side), "
            "local consent stub, catalog webhooks with durable subscription "
            "registry + delivery/retry log + HMAC stub, OAuth2 "
            "client_credentials + authorization_code/refresh with PKCE S256 "
            "(IdP proxy when configured), key rotation, and optional OIDC JWT "
            "(JWKS) Bearer validation. GraphQL is deferred. Streamlit pages in "
            "this repo are a UI demo; external apps should integrate against "
            "`/api/v1`."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Request-ID",
            "X-CSRF-Token",
        ],
        expose_headers=[
            REQUEST_ID_HEADER,
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
            "X-RateLimit-Backend",
            "Retry-After",
        ],
    )
    # Starlette applies middleware in reverse add order for requests.
    application.add_middleware(RateLimitHeaderMiddleware)
    application.add_middleware(MetricsMiddleware)
    application.add_middleware(RequestIdMiddleware)

    application.add_exception_handler(ApiError, api_error_handler)
    application.add_exception_handler(StarletteHTTPException, http_exception_handler)
    application.add_exception_handler(
        RequestValidationError, validation_exception_handler
    )
    application.add_exception_handler(Exception, unhandled_exception_handler)

    application.include_router(health.router)
    application.include_router(oauth.router)
    application.include_router(layers.router, prefix="/api/v1")
    application.include_router(features.router, prefix="/api/v1")
    application.include_router(tiles.router, prefix="/api/v1")
    application.include_router(security.router, prefix="/api/v1")
    application.include_router(admin_keys.router, prefix="/api/v1")
    application.include_router(webhooks.router, prefix="/api/v1")

    static_root = Path(__file__).resolve().parent.parent / "static"
    if static_root.is_dir():
        application.mount(
            "/static",
            StaticFiles(directory=str(static_root)),
            name="static",
        )

    @application.get("/admin/key-portal", include_in_schema=True, tags=["admin"])
    async def key_portal_redirect() -> RedirectResponse:
        """Convenience alias for the static API-key portal UI."""
        return RedirectResponse(url="/static/admin/key_portal.html", status_code=307)

    @application.get("/api/v1", include_in_schema=True, tags=["meta"])
    async def api_v1_root(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "name": settings.app_name,
                "version": settings.api_version,
                "package_version": __version__,
                "docs": "/docs",
                "graphql": "deferred",
                "key_portal": "/admin/key-portal",
                "endpoints": {
                    "layers": "/api/v1/layers",
                    "layer_detail": "/api/v1/layers/{layer_id}",
                    "legend": "/api/v1/layers/{layer_id}/legend",
                    "legend_image": "/api/v1/layers/{layer_id}/legend/image",
                    "features": "/api/v1/layers/{layer_id}/features",
                    "tiles": "/api/v1/tiles",
                    "tile_detail": "/api/v1/tiles/{layer_id}",
                    "check_url": "/api/v1/security/check-url",
                    "allowlist": "/api/v1/security/allowlist",
                    "admin_keys": "/api/v1/admin/keys",
                    "admin_key_rotate": "/api/v1/admin/keys/{key_id}/rotate",
                    "admin_webhooks": "/api/v1/admin/webhooks",
                    "admin_webhook_deliveries": "/api/v1/admin/webhooks/deliveries",
                    "admin_catalog": "/api/v1/admin/catalog",
                    "oauth_token": "/oauth/token",
                    "oauth_authorize": "/oauth/authorize",
                    "oauth_callback": "/oauth/callback",
                    "oauth_consent": "/oauth/consent",
                    "oauth_oidc_config": "/oauth/oidc-config",
                    "oauth_portal_login": "/oauth/portal/login",
                    "oauth_portal_session": "/oauth/portal/session",
                    "key_portal": "/admin/key-portal",
                    "healthz": "/healthz",
                    "metrics": "/metrics",
                    "metrics_prometheus": "/metrics/prometheus",
                },
                "auth": {
                    "api_key": "X-API-Key",
                    "oauth_opaque": "/oauth/token",
                    "oauth_grants": [
                        "client_credentials",
                        "authorization_code",
                        "refresh_token",
                    ],
                    "pkce": "S256",
                    "portal_cookie": settings.portal_cookie_name,
                    "portal_cookie_value": "opaque_session_id",
                    "portal_csrf_cookie": settings.portal_csrf_cookie_name,
                    "portal_csrf_header": "X-CSRF-Token",
                    "session_store": get_session_store().backend_name,
                    "idp_refresh_persistence": True,
                    "local_consent": settings.oauth_consent_enabled,
                    "rbac": {
                        "operator_list": "keys:read",
                        "admin_manage": "admin:keys",
                    },
                    "oidc_jwt": bool(settings.oidc_jwks_url),
                    "oidc_auth_code": bool(settings.oidc_token_url),
                },
                "features_mode": "wfs_lite",
                "tile_cdn": {
                    "zenith_hosts_tiles": False,
                    "allowlisted_base_urls": list(settings.tile_cdn_base_urls),
                },
                "webhook_egress_allowlist": sorted(settings.webhook_allowed_hosts),
                "key_vault_durable": bool(settings.key_vault_path),
                "webhook_log_durable": bool(settings.webhook_log_path),
                "webhook_registry_durable": bool(settings.webhook_log_path),
                "webhook_retry_enabled": bool(settings.webhook_retry_enabled),
                "session_store_durable": get_session_store().backend_name
                in {"sqlite", "redis"},
                "readiness": "staging-ready",
                "request_id": get_request_id(request),
            },
            headers={REQUEST_ID_HEADER: get_request_id(request)},
        )

    return application


app = create_app()

"""Acceptance tests for M2–N6 + WFS-lite / vault / OIDC / webhook ops."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.webhook_log import get_delivery_log
from api.webhook_retry import get_retry_queue


def test_healthz(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in {"ok", "degraded"}
    assert body["api_version"] == "v1"
    assert "upstreams" in body
    assert "metrics" in body
    assert "X-Request-ID" in response.headers


def test_metrics_endpoint(client: TestClient) -> None:
    client.get("/healthz")
    response = client.get("/metrics")
    assert response.status_code == 200
    body = response.json()
    assert body["api_version"] == "v1"
    assert body["metrics"]["request_count"] >= 1


def test_openapi_and_docs(client: TestClient) -> None:
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    schema = openapi.json()
    assert schema["openapi"].startswith("3.")
    assert "/api/v1/layers" in schema["paths"]
    assert "/api/v1/layers/{layer_id}/legend/image" in schema["paths"]
    assert "/metrics" in schema["paths"]

    docs = client.get("/docs")
    assert docs.status_code == 200


def test_openapi_contract_required_paths(client: TestClient) -> None:
    """Minimal OpenAPI contract: stable paths and security scheme (S5)."""
    schema = client.get("/openapi.json").json()
    required_paths = {
        "/healthz",
        "/metrics",
        "/metrics/prometheus",
        "/oauth/token",
        "/oauth/authorize",
        "/oauth/callback",
        "/oauth/oidc-config",
        "/oauth/portal/login",
        "/oauth/portal/callback",
        "/oauth/portal/logout",
        "/oauth/portal/session",
        "/admin/key-portal",
        "/api/v1/layers",
        "/api/v1/layers/{layer_id}",
        "/api/v1/layers/{layer_id}/legend",
        "/api/v1/layers/{layer_id}/legend/image",
        "/api/v1/layers/{layer_id}/features",
        "/api/v1/tiles",
        "/api/v1/tiles/{layer_id}",
        "/api/v1/security/check-url",
        "/api/v1/security/allowlist",
        "/api/v1/admin/keys",
        "/api/v1/admin/keys/{key_id}",
        "/api/v1/admin/keys/{key_id}/rotate",
        "/api/v1/admin/webhooks",
        "/api/v1/admin/webhooks/deliveries",
        "/api/v1/admin/catalog",
        "/api/v1/admin/catalog/bump",
    }
    assert required_paths <= set(schema["paths"])
    # Layers list declares API key security via dependency; schema must list the path.
    layers_get = schema["paths"]["/api/v1/layers"]["get"]
    assert "layers" in layers_get.get("tags", [])


def test_layers_requires_api_key(client: TestClient) -> None:
    response = client.get("/api/v1/layers")
    assert response.status_code == 401
    body = response.json()
    assert body["code"] == "unauthorized"
    assert "request_id" in body
    assert "message" in body


def test_layers_rejects_invalid_key(client: TestClient) -> None:
    response = client.get(
        "/api/v1/layers", headers={"X-API-Key": "definitely-not-a-real-key"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "unauthorized"


def test_list_layers(client: TestClient, auth_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/layers", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 2
    ids = {item["id"] for item in body["items"]}
    assert "esa-worldcover-2020" in ids
    assert "X-RateLimit-Limit" in response.headers


def test_layer_detail_and_legend(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    detail = client.get("/api/v1/layers/esa-worldcover-2020", headers=auth_headers)
    assert detail.status_code == 200
    data = detail.json()
    assert data["kind"] == "wms"
    assert data["wms"]["layer_name"] == "WORLDCOVER_2020_MAP"
    assert data["legend_available"] is True

    legend = client.get(
        "/api/v1/layers/esa-worldcover-2020/legend", headers=auth_headers
    )
    assert legend.status_code == 200
    legend_body = legend.json()
    assert legend_body["layer_id"] == "esa-worldcover-2020"
    assert len(legend_body["entries"]) >= 5
    assert {"label", "color"} <= set(legend_body["entries"][0].keys())
    # S1 richer legend fields
    assert legend_body["get_legend_graphic_url"]
    assert "GetLegendGraphic" in legend_body["get_legend_graphic_url"]
    assert legend_body["legend_image_path"] == (
        "/api/v1/layers/esa-worldcover-2020/legend/image"
    )


def test_legend_image_proxy(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.content = fake_png
    mock_response.headers = {"content-type": "image/png"}

    with patch("api.legend_graphic.httpx.Client") as client_cls:
        client_cls.return_value.__enter__.return_value.get.return_value = mock_response
        response = client.get(
            "/api/v1/layers/esa-worldcover-2020/legend/image",
            headers=auth_headers,
        )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/png")
    assert response.content.startswith(b"\x89PNG")


def test_legend_image_not_for_xyz(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.get(
        "/api/v1/layers/opentopomap/legend/image", headers=auth_headers
    )
    assert response.status_code == 404
    assert response.json()["code"] == "legend_graphic_not_available"


def test_layer_not_found_error_envelope(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.get("/api/v1/layers/does-not-exist", headers=auth_headers)
    assert response.status_code == 404
    body = response.json()
    assert body["code"] == "not_found"
    assert body["request_id"]
    assert "message" in body


def test_legend_not_available(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.get("/api/v1/layers/opentopomap/legend", headers=auth_headers)
    assert response.status_code == 404
    assert response.json()["code"] == "legend_not_available"


def test_wms_allowlist_blocks_arbitrary_url(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/security/check-url",
        headers=auth_headers,
        json={"url": "https://evil.example/wms", "layer_name": "WORLDCOVER_2020_MAP"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is False
    assert body["reason"] == "host_not_allowlisted"


def test_wms_allowlist_accepts_terrascope(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/security/check-url",
        headers=auth_headers,
        json={
            "url": "https://services.terrascope.be/wms/v2",
            "layer_name": "WORLDCOVER_2020_MAP",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowed"] is True
    assert body["host"] == "services.terrascope.be"


def test_wms_allowlist_blocks_ssrf_schemes(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/security/check-url",
        headers=auth_headers,
        json={"url": "file:///etc/passwd"},
    )
    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_wms_allowlist_blocks_localhost(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    response = client.post(
        "/api/v1/security/check-url",
        headers=auth_headers,
        json={"url": "http://127.0.0.1/admin"},
    )
    assert response.status_code == 200
    assert response.json()["allowed"] is False


def test_cors_allowlist_reflects_configured_origin(client: TestClient) -> None:
    response = client.options(
        "/api/v1/layers",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "X-API-Key",
        },
    )
    assert response.status_code in {200, 204}
    assert (
        response.headers.get("access-control-allow-origin") == "http://localhost:3000"
    )


def test_cors_blocks_unknown_origin(client: TestClient) -> None:
    response = client.get(
        "/healthz",
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 200
    # Starlette CORSMiddleware omits ACAO for disallowed origins.
    assert response.headers.get("access-control-allow-origin") != "https://evil.example"


def test_request_id_echo(client: TestClient) -> None:
    custom = "test-request-id-123"
    response = client.get("/healthz", headers={"X-Request-ID": custom})
    assert response.headers.get("X-Request-ID") == custom


def test_rate_limit_per_api_key(
    low_rate_limit_client: TestClient, auth_headers: dict[str, str]
) -> None:
    """S3: after N requests, further calls return 429 with Retry-After."""
    client = low_rate_limit_client
    for _ in range(3):
        ok = client.get("/api/v1/layers", headers=auth_headers)
        assert ok.status_code == 200
    limited = client.get("/api/v1/layers", headers=auth_headers)
    assert limited.status_code == 429
    body = limited.json()
    assert body["code"] == "rate_limited"
    assert "Retry-After" in limited.headers
    assert "X-RateLimit-Limit" in limited.headers
    assert limited.headers.get("X-RateLimit-Backend") == "memory"


def test_admin_keys_create_list_revoke(
    client: TestClient, admin_headers: dict[str, str], auth_headers: dict[str, str]
) -> None:
    """Admin key management requires admin:keys; secret shown once."""
    denied = client.get("/api/v1/admin/keys", headers=auth_headers)
    assert denied.status_code == 403

    created = client.post(
        "/api/v1/admin/keys",
        headers=admin_headers,
        json={
            "key_id": "partner-a",
            "scopes": ["layers:read"],
            "label": "Partner A sandbox",
        },
    )
    assert created.status_code == 201
    body = created.json()
    assert body["key_id"] == "partner-a"
    assert body["secret"].startswith("zenith_")
    secret = body["secret"]

    listed = client.get("/api/v1/admin/keys", headers=admin_headers)
    assert listed.status_code == 200
    ids = {item["key_id"] for item in listed.json()["items"]}
    assert "partner-a" in ids
    assert all("secret" not in item for item in listed.json()["items"])

    # New key can call catalog.
    ok = client.get("/api/v1/layers", headers={"X-API-Key": secret})
    assert ok.status_code == 200

    revoked = client.delete("/api/v1/admin/keys/partner-a", headers=admin_headers)
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True

    blocked = client.get("/api/v1/layers", headers={"X-API-Key": secret})
    assert blocked.status_code == 401


def test_oauth_client_credentials_and_bearer(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    token_resp = client.post(
        "/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": "demo",
            "client_secret": "zenith_demo_key_layers_read",
        },
    )
    assert token_resp.status_code == 200
    token_body = token_resp.json()
    assert token_body["token_type"] == "Bearer"
    assert token_body["access_token"]
    assert "layers:read" in token_body["scope"]

    layers = client.get(
        "/api/v1/layers",
        headers={"Authorization": f"Bearer {token_body['access_token']}"},
    )
    assert layers.status_code == 200

    bad = client.post(
        "/oauth/token",
        json={
            "grant_type": "password",
            "client_id": "demo",
            "client_secret": "zenith_demo_key_layers_read",
        },
    )
    assert bad.status_code == 400
    assert bad.json()["code"] == "unsupported_grant_type"

    # API key path still works alongside OAuth.
    assert client.get("/api/v1/layers", headers=auth_headers).status_code == 200


def test_prometheus_metrics_endpoint(client: TestClient) -> None:
    client.get("/healthz")
    response = client.get("/metrics/prometheus")
    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    text = response.text
    assert "zenith_http_requests_total" in text or "zenith_api_up" in text


def test_rate_limit_backend_header(client: TestClient, auth_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/layers", headers=auth_headers)
    assert response.status_code == 200
    assert response.headers.get("X-RateLimit-Backend") == "memory"
    health = client.get("/healthz").json()
    assert health["metrics"]["rate_limit_backend"] == "memory"


def test_layer_features_wfs_lite_fixture(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """WFS-lite: bundled GeoJSON fixtures + bbox/limit (fallback without PostGIS)."""
    response = client.get(
        "/api/v1/layers/esa-worldcover-2020/features",
        headers=auth_headers,
        params={"limit": 5},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "FeatureCollection"
    assert body["mode"] == "wfs_lite"
    assert body["backend"] == "fixture"
    assert body["layer_id"] == "esa-worldcover-2020"
    assert body["numberReturned"] == 5
    assert len(body["features"]) == 5
    assert body["features"][0]["geometry"]["type"] == "Point"

    bboxed = client.get(
        "/api/v1/layers/esa-worldcover-2020/features",
        headers=auth_headers,
        params={"bbox": "50,35,52,36", "limit": 50},
    )
    assert bboxed.status_code == 200
    # Tehran sample (~51.39, 35.69) should match.
    assert bboxed.json()["numberReturned"] >= 1
    assert bboxed.json()["backend"] == "fixture"

    missing = client.get(
        "/api/v1/layers/no-such-layer/features", headers=auth_headers
    )
    assert missing.status_code == 404


def test_features_postgis_falls_back_to_fixture(
    client: TestClient, auth_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unreachable PostGIS DSN must not break the features endpoint."""
    from api.config import get_settings

    monkeypatch.setenv(
        "ZENITH_DATABASE_URL", "postgresql://nobody:invalid@127.0.0.1:1/none"
    )
    get_settings.cache_clear()
    response = client.get(
        "/api/v1/layers/esa-worldcover-2020/features",
        headers=auth_headers,
        params={"limit": 2},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "wfs_lite"
    assert body["backend"] == "fixture"
    get_settings.cache_clear()


def test_tiles_catalog_allowlisted(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """N4: expose catalog XYZ templates; Zenith does not host tiles."""
    listed = client.get("/api/v1/tiles", headers=auth_headers)
    assert listed.status_code == 200
    body = listed.json()
    assert body["zenith_hosts_tiles"] is False
    assert body["cdn_policy"]["zenith_hosts_tiles"] is False
    assert body["cdn_policy"]["env_var"] == "ZENITH_TILE_CDN_BASE_URLS"
    assert body["count"] >= 1
    ids = {item["layer_id"] for item in body["items"]}
    assert "opentopomap" in ids
    otm = next(i for i in body["items"] if i["layer_id"] == "opentopomap")
    assert otm["allowlisted"] is True
    assert "tile.opentopomap.org" in (otm["tile_url_template"] or "")

    detail = client.get("/api/v1/tiles/opentopomap", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["allowlisted"] is True

    # WMS-only layer has no tile template → 404 tiles_not_available
    no_tiles = client.get("/api/v1/tiles/esa-worldcover-2020", headers=auth_headers)
    assert no_tiles.status_code == 404
    assert no_tiles.json()["code"] == "tiles_not_available"


def test_tile_cdn_base_url_allowlist(
    client: TestClient, auth_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """CDN policy env allowlists partner bases without inventing CDN infra."""
    monkeypatch.setenv(
        "ZENITH_TILE_CDN_BASE_URLS", "https://cdn.partner.example"
    )
    get_settings.cache_clear()
    from api.main import create_app

    with TestClient(create_app()) as c:
        body = c.get("/api/v1/tiles", headers=auth_headers).json()
        assert "https://cdn.partner.example" in body["cdn_policy"][
            "allowlisted_cdn_base_urls"
        ]
        root = c.get("/api/v1").json()
        assert root["readiness"] == "staging-ready"
        assert root["tile_cdn"]["zenith_hosts_tiles"] is False
    get_settings.cache_clear()


def test_webhooks_register_and_catalog_bump(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    """N3+: register webhook; bump/key create pings; HMAC + delivery log."""
    created = client.post(
        "/api/v1/admin/webhooks",
        headers=admin_headers,
        json={
            "url": "https://example.com/zenith-hook",
            "events": ["catalog.updated", "admin.key_created"],
            "label": "Partner hook",
            "webhook_id": "wh-partner",
        },
    )
    assert created.status_code == 201
    assert created.json()["id"] == "wh-partner"

    listed = client.get("/api/v1/admin/webhooks", headers=admin_headers)
    assert listed.status_code == 200
    assert listed.json()["count"] == 1

    mock_response = MagicMock()
    mock_response.status_code = 204

    with patch("api.webhooks.httpx.Client") as client_cls:
        mock_http = MagicMock()
        mock_http.post.return_value = mock_response
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        client_cls.return_value = mock_http

        bumped = client.post(
            "/api/v1/admin/catalog/bump",
            headers=admin_headers,
            json={"reason": "test-bump"},
        )
        assert bumped.status_code == 200
        body = bumped.json()
        assert body["version"] == 2
        assert body["webhook"]["attempted"] == 1
        assert body["webhook"]["succeeded"] == 1
        assert mock_http.post.called
        # HMAC stub header present when signing secret configured.
        call_kwargs = mock_http.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers")
        assert headers is not None
        assert "X-Zenith-Signature" in headers
        assert headers["X-Zenith-Signature"].startswith("sha256=")

        key = client.post(
            "/api/v1/admin/keys",
            headers=admin_headers,
            json={"key_id": "hooked-partner", "scopes": ["layers:read"]},
        )
        assert key.status_code == 201
        # Second delivery for admin.key_created
        assert mock_http.post.call_count >= 2

    deliveries = client.get(
        "/api/v1/admin/webhooks/deliveries", headers=admin_headers
    )
    assert deliveries.status_code == 200
    del_body = deliveries.json()
    assert del_body["count"] >= 2
    assert del_body["durable"] is True
    assert all(item["signature_header"] for item in del_body["items"])

    meta = client.get("/api/v1/admin/catalog", headers=admin_headers)
    assert meta.status_code == 200
    assert meta.json()["version"] == 2

    deleted = client.delete(
        "/api/v1/admin/webhooks/wh-partner", headers=admin_headers
    )
    assert deleted.status_code == 200
    assert deleted.json()["active"] is False


def test_api_v1_root_marks_graphql_deferred(client: TestClient) -> None:
    """N5: GraphQL explicitly deferred on the version root."""
    response = client.get("/api/v1")
    assert response.status_code == 200
    body = response.json()
    assert body["graphql"] == "deferred"
    assert "features" in body["endpoints"]
    assert "tiles" in body["endpoints"]


def test_export_openapi_collection_script(tmp_path) -> None:
    """N2: export script writes OpenAPI + Postman collection without a server."""
    from scripts.export_openapi_collection import main

    out = tmp_path / "export"
    assert main(["--out-dir", str(out)]) == 0
    openapi = (out / "openapi.json").read_text(encoding="utf-8")
    postman = (out / "postman.collection.json").read_text(encoding="utf-8")
    assert '"openapi"' in openapi
    assert "/api/v1/layers/{layer_id}/features" in openapi
    assert "zenith_api_key" in postman
    assert "item" in postman


def test_python_sdk_lists_layers(client: TestClient, auth_headers: dict[str, str]) -> None:
    """N2: Python SDK starter wraps the same catalog endpoints."""
    import httpx

    from zenith_maps import ZenithMapsClient

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.url.query:
            path = f"{path}?{request.url.query}"
        headers = {k.decode(): v.decode() for k, v in request.headers.raw}
        resp = client.request(request.method, path, headers=headers)
        return httpx.Response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content=resp.content,
            request=request,
        )

    with ZenithMapsClient(
        base_url="http://testserver",
        api_key=auth_headers["X-API-Key"],
        transport=httpx.MockTransport(handler),
    ) as sdk:
        layers = sdk.list_layers()
        assert layers["count"] >= 2
        feats = sdk.get_features("esa-worldcover-2020", limit=3)
        assert feats["type"] == "FeatureCollection"
        tiles = sdk.list_tiles()
        assert tiles["zenith_hosts_tiles"] is False


def test_key_vault_survives_reseed(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Durable SQLite vault keeps admin-created keys across reset_and_seed."""
    from api.config import get_settings
    from api.keystore import KeyStore

    vault = tmp_path / "keys.sqlite"
    monkeypatch.setenv("ZENITH_KEY_VAULT_PATH", str(vault))
    get_settings.cache_clear()

    store = KeyStore()
    store.reset_and_seed()
    created = store.create(key_id="partner-durable", scopes=["layers:read"], label="d")
    secret = created.secret

    # New store instance + reseed from same vault file.
    store2 = KeyStore()
    store2.reset_and_seed()
    found = store2.lookup_by_secret(secret)
    assert found is not None
    assert found.key_id == "partner-durable"
    assert store2.durable is True
    get_settings.cache_clear()


def test_oidc_jwt_bearer_auth(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Optional JWKS path accepts a signed RS256 JWT as Bearer auth."""
    import time

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from jwt.algorithms import RSAAlgorithm

    from api.config import get_settings
    from api.oidc import get_jwks_cache

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    jwk["kid"] = "test-kid"
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"

    monkeypatch.setenv("ZENITH_OIDC_JWKS_URL", "https://idp.example/.well-known/jwks.json")
    monkeypatch.setenv("ZENITH_OIDC_AUDIENCE", "zenith-api")
    monkeypatch.setenv("ZENITH_OIDC_ISSUER", "https://idp.example/")
    get_settings.cache_clear()
    get_jwks_cache().reset()

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"keys": [jwk]}

    token = jwt.encode(
        {
            "sub": "partner-oidc",
            "aud": "zenith-api",
            "iss": "https://idp.example/",
            "exp": int(time.time()) + 600,
            "scope": "layers:read",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )

    with patch("api.oidc.httpx.Client") as client_cls:
        mock_http = MagicMock()
        mock_http.get.return_value = mock_resp
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        client_cls.return_value = mock_http

        # Recreate app so settings pick up OIDC env.
        from api.main import create_app

        with TestClient(create_app()) as oidc_client:
            ok = oidc_client.get(
                "/api/v1/layers",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert ok.status_code == 200
            assert ok.json()["count"] >= 1

            bad = oidc_client.get(
                "/api/v1/layers",
                headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.bad.sig"},
            )
            assert bad.status_code == 401

    get_settings.cache_clear()
    get_jwks_cache().reset()


def test_api_v1_root_reports_wfs_lite_and_auth(client: TestClient) -> None:
    response = client.get("/api/v1")
    assert response.status_code == 200
    body = response.json()
    assert body["features_mode"] == "wfs_lite"
    assert body["auth"]["api_key"] == "X-API-Key"
    assert "authorization_code" in body["auth"]["oauth_grants"]
    assert body["endpoints"]["oauth_authorize"] == "/oauth/authorize"
    assert body["key_portal"] == "/admin/key-portal"
    assert "admin_webhook_deliveries" in body["endpoints"]
    assert body["webhook_registry_durable"] is True
    assert body["webhook_retry_enabled"] is True
    assert body["package_version"] == "0.10.0"


def test_webhook_registry_survives_reconfigure(
    tmp_path, monkeypatch: pytest.MonkeyPatch, admin_headers: dict[str, str]
) -> None:
    """Ops: subscriptions persist in the shared webhook SQLite file."""
    from api.main import create_app
    from api.webhooks import get_webhook_registry

    whdb = tmp_path / "webhooks.sqlite"
    monkeypatch.setenv("ZENITH_WEBHOOK_LOG_PATH", str(whdb))
    get_settings.cache_clear()
    get_delivery_log().configure(str(whdb))
    get_webhook_registry().configure(str(whdb))
    get_retry_queue().configure(str(whdb))

    app = create_app()
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/admin/webhooks",
            headers=admin_headers,
            json={
                "url": "https://example.com/durable-hook",
                "events": ["catalog.updated"],
                "webhook_id": "wh-durable",
                "label": "Durable",
            },
        )
        assert created.status_code == 201

    # New process-equivalent: reconfigure registry from the same SQLite path.
    get_webhook_registry().configure(str(whdb))
    sub = get_webhook_registry().get("wh-durable")
    assert sub is not None
    assert sub.active is True
    assert sub.url == "https://example.com/durable-hook"
    listed = get_webhook_registry().list()
    assert any(w.id == "wh-durable" for w in listed)


def test_webhook_retry_backoff_and_worker(
    monkeypatch: pytest.MonkeyPatch, admin_headers: dict[str, str]
) -> None:
    """Failed deliveries enqueue; worker retries with exponential backoff."""
    from api.main import create_app
    from api.webhook_retry import (
        compute_backoff_s,
        get_retry_queue,
        process_due_retries,
    )
    from api.webhooks import get_webhook_registry

    assert compute_backoff_s(1, base_delay_s=2.0) == 2.0
    assert compute_backoff_s(2, base_delay_s=2.0) == 4.0
    assert compute_backoff_s(3, base_delay_s=2.0) == 8.0
    assert compute_backoff_s(10, base_delay_s=2.0, max_delay_s=30.0) == 30.0

    monkeypatch.setenv("ZENITH_WEBHOOK_RETRY_BASE_DELAY_S", "0.01")
    monkeypatch.setenv("ZENITH_WEBHOOK_RETRY_MAX_ATTEMPTS", "3")
    get_settings.cache_clear()

    app = create_app()
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/admin/webhooks",
            headers=admin_headers,
            json={
                "url": "https://example.com/retry-hook",
                "events": ["catalog.updated"],
                "webhook_id": "wh-retry",
            },
        )
        assert created.status_code == 201

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("api.webhooks.httpx.Client") as client_cls:
            mock_http = MagicMock()
            mock_http.post.return_value = mock_response
            mock_http.__enter__ = MagicMock(return_value=mock_http)
            mock_http.__exit__ = MagicMock(return_value=False)
            client_cls.return_value = mock_http

            bumped = client.post(
                "/api/v1/admin/catalog/bump",
                headers=admin_headers,
                json={"reason": "force-fail"},
            )
            assert bumped.status_code == 200
            assert bumped.json()["webhook"]["succeeded"] == 0

        pending = get_retry_queue().list_pending()
        assert len(pending) == 1
        assert pending[0].webhook_id == "wh-retry"
        assert pending[0].attempt_count == 1

        # Make the job due immediately and succeed on retry.
        job = pending[0]
        get_retry_queue().reschedule(job, error="force-due")
        # Overwrite next_retry_at by marking due via process with now far future
        # — re-read and force due by calling process_due_retries with now large.
        due_now = job.next_retry_at + 10_000

        ok_response = MagicMock()
        ok_response.status_code = 204
        with patch("api.webhook_retry.httpx.Client") as retry_cls:
            mock_retry = MagicMock()
            mock_retry.post.return_value = ok_response
            mock_retry.__enter__ = MagicMock(return_value=mock_retry)
            mock_retry.__exit__ = MagicMock(return_value=False)
            retry_cls.return_value = mock_retry

            # First force the pending job's next_retry_at into the past.
            from api.webhook_store import connect

            path = get_retry_queue().path
            with connect(path) as conn:
                conn.execute(
                    "UPDATE webhook_retry_queue SET next_retry_at = 0, "
                    "attempt_count = 1, status = 'pending'"
                )
                conn.commit()

            stats = process_due_retries(now=due_now, client=mock_retry)
            assert stats["attempted"] == 1
            assert stats["succeeded"] == 1

        assert get_retry_queue().list_pending() == []
        assert get_webhook_registry().get("wh-retry").last_status == "ok"


def test_key_portal_static_and_redirect(client: TestClient) -> None:
    """Minimal key portal HTML is served; /admin/key-portal redirects to it."""
    page = client.get("/static/admin/key_portal.html")
    assert page.status_code == 200
    assert "text/html" in page.headers.get("content-type", "")
    assert "API Key Portal" in page.text
    assert "/api/v1/admin/keys" in page.text

    redirected = client.get("/admin/key-portal", follow_redirects=False)
    assert redirected.status_code == 307
    assert redirected.headers["location"] == "/static/admin/key_portal.html"


def test_oauth_auth_code_and_refresh_local_stub(client: TestClient) -> None:
    """Local stub: authorize → code → token (+ refresh) → refresh grant."""
    cfg = client.get("/oauth/oidc-config")
    assert cfg.status_code == 200
    assert cfg.json()["mode"] == "local_stub"
    assert "authorization_code" in cfg.json()["grants"]

    auth = client.get(
        "/oauth/authorize",
        params={"response_type": "code", "client_id": "demo"},
    )
    assert auth.status_code == 200
    code = auth.json()["code"]
    assert code

    token = client.post(
        "/oauth/token",
        json={"grant_type": "authorization_code", "code": code},
    )
    assert token.status_code == 200
    body = token.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert "layers:read" in body["scope"]

    layers = client.get(
        "/api/v1/layers",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert layers.status_code == 200

    # Code is one-time.
    reuse = client.post(
        "/oauth/token",
        json={"grant_type": "authorization_code", "code": code},
    )
    assert reuse.status_code == 400
    assert reuse.json()["code"] == "invalid_grant"

    refreshed = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "refresh_token": body["refresh_token"],
        },
    )
    assert refreshed.status_code == 200
    new_body = refreshed.json()
    assert new_body["access_token"]
    assert new_body["refresh_token"]
    assert new_body["access_token"] != body["access_token"]

    # Old refresh token is consumed.
    again = client.post(
        "/oauth/token",
        json={
            "grant_type": "refresh_token",
            "refresh_token": body["refresh_token"],
        },
    )
    assert again.status_code == 400


def test_oauth_authorize_redirect_to_idp(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ZENITH_OIDC_CLIENT_ID", "zenith-app")
    monkeypatch.setenv(
        "ZENITH_OIDC_AUTHORIZE_URL", "https://idp.example/authorize"
    )
    monkeypatch.setenv(
        "ZENITH_OIDC_REDIRECT_URI", "http://127.0.0.1:8000/oauth/callback"
    )
    get_settings.cache_clear()
    from api.main import create_app

    with TestClient(create_app()) as oidc_client:
        resp = oidc_client.get(
            "/oauth/authorize",
            params={"response_type": "code", "state": "xyz", "scope": "openid"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        loc = resp.headers["location"]
        assert loc.startswith("https://idp.example/authorize")
        assert "client_id=zenith-app" in loc
        assert "state=xyz" in loc
        assert "response_type=code" in loc
    get_settings.cache_clear()


def test_oauth_auth_code_proxies_to_idp_token_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ZENITH_OIDC_CLIENT_ID", "zenith-app")
    monkeypatch.setenv("ZENITH_OIDC_CLIENT_SECRET", "super-secret")
    monkeypatch.setenv("ZENITH_OIDC_TOKEN_URL", "https://idp.example/token")
    monkeypatch.setenv(
        "ZENITH_OIDC_REDIRECT_URI", "http://127.0.0.1:8000/oauth/callback"
    )
    get_settings.cache_clear()
    from api.main import create_app

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "access_token": "idp-access",
        "token_type": "Bearer",
        "expires_in": 1800,
        "refresh_token": "idp-refresh",
        "scope": "openid layers:read",
    }

    with patch("api.oidc_flow.httpx.Client") as client_cls:
        mock_http = MagicMock()
        mock_http.post.return_value = mock_resp
        mock_http.__enter__ = MagicMock(return_value=mock_http)
        mock_http.__exit__ = MagicMock(return_value=False)
        client_cls.return_value = mock_http

        with TestClient(create_app()) as oidc_client:
            token = oidc_client.post(
                "/oauth/token",
                json={
                    "grant_type": "authorization_code",
                    "code": "from-idp",
                    "redirect_uri": "http://127.0.0.1:8000/oauth/callback",
                },
            )
            assert token.status_code == 200
            body = token.json()
            assert body["access_token"] == "idp-access"
            # IdP refresh is persisted server-side; client gets opaque handle.
            assert body["refresh_token"]
            assert body["refresh_token"] != "idp-refresh"

            refresh = oidc_client.post(
                "/oauth/token",
                json={
                    "grant_type": "refresh_token",
                    "refresh_token": body["refresh_token"],
                },
            )
            assert refresh.status_code == 200
            assert mock_http.post.call_count == 2
            # Second call must send the real IdP refresh, not the opaque handle.
            second_form = mock_http.post.call_args_list[1].kwargs.get("data") or {}
            assert second_form.get("refresh_token") == "idp-refresh"
            assert refresh.json()["refresh_token"] != "idp-refresh"

    get_settings.cache_clear()


def test_oauth_callback_exchanges_stub_code(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from urllib.parse import parse_qs, urlparse

    from api.config import get_settings
    from api.main import create_app

    # Skip consent HTML for this redirect-bound authorize → callback path.
    monkeypatch.setenv("ZENITH_OAUTH_CONSENT_ENABLED", "false")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        auth = c.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": "demo",
                "redirect_uri": "http://127.0.0.1:8000/oauth/callback",
            },
            follow_redirects=False,
        )
        assert auth.status_code == 302
        loc = auth.headers["location"]
        assert "code=" in loc
        qs = parse_qs(urlparse(loc).query)
        code = qs["code"][0]

        cb = c.get("/oauth/callback", params={"code": code, "state": "s1"})
        assert cb.status_code == 200
        body = cb.json()
        assert body["access_token"]
        assert body["refresh_token"]
        assert body["mode"] == "local_stub"
        assert body["state"] == "s1"
    get_settings.cache_clear()


def test_zenith_client_admin_key_helpers(client: TestClient) -> None:
    """Shared client helpers used by the Streamlit key portal."""
    from zenith_client import ZenithApiClient, ZenithApiError

    zc = ZenithApiClient(base_url="http://test", api_key="zenith_admin_key_manage")

    def _patched_request(method: str, path: str, **kwargs):
        response = client.request(method, path, headers=zc._headers(), **kwargs)
        if response.status_code >= 400:
            body = response.json()
            raise ZenithApiError(
                body.get("message", response.text),
                status_code=response.status_code,
                code=body.get("code"),
            )
        return response.json()

    zc._request = _patched_request  # type: ignore[method-assign]
    created = zc.create_api_key(
        key_id="portal-partner", scopes=["layers:read"], label="p"
    )
    assert created["key_id"] == "portal-partner"
    assert created["secret"].startswith("zenith_")
    listed = zc.list_api_keys()
    assert any(i["key_id"] == "portal-partner" for i in listed["items"])
    rotated = zc.rotate_api_key("portal-partner")
    assert rotated["secret"].startswith("zenith_")
    assert rotated["secret"] != created["secret"]
    revoked = zc.revoke_api_key("portal-partner")
    assert revoked["revoked"] is True


def test_oauth_pkce_s256_local_stub(client: TestClient) -> None:
    """Auth-code + PKCE S256: challenge at authorize, verifier at token."""
    from api.pkce import code_challenge_s256, generate_code_verifier

    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)
    auth = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert auth.status_code == 200
    assert auth.json()["pkce"] is True
    code = auth.json()["code"]

    bad = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": "wrong-verifier-value-xxxxxxxxxxxxxxxxxxxx",
        },
    )
    assert bad.status_code == 400

    # Failed PKCE must not consume the code — correct verifier still works.
    ok = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
        },
    )
    assert ok.status_code == 200
    assert ok.json()["access_token"]


def test_oauth_pkce_required_rejects_missing_challenge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ZENITH_OIDC_PKCE_REQUIRED", "true")
    get_settings.cache_clear()
    from api.main import create_app

    with TestClient(create_app()) as c:
        resp = c.get(
            "/oauth/authorize",
            params={"response_type": "code", "client_id": "demo"},
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == "invalid_request"
    get_settings.cache_clear()


def test_portal_rbac_operator_vs_admin(client: TestClient) -> None:
    """keys:read lists; admin:keys mutates; rotate needs admin."""
    op = {"X-API-Key": "zenith_operator_key_read"}
    listed = client.get("/api/v1/admin/keys", headers=op)
    assert listed.status_code == 200

    denied = client.post(
        "/api/v1/admin/keys",
        headers=op,
        json={"key_id": "nope", "scopes": ["layers:read"]},
    )
    assert denied.status_code == 403

    admin = {"X-API-Key": "zenith_admin_key_manage"}
    created = client.post(
        "/api/v1/admin/keys",
        headers=admin,
        json={"key_id": "rot-me", "scopes": ["layers:read"], "label": "r"},
    )
    assert created.status_code == 201
    old_secret = created.json()["secret"]

    rotate_denied = client.post("/api/v1/admin/keys/rot-me/rotate", headers=op)
    assert rotate_denied.status_code == 403

    rotated = client.post("/api/v1/admin/keys/rot-me/rotate", headers=admin)
    assert rotated.status_code == 200
    new_secret = rotated.json()["secret"]
    assert new_secret != old_secret
    assert client.get("/api/v1/layers", headers={"X-API-Key": old_secret}).status_code == 401
    assert client.get("/api/v1/layers", headers={"X-API-Key": new_secret}).status_code == 200


def test_portal_login_sets_session_cookie(client: TestClient) -> None:
    """PKCE portal login → cookie → session + admin list without X-API-Key."""
    cfg = client.get("/oauth/oidc-config")
    assert cfg.status_code == 200
    assert cfg.json()["pkce"]["methods"] == ["S256"]
    assert "portal_login" in cfg.json()
    assert cfg.json()["portal_cookies"]["csrf_enabled"] is True

    # follow_redirects: login → callback → key-portal; cookie jar keeps session.
    landed = client.get(
        "/oauth/portal/login",
        params={"client_id": "admin", "return_to": "/admin/key-portal"},
        follow_redirects=True,
    )
    assert landed.status_code in {200, 307}
    assert client.cookies.get("zenith_portal_token")
    csrf = client.cookies.get("zenith_portal_csrf")
    assert csrf

    session = client.get("/oauth/portal/session")
    assert session.status_code == 200
    body = session.json()
    assert body["authenticated"] is True
    assert body["key_id"] == "admin"
    assert body["can_manage_keys"] is True
    assert body["auth_via"] == "portal_cookie"
    assert body["session_id"]
    assert body["session_store"] in {"sqlite", "memory", "redis"}
    assert body["session"]["key_id"] == "admin"
    # Cookie holds opaque session_id, not the access token itself.
    assert client.cookies.get("zenith_portal_token") == body["session_id"]

    listed = client.get("/api/v1/admin/keys")
    assert listed.status_code == 200

    # Cookie-auth mutation without CSRF header → 403.
    bad = client.post(
        "/api/v1/admin/keys",
        json={"key_id": "csrf-denied", "scopes": ["layers:read"]},
    )
    assert bad.status_code == 403
    assert bad.json()["code"] == "csrf_failed"

    ok = client.post(
        "/api/v1/admin/keys",
        headers={"X-CSRF-Token": csrf},
        json={"key_id": "csrf-ok", "scopes": ["layers:read"]},
    )
    assert ok.status_code == 201
    assert ok.json()["key_id"] == "csrf-ok"

    logout = client.post("/oauth/portal/logout")
    assert logout.status_code == 200
    assert client.get("/oauth/portal/session").status_code == 401


def test_webhook_egress_blocks_private_and_respects_allowlist(
    client: TestClient, admin_headers: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """SSRF hardening: private IPs blocked; optional host allowlist enforced."""
    blocked = client.post(
        "/api/v1/admin/webhooks",
        headers=admin_headers,
        json={"url": "https://10.0.0.5/hook", "events": ["webhook.ping"]},
    )
    assert blocked.status_code == 400

    meta = client.post(
        "/api/v1/admin/webhooks",
        headers=admin_headers,
        json={
            "url": "https://169.254.169.254/latest/meta-data",
            "events": ["webhook.ping"],
        },
    )
    assert meta.status_code == 400

    monkeypatch.setenv("ZENITH_WEBHOOK_ALLOWED_HOSTS", "hooks.partner.example")
    get_settings.cache_clear()
    from api.main import create_app

    with TestClient(create_app()) as c:
        denied = c.post(
            "/api/v1/admin/webhooks",
            headers=admin_headers,
            json={
                "url": "https://example.com/zenith-hook",
                "events": ["webhook.ping"],
            },
        )
        assert denied.status_code == 400
        assert "allowlist" in denied.json()["message"].lower()

        allowed = c.post(
            "/api/v1/admin/webhooks",
            headers=admin_headers,
            json={
                "url": "https://hooks.partner.example/zenith",
                "events": ["webhook.ping"],
                "webhook_id": "wh-allow",
            },
        )
        assert allowed.status_code == 201
    get_settings.cache_clear()


def test_migrate_lists_sql_and_exits_without_dsn(tmp_path) -> None:
    """Lightweight migration runner discovers NNN_*.sql; no DSN → exit 2."""
    from api.migrate import list_migration_files, main

    files = list_migration_files()
    assert any(name == "001" for name, _ in files)
    assert any(p.name == "001_zenith_features.sql" for _, p in files)

    # Tiny local sql dir still discovered.
    sample = tmp_path / "002_demo.sql"
    sample.write_text("-- demo\nSELECT 1;\n", encoding="utf-8")
    local = list_migration_files(tmp_path)
    assert local == [("002", sample)]

    assert main(["--dry-run"]) == 2


def test_oauth_local_consent_stub_approve_and_deny(
    client: TestClient,
) -> None:
    """Local auth-code + redirect_uri parks on consent HTML before code."""
    from urllib.parse import parse_qs, urlparse

    auth = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo",
            "redirect_uri": "http://127.0.0.1:8000/oauth/callback",
            "state": "consent-state",
            "scope": "layers:read",
        },
        follow_redirects=False,
    )
    assert auth.status_code == 200
    assert "text/html" in auth.headers.get("content-type", "")
    assert "Authorize application" in auth.text
    assert 'name="pending_id"' in auth.text

    # Pull pending_id from the HTML form.
    import re

    match = re.search(r'name="pending_id" value="([^"]+)"', auth.text)
    assert match
    pending_id = match.group(1)

    denied = client.post(
        "/oauth/consent",
        data={"pending_id": pending_id, "decision": "deny"},
        follow_redirects=False,
    )
    assert denied.status_code == 302
    assert "error=access_denied" in denied.headers["location"]
    assert "state=consent-state" in denied.headers["location"]

    # Fresh consent → approve → code redirect.
    auth2 = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "demo",
            "redirect_uri": "http://127.0.0.1:8000/oauth/callback",
            "state": "ok",
        },
        follow_redirects=False,
    )
    match2 = re.search(r'name="pending_id" value="([^"]+)"', auth2.text)
    assert match2
    approved = client.post(
        "/oauth/consent",
        data={"pending_id": match2.group(1), "decision": "approve"},
        follow_redirects=False,
    )
    assert approved.status_code == 302
    loc = approved.headers["location"]
    qs = parse_qs(urlparse(loc).query)
    assert qs["code"][0]
    assert qs["state"][0] == "ok"

    token = client.post(
        "/oauth/token",
        json={
            "grant_type": "authorization_code",
            "code": qs["code"][0],
            "redirect_uri": "http://127.0.0.1:8000/oauth/callback",
        },
    )
    assert token.status_code == 200
    assert token.json()["access_token"]


def test_session_store_sqlite_survives_reconfigure(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """SQLite session + IdP refresh handles persist across worker re-attach."""
    from api.config import get_settings
    from api.session_store import (
        SqliteSessionStore,
        configure_session_store,
        reset_session_store,
    )

    path = tmp_path / "sso.sqlite"
    monkeypatch.setenv("ZENITH_SESSION_STORE_BACKEND", "sqlite")
    monkeypatch.setenv("ZENITH_SESSION_STORE_PATH", str(path))
    get_settings.cache_clear()
    store = reset_session_store()
    assert store.backend_name == "sqlite"

    session = store.create_session(
        key_id="admin",
        scopes=frozenset({"admin:keys"}),
        label="Admin",
        ttl_s=600,
        idp_refresh_token="secret-idp-refresh",
    )
    refresh = store.store_idp_refresh(
        idp_refresh_token="idp-rt-1",
        key_id="oidc:user",
        scopes=frozenset({"openid"}),
        label="u",
        ttl_s=3600,
    )
    sid, handle = session.session_id, refresh.handle

    # Re-attach without wipe (simulates another worker on the same file).
    store2 = configure_session_store()
    assert store2.backend_name == "sqlite"
    loaded = store2.get_session(sid)
    assert loaded is not None
    assert loaded.key_id == "admin"
    assert loaded.idp_refresh_token == "secret-idp-refresh"
    rt = store2.get_idp_refresh(handle)
    assert rt is not None
    assert rt.idp_refresh_token == "idp-rt-1"

    # Independent backend instance on the same path also sees rows.
    peer = SqliteSessionStore(str(path))
    assert peer.get_session(sid) is not None
    get_settings.cache_clear()


def test_oauth_oidc_config_exposes_session_and_consent(client: TestClient) -> None:
    cfg = client.get("/oauth/oidc-config")
    assert cfg.status_code == 200
    body = cfg.json()
    assert body["idp_refresh_persistence"] is True
    assert body["consent"]["enabled"] is True
    assert body["consent_path"] == "/oauth/consent"
    assert body["session_store"]["backend"] in {"sqlite", "memory", "redis"}
    assert body["portal_cookies"]["value"] == "opaque_session_id"


def test_oauth_authorize_idp_includes_pkce(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api.pkce import code_challenge_s256, generate_code_verifier

    monkeypatch.setenv("ZENITH_OIDC_CLIENT_ID", "zenith-app")
    monkeypatch.setenv(
        "ZENITH_OIDC_AUTHORIZE_URL", "https://idp.example/authorize"
    )
    monkeypatch.setenv(
        "ZENITH_OIDC_REDIRECT_URI", "http://127.0.0.1:8000/oauth/callback"
    )
    get_settings.cache_clear()
    from api.main import create_app

    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)
    with TestClient(create_app()) as oidc_client:
        resp = oidc_client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "state": "xyz",
                "scope": "openid",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        loc = resp.headers["location"]
        assert "code_challenge=" in loc
        assert "code_challenge_method=S256" in loc
    get_settings.cache_clear()

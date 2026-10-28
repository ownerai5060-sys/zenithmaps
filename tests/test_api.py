"""Acceptance tests for M2–M7 and S1–S5 platform API surface."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


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
        "/api/v1/admin/webhooks",
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
            "grant_type": "authorization_code",
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


def test_layer_features_stub(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """N1: stub GeoJSON FeatureCollection for catalog layers."""
    response = client.get(
        "/api/v1/layers/esa-worldcover-2020/features",
        headers=auth_headers,
        params={"limit": 5},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["type"] == "FeatureCollection"
    assert body["mode"] == "stub"
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

    missing = client.get(
        "/api/v1/layers/no-such-layer/features", headers=auth_headers
    )
    assert missing.status_code == 404


def test_tiles_catalog_allowlisted(
    client: TestClient, auth_headers: dict[str, str]
) -> None:
    """N4: expose catalog XYZ templates; Zenith does not host tiles."""
    listed = client.get("/api/v1/tiles", headers=auth_headers)
    assert listed.status_code == 200
    body = listed.json()
    assert body["zenith_hosts_tiles"] is False
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


def test_webhooks_register_and_catalog_bump(
    client: TestClient, admin_headers: dict[str, str]
) -> None:
    """N3: register webhook URL; bump catalog / key create pings subscribers."""
    from unittest.mock import MagicMock, patch

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

        key = client.post(
            "/api/v1/admin/keys",
            headers=admin_headers,
            json={"key_id": "hooked-partner", "scopes": ["layers:read"]},
        )
        assert key.status_code == 201
        # Second delivery for admin.key_created
        assert mock_http.post.call_count >= 2

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

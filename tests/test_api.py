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
        "/api/v1/layers",
        "/api/v1/layers/{layer_id}",
        "/api/v1/layers/{layer_id}/legend",
        "/api/v1/layers/{layer_id}/legend/image",
        "/api/v1/security/check-url",
        "/api/v1/security/allowlist",
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

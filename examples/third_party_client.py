#!/usr/bin/env python3
"""Minimal third-party client — acceptance check for the Zenith platform API.

Usage (API must be running on localhost:8000)::

    python examples/third_party_client.py

Or as a pytest that starts its own ASGI app (no live server required)::

    pytest examples/third_party_client.py -q
"""

from __future__ import annotations

import os
import sys

import httpx

API_BASE = os.getenv("ZENITH_API_BASE", "http://127.0.0.1:8000")
API_KEY = os.getenv("ZENITH_API_KEY", "zenith_demo_key_layers_read")


def run_against(base_url: str, api_key: str) -> None:
    headers = {"X-API-Key": api_key}
    with httpx.Client(base_url=base_url, timeout=10.0) as client:
        health = client.get("/healthz")
        health.raise_for_status()
        print("health:", health.json())

        layers = client.get("/api/v1/layers", headers=headers)
        layers.raise_for_status()
        catalog = layers.json()
        print(f"layers: {catalog['count']} item(s)")
        for item in catalog["items"]:
            print(f"  - {item['id']}: {item['title']}")

        layer_id = "esa-worldcover-2020"
        detail = client.get(f"/api/v1/layers/{layer_id}", headers=headers)
        detail.raise_for_status()
        print("detail wms:", detail.json().get("wms"))

        legend = client.get(f"/api/v1/layers/{layer_id}/legend", headers=headers)
        legend.raise_for_status()
        entries = legend.json()["entries"]
        print(f"legend entries: {len(entries)} (first={entries[0]})")

        blocked = client.post(
            "/api/v1/security/check-url",
            headers=headers,
            json={"url": "https://evil.example/wms"},
        )
        blocked.raise_for_status()
        assert blocked.json()["allowed"] is False
        print("allowlist correctly blocked evil.example")

    print("OK — third-party client acceptance passed")


def test_third_party_client_asgi() -> None:
    """Pytest acceptance: exercise the same flow in-process (no live server)."""
    from fastapi.testclient import TestClient

    from api.config import get_settings
    from api.main import create_app

    get_settings.cache_clear()
    headers = {"X-API-Key": API_KEY}
    with TestClient(create_app()) as client:
        assert client.get("/healthz").status_code == 200
        layers = client.get("/api/v1/layers", headers=headers)
        assert layers.status_code == 200
        assert layers.json()["count"] >= 1
        legend = client.get(
            "/api/v1/layers/esa-worldcover-2020/legend", headers=headers
        )
        assert legend.status_code == 200
        assert legend.json()["entries"]
        check = client.post(
            "/api/v1/security/check-url",
            headers=headers,
            json={"url": "https://evil.example/wms"},
        )
        assert check.json()["allowed"] is False
    get_settings.cache_clear()


def main() -> int:
    try:
        run_against(API_BASE, API_KEY)
    except Exception as exc:  # noqa: BLE001 — CLI surface
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

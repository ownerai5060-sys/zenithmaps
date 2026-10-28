#!/usr/bin/env python3
"""Export OpenAPI JSON and a Postman Collection v2.1 from the running app (N2).

Usage::

    # From repo root (no server required — imports the FastAPI app):
    python scripts/export_openapi_collection.py --out-dir artifacts/api-export

    # Or against a live base URL:
    python scripts/export_openapi_collection.py --base-url http://127.0.0.1:8000

Writes:
  openapi.json
  postman.collection.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.request import urlopen


def _load_openapi_from_app() -> dict[str, Any]:
    # Ensure repo root is importable when run as a script.
    root = Path(__file__).resolve().parents[1]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from api.main import create_app

    app = create_app()
    return app.openapi()


def _load_openapi_from_url(base_url: str) -> dict[str, Any]:
    url = base_url.rstrip("/") + "/openapi.json"
    with urlopen(url, timeout=30) as resp:  # noqa: S310 — operator-controlled URL
        return json.loads(resp.read().decode("utf-8"))


def openapi_to_postman(openapi: dict[str, Any], *, base_url: str) -> dict[str, Any]:
    """Minimal OpenAPI 3 → Postman Collection v2.1 converter."""
    info = openapi.get("info") or {}
    paths = openapi.get("paths") or {}
    items: list[dict[str, Any]] = []

    for path, methods in sorted(paths.items()):
        for method, operation in sorted(methods.items()):
            if method.startswith("x-") or not isinstance(operation, dict):
                continue
            name = operation.get("summary") or f"{method.upper()} {path}"
            raw_url = base_url.rstrip("/") + path
            # Postman path array without leading empty segment issues.
            path_parts = [p for p in path.strip("/").split("/") if p]
            headers = [
                {"key": "Accept", "value": "application/json"},
                {
                    "key": "X-API-Key",
                    "value": "{{zenith_api_key}}",
                    "description": "Demo/sandbox API key",
                },
            ]
            request: dict[str, Any] = {
                "method": method.upper(),
                "header": headers,
                "url": {
                    "raw": raw_url,
                    "host": ["{{zenith_base_url}}"],
                    "path": path_parts,
                },
                "description": operation.get("description") or "",
            }
            items.append({"name": name, "request": request})

    return {
        "info": {
            "name": info.get("title") or "Zenith Maps Platform API",
            "description": info.get("description") or "",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "_postman_id": "zenith-maps-api-v1",
            "version": info.get("version") or "0.4.0",
        },
        "variable": [
            {"key": "zenith_base_url", "value": base_url.rstrip("/")},
            {"key": "zenith_api_key", "value": "zenith_demo_key_layers_read"},
        ],
        "item": items,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("artifacts/api-export"),
        help="Directory for openapi.json and postman.collection.json",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help="If set, fetch /openapi.json from this base URL instead of importing the app",
    )
    parser.add_argument(
        "--collection-base-url",
        default="http://127.0.0.1:8000",
        help="Base URL embedded in the Postman collection variables",
    )
    args = parser.parse_args(argv)

    if args.base_url:
        openapi = _load_openapi_from_url(args.base_url)
        collection_base = args.base_url
    else:
        openapi = _load_openapi_from_app()
        collection_base = args.collection_base_url

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    openapi_path = out_dir / "openapi.json"
    postman_path = out_dir / "postman.collection.json"
    openapi_path.write_text(json.dumps(openapi, indent=2) + "\n", encoding="utf-8")
    collection = openapi_to_postman(openapi, base_url=collection_base)
    postman_path.write_text(json.dumps(collection, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote {openapi_path}")
    print(f"Wrote {postman_path}")
    print(f"OpenAPI paths: {len(openapi.get('paths') or {})}")
    print(f"Postman requests: {len(collection.get('item') or [])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

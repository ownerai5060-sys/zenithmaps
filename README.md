# Zenith Maps

Interactive Zenith map demos (Streamlit + leafmap) plus a **platform HTTP API**
for external applications.

## Architecture

| Surface | Path | Role |
|---------|------|------|
| UI demo | `Home.py`, `pages/` | Streamlit map demos — not a stable integration API |
| Platform API | `api/` | FastAPI under `/api/v1` — catalog, metadata, legend JSON + GetLegendGraphic |
| Shared client | `zenith_client/` | Helper used by Streamlit and examples |

External apps should integrate against the API, not against Streamlit page
routes. See OpenAPI at `/docs` when the API is running.

Bilingual integration / staging notes:
[docs in agent store](https://github.com/ownerai5060-sys/zenithmaps) — see project
docs `zenith-api-integration-guide.md` (also mirrored conceptually below).

## Platform API (quick start)

```bash
pip install -r requirements-api.txt
uvicorn api.main:app --reload --port 8000
```

- Docs: http://127.0.0.1:8000/docs
- Health: `GET /healthz` (optional `?check_upstreams=true`)
- Metrics: `GET /metrics`
- Catalog: `GET /api/v1/layers` with header `X-API-Key: zenith_demo_key_layers_read`
- Legend image: `GET /api/v1/layers/{id}/legend/image`

Demo API keys are stubs for local/third-party onboarding only. Override with
`ZENITH_API_KEYS`, `ZENITH_CORS_ORIGINS`, `ZENITH_WMS_ALLOWED_HOSTS`,
`ZENITH_WMS_ALLOWED_LAYERS`, `ZENITH_RATE_LIMIT_*`, and `ZENITH_PUBLIC_BASE_URL`
in real deployments.

```bash
pytest
ruff check api tests zenith_client examples
python examples/third_party_client.py   # requires API on :8000
```

Sample browser client: `examples/third_party_client.html`

Pinned dependencies: `requirements-api.txt` + `requirements-api.lock.txt`.  
CI: `.github/workflows/api-ci.yml` (lint + OpenAPI contract tests).

## Streamlit UI demo

```bash
pip install -r requirements.txt
# Start API in another terminal for catalog/legend pages:
uvicorn api.main:app --port 8000
streamlit run Home.py
```

- `pages/6_📦_Web_Map_Service.py` — prefers API legends for catalog WMS layers
- `pages/7_🗂️_API_Catalog.py` — thin client of `/api/v1`

Based on the [opengeos/streamlit-map-template](https://github.com/opengeos/streamlit-map-template).

## Demo

![](https://i.imgur.com/6lj0oAO.png)

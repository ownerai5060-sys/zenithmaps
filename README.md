# Zenith Maps

Interactive Zenith map demos (Streamlit + leafmap) plus a **platform HTTP API**
for external applications.

## Architecture

| Surface | Path | Role |
|---------|------|------|
| UI demo | `Home.py`, `pages/` | Streamlit map demos — not a stable integration API |
| Platform API | `api/` | FastAPI under `/api/v1` — catalog, metadata, legend JSON |

External apps should integrate against the API, not against Streamlit page
routes. See OpenAPI at `/docs` when the API is running.

## Platform API (quick start)

```bash
pip install -r requirements-api.txt
uvicorn api.main:app --reload --port 8000
```

- Docs: http://127.0.0.1:8000/docs
- Health: `GET /healthz`
- Catalog: `GET /api/v1/layers` with header `X-API-Key: zenith_demo_key_layers_read`

Demo API keys are stubs for local/third-party onboarding only. Override with
`ZENITH_API_KEYS`, `ZENITH_CORS_ORIGINS`, `ZENITH_WMS_ALLOWED_HOSTS`, and
`ZENITH_WMS_ALLOWED_LAYERS` in real deployments.

```bash
pytest
python examples/third_party_client.py   # requires API on :8000
```

Sample browser client: `examples/third_party_client.html`

## Streamlit UI demo

```bash
pip install -r requirements.txt
streamlit run Home.py
```

Based on the [opengeos/streamlit-map-template](https://github.com/opengeos/streamlit-map-template).

## Demo

![](https://i.imgur.com/6lj0oAO.png)

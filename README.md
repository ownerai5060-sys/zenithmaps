# Zenith Maps

Interactive Zenith map demos (Streamlit + leafmap) plus a **platform HTTP API**
for external applications.

## دربارهٔ زنیت / About Zenith (محصول)

**زنیت** پلتفرم نقشه‌های تعاملی است: برای کاربر نهایی دموهای Streamlit، و برای
اپ‌های دیگر یک **API پایدار** زیر `/api/v1`.

| چه می‌خواهید؟ | از کجا شروع کنید؟ |
|---------------|-------------------|
| دیدن نقشه در مرورگر | `streamlit run Home.py` |
| وصل کردن اپ خودتان به کاتالوگ لایه / legend / کاشی‌های تأییدشده | `uvicorn api.main:app` → `/docs` |
| SDK نازک پایتون / JS | `sdk/python`, `sdk/js` |
| خروجی Postman / OpenAPI | `python scripts/export_openapi_collection.py` |

این مخزن **سرویس کاشی اختصاصی زنیت (WMTS/CDN) ندارد** و **GraphQL ندارد**
(عمداً به تعویق افتاده). کاشی‌ها فقط URLهای allowlist‌شدهٔ کاتالوگ هستند؛
سیاست CDN: `docs/tile-cdn-policy.md` و env اختیاری `ZENITH_TILE_CDN_BASE_URLS`.

**وضعیت آمادگی API:** `staging-ready` (package `0.12.0` — sandbox / پروتوتایپ خارجی).
چرخش کلید مبتنی بر سیاست، پل SSO استریم‌لیت، Redis/OTel extras، نمونهٔ
`docker compose` (API+Redis+PostGIS+OTel)، و یادداشت sidecar خروجی webhook.
موارد فقط‑پروداکشن باقی‌مانده: IdP واقعی، SLA، CDN عملیاتی، queue مدیریت‌شده،
egress سازمانی.

---

## Architecture

| Surface | Path | Role |
|---------|------|------|
| UI demo | `Home.py`, `pages/` | Streamlit map demos — not a stable integration API |
| Platform API | `api/` | FastAPI under `/api/v1` — catalog, legend, WFS-lite features, tiles metadata, durable keys, webhooks, optional OIDC |
| Shared client | `zenith_client/` | Helper used by Streamlit and examples |
| Official SDK starters | `sdk/python`, `sdk/js` | Thin Python package + JS fetch helper (N2) |

External apps should integrate against the API, not against Streamlit page
routes. See OpenAPI at `/docs` when the API is running.

## Platform API (quick start)

```bash
pip install -r requirements-api.txt
uvicorn api.main:app --reload --port 8000
```

- Docs: http://127.0.0.1:8000/docs
- Health: `GET /healthz`
- Catalog: `GET /api/v1/layers` with `X-API-Key: zenith_demo_key_layers_read`
- WFS-lite features: `GET /api/v1/layers/{id}/features` (fixtures; optional PostGIS via `ZENITH_DATABASE_URL`)
- Allowlisted tile templates (N4): `GET /api/v1/tiles`
- Admin webhooks + delivery log: `POST /api/v1/admin/webhooks`, `GET .../deliveries`
- Durable webhook registry + retry queue: set `ZENITH_WEBHOOK_LOG_PATH` (SQLite); drain with `python -m api.webhook_worker`
- PostGIS WFS-lite schema: `python -m api.migrate` (or `sql/001_zenith_features.sql`; `psycopg` pinned)
- Durable key vault: set `ZENITH_KEY_VAULT_PATH` (SQLite) so admin-created keys survive restart
- Key portal UI: `/admin/key-portal` (static HTML) or Streamlit page `pages/8_🔑_API_Keys.py`
- Portal SSO (PKCE S256): `/oauth/portal/login` → HttpOnly session + CSRF double-submit cookie
- Light RBAC: `keys:read` (list) vs `admin:keys` (create/revoke/rotate); `POST .../keys/{id}/rotate`
- Policy rotation: `GET/PUT /api/v1/admin/keys/rotation-policy` + cron `python -m api.rotation_worker`
- Streamlit SSO bridge: shared `ZENITH_PORTAL_COOKIE_DOMAIN` + `/oauth/portal/token-exchange` (see `zenith_client/sso_bridge.py`)
- Optional Redis/OTel: `pip install -r requirements-api-extras.txt`; sample `docs/otel-collector.env.sample`
- Local stack sample: `docker compose --env-file compose.env.sample up --build` (API + Redis + PostGIS + OTel collector)
- Webhook egress: soft SSRF + `ZENITH_WEBHOOK_ALLOWED_HOSTS`; optional allowlist sidecar `docs/webhook-egress-proxy.md` (`--profile egress`)
- Tile CDN policy stub: `ZENITH_TILE_CDN_BASE_URLS` (allowlist only; no hosted CDN)
- OAuth/OIDC: `/oauth/token` supports `client_credentials`, `authorization_code`, `refresh_token`
  with PKCE S256; `/oauth/authorize` + `/oauth/callback` stub locally or proxy to IdP via `ZENITH_OIDC_*`
- Optional OIDC JWT Bearer: set `ZENITH_OIDC_JWKS_URL` (+ audience/issuer)

Demo API keys are stubs for local/third-party onboarding only. Override with
`ZENITH_API_KEYS`, `ZENITH_KEY_VAULT_PATH`, `ZENITH_CORS_ORIGINS`,
`ZENITH_WMS_ALLOWED_HOSTS`, `ZENITH_WMS_ALLOWED_LAYERS`, `ZENITH_RATE_LIMIT_*`,
`ZENITH_DATABASE_URL`, `ZENITH_OIDC_*`, `ZENITH_WEBHOOK_*`, and
`ZENITH_PUBLIC_BASE_URL` in real deployments.

```bash
pytest
ruff check api tests zenith_client examples scripts
python examples/third_party_client.py   # requires API on :8000
python scripts/export_openapi_collection.py --out-dir artifacts/api-export
pip install -e sdk/python
```

Sample browser client: `examples/third_party_client.html`  
JS helper: `sdk/js/zenith-maps.js`

Pinned dependencies: `requirements-api.txt` + `requirements-api.lock.txt`.  
CI: `.github/workflows/api-ci.yml` (lint + OpenAPI contract tests).

### GraphQL (N5 — deferred)

No GraphQL schema is shipped. Prefer REST `/api/v1` + OpenAPI. Revisit only if
multiple clients need flexible field selection beyond the catalog/features surface.

### Tiles / WMTS / XYZ (N4)

Zenith does **not** operate a private tile CDN. `GET /api/v1/tiles` lists
`tile_url_template` values already on catalog layers (e.g. OpenTopoMap) when
their hosts are allowlisted. Clients fetch those upstreams directly — this API
does not proxy open CDNs.

## Streamlit UI demo

```bash
pip install -r requirements.txt
# Start API in another terminal for catalog/legend pages:
uvicorn api.main:app --port 8000
streamlit run Home.py
```

- `pages/6_📦_Web_Map_Service.py` — prefers API legends for catalog WMS layers
- `pages/7_🗂️_API_Catalog.py` — thin client of `/api/v1`
- `pages/8_🔑_API_Keys.py` — operator/admin key portal (list / create / revoke / rotate)

Based on the [opengeos/streamlit-map-template](https://github.com/opengeos/streamlit-map-template).

## Demo

![](https://i.imgur.com/6lj0oAO.png)

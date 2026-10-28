# SQL / schema notes

Light, operator-applied SQL for optional PostGIS WFS-lite. This repo does **not**
run Alembic (or similar) automatically; apply scripts manually against the
database named by `ZENITH_DATABASE_URL`.

| File | Purpose |
|------|---------|
| `001_zenith_features.sql` | Creates `zenith_features` (+ PostGIS extension, indexes) for `GET /api/v1/layers/{id}/features` when `backend=postgis` |

**Apply (example):**

```bash
psql "$ZENITH_DATABASE_URL" -f sql/001_zenith_features.sql
```

**Python driver:** `psycopg[binary]` is pinned in `requirements-api.txt`. Without
it, the API still starts and falls back to fixtures/stubs.

**Webhook ops SQLite** (subscriptions, deliveries, retry queue) is created
automatically at runtime when `ZENITH_WEBHOOK_LOG_PATH` is set — no SQL file
needed for that path.

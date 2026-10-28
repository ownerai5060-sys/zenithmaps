# SQL / schema notes

Optional PostGIS schema for WFS-lite. Prefer the lightweight migration runner
over hand-applying scripts when a database is available.

| File | Purpose |
|------|---------|
| `001_zenith_features.sql` | Creates `zenith_features` (+ PostGIS extension, indexes) for `GET /api/v1/layers/{id}/features` when `backend=postgis` |

**Apply with runner (recommended):**

```bash
export ZENITH_DATABASE_URL="postgresql://..."   # PostGIS DSN
python -m api.migrate --dry-run                 # list pending
python -m api.migrate                           # apply pending NNN_*.sql
```

The runner records applied versions in `zenith_schema_migrations`. It is **not**
Alembic (no autogenerate / downgrade graph) — just a deterministic apply path.

**Manual apply (still supported):**

```bash
psql "$ZENITH_DATABASE_URL" -f sql/001_zenith_features.sql
```

**Python driver:** `psycopg[binary]` is pinned in `requirements-api.txt`. Without
it, the API still starts and falls back to fixtures/stubs. Without
`ZENITH_DATABASE_URL`, `python -m api.migrate` exits with code 2 and a clear message.

**Webhook ops SQLite** (subscriptions, deliveries, retry queue) is created
automatically at runtime when `ZENITH_WEBHOOK_LOG_PATH` is set — no SQL file
needed for that path.

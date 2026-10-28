# Compose / staging smoke checks

**Purpose:** After `docker compose up` (or a local `uvicorn`), confirm the API is
alive and the demo catalog is reachable with the sandbox key.

**Software status:** in-repo work is **software-complete**; operational label
remains **`staging-ready`** (no production SLA).

## Prerequisites

- API listening (default `http://127.0.0.1:8000`)
- `curl` available; `jq` optional (falls back to `python3`)
- Demo key `zenith_demo_key_layers_read` (default seed) **or** override
  `ZENITH_API_KEY`

## Run

```bash
# From repo root — stack already up:
docker compose --env-file compose.env.sample up --build -d
./scripts/compose_smoke.sh

# Custom base / key:
ZENITH_API_BASE=http://127.0.0.1:8000 \
ZENITH_API_KEY=zenith_demo_key_layers_read \
  ./scripts/compose_smoke.sh
```

## What it checks

| Step | Request | Expect |
|------|---------|--------|
| 1 | `GET /healthz` | JSON `status` is `ok` or `degraded` |
| 2 | `GET /api/v1` | `readiness` = `staging-ready` (+ prints `package_version`) |
| 3 | `GET /api/v1/layers` + `X-API-Key` | `count` ≥ 1 |

Exit code `0` = pass; non-zero = fail (script prints the body on failure).

## Related

- Deeper acceptance client: `examples/third_party_client.py`
- Ops runbook (store): health section + external-infra leftovers
- In-process CI: `pytest` (`tests/test_api.py`) — does not replace this live smoke

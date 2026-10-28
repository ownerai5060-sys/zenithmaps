#!/usr/bin/env bash
# Compose / staging smoke: healthz + /api/v1 meta + layers with demo key.
#
# Usage (API already up, e.g. docker compose):
#   ./scripts/compose_smoke.sh
#   ZENITH_API_BASE=http://127.0.0.1:8000 ./scripts/compose_smoke.sh
#
# Env:
#   ZENITH_API_BASE   default http://127.0.0.1:8000
#   ZENITH_API_KEY    default zenith_demo_key_layers_read (demo stub only)
#
# Exit 0 on success; non-zero on HTTP/JSON/contract failure.
set -euo pipefail

BASE="${ZENITH_API_BASE:-http://127.0.0.1:8000}"
BASE="${BASE%/}"
KEY="${ZENITH_API_KEY:-zenith_demo_key_layers_read}"

have_jq=0
if command -v jq >/dev/null 2>&1; then
  have_jq=1
fi

json_field() {
  # json_field <json> <key> — best-effort without requiring jq
  local json="$1"
  local key="$2"
  if [[ "$have_jq" -eq 1 ]]; then
    printf '%s' "$json" | jq -r --arg k "$key" '.[$k] // empty'
    return
  fi
  python3 - "$json" "$key" <<'PY'
import json, sys
doc = json.loads(sys.argv[1])
key = sys.argv[2]
val = doc.get(key, "")
if isinstance(val, (dict, list)):
    print(json.dumps(val))
else:
    print(val if val is not None else "")
PY
}

http_get() {
  local url="$1"
  shift
  curl -fsS --max-time 15 "$@" "$url"
}

echo "== smoke against ${BASE} =="

echo "-- GET /healthz"
health_json="$(http_get "${BASE}/healthz")"
health_status="$(json_field "$health_json" status)"
if [[ "$health_status" != "ok" && "$health_status" != "degraded" ]]; then
  echo "FAIL: unexpected health status: ${health_status:-<empty>}" >&2
  echo "$health_json" >&2
  exit 1
fi
echo "health status=${health_status}"

echo "-- GET /api/v1"
meta_json="$(http_get "${BASE}/api/v1")"
readiness="$(json_field "$meta_json" readiness)"
pkg="$(json_field "$meta_json" package_version)"
if [[ "$readiness" != "staging-ready" ]]; then
  echo "FAIL: expected readiness=staging-ready, got: ${readiness:-<empty>}" >&2
  echo "$meta_json" >&2
  exit 1
fi
echo "readiness=${readiness} package_version=${pkg}"

echo "-- GET /api/v1/layers (X-API-Key demo)"
layers_json="$(
  http_get "${BASE}/api/v1/layers" -H "X-API-Key: ${KEY}"
)"
count="$(json_field "$layers_json" count)"
if [[ -z "$count" || "$count" == "null" ]]; then
  echo "FAIL: layers response missing count" >&2
  echo "$layers_json" >&2
  exit 1
fi
# integer compare — count must be >= 1
if ! [[ "$count" =~ ^[0-9]+$ ]] || [[ "$count" -lt 1 ]]; then
  echo "FAIL: expected layers count >= 1, got: ${count}" >&2
  echo "$layers_json" >&2
  exit 1
fi
echo "layers count=${count}"

echo "OK — compose smoke passed (healthz + meta + layers)"

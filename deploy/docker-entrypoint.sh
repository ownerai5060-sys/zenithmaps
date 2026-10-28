#!/bin/sh
# Optional PostGIS migrate before starting the API process.
set -e
if [ "${ZENITH_MIGRATE_ON_START:-false}" = "true" ] \
   && [ -n "${ZENITH_DATABASE_URL:-}" ]; then
  echo "zenith: applying pending SQL migrations..."
  python -m api.migrate || {
    echo "zenith: migrate failed (continuing only if you unset ZENITH_MIGRATE_ON_START)" >&2
    exit 1
  }
fi
exec "$@"

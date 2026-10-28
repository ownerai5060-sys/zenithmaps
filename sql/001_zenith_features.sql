-- Zenith WFS-lite PostGIS schema (optional)
-- Apply when ZENITH_DATABASE_URL points at a PostGIS-enabled database.
-- Table name must match ZENITH_FEATURES_TABLE (default: zenith_features).
--
-- Requires: PostgreSQL 12+ with PostGIS 3.x
-- Risk: creates objects only; does not drop or migrate existing data.
-- Rollback: DROP TABLE IF EXISTS zenith_features; DROP INDEX IF EXISTS ...

CREATE EXTENSION IF NOT EXISTS postgis;

CREATE TABLE IF NOT EXISTS zenith_features (
    id          TEXT PRIMARY KEY,
    layer_id    TEXT NOT NULL,
    geom        geometry(Geometry, 4326) NOT NULL,
    properties  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_zenith_features_layer
    ON zenith_features (layer_id);

CREATE INDEX IF NOT EXISTS idx_zenith_features_geom
    ON zenith_features USING GIST (geom);

COMMENT ON TABLE zenith_features IS
    'WFS-lite source for GET /api/v1/layers/{id}/features (backend=postgis)';

-- Example seed (optional; remove in production):
-- INSERT INTO zenith_features (id, layer_id, geom, properties) VALUES
--   ('sample-1', 'esa-worldcover-2020',
--    ST_SetSRID(ST_MakePoint(51.3890, 35.6892), 4326),
--    '{"class":"Built-up","note":"Tehran sample"}'::jsonb);

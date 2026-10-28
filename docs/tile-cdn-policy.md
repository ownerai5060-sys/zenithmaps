# Zenith tile CDN policy (stub)

**Status:** documented policy only — **no Zenith-operated WMTS/XYZ CDN**.

## Rules

1. Zenith Maps API **does not** host, proxy, or invent open public tile CDN
   endpoints. Clients fetch upstream tile URLs themselves.
2. Catalog layers may expose an allowlisted `tile_url_template` via
   `GET /api/v1/tiles` (same host allowlist as WMS: `ZENITH_WMS_ALLOWED_HOSTS`).
3. Optional partner / edge CDN bases may be **documented and allowlisted** with:

   ```bash
   export ZENITH_TILE_CDN_BASE_URLS="https://tiles.partner.example,https://cdn.example.net"
   ```

   Hosts from these bases are treated as allowlisted for tile metadata only.
   Setting this env does **not** stand up CDN infrastructure.

4. Production tile delivery (if required) remains an ops concern outside this
   repository (vendor CDN, MapProxy, etc.).

## API surface

`GET /api/v1/tiles` returns `cdn_policy`:

```json
{
  "zenith_hosts_tiles": false,
  "allowlisted_cdn_base_urls": [],
  "env_var": "ZENITH_TILE_CDN_BASE_URLS",
  "notes": "..."
}
```

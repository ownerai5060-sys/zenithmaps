# Webhook egress proxy / allowlist sidecar

**Status:** sample + ops notes — not a managed production egress product.

Zenith already validates webhook URLs in-process (`api/security/webhook_egress.py`):

* soft SSRF blocks (private / loopback / link-local / cloud metadata)
* optional host allowlist via `ZENITH_WEBHOOK_ALLOWED_HOSTS`

That still runs **inside** the API process. DNS rebinding and “call anything
public then pivot” risks are better closed with a **network egress control**:
only the allowlisted hosts are reachable from the worker/API network path.

## Recommended layers (defense in depth)

| Layer | What | Where |
|-------|------|--------|
| 1 | Soft SSRF + optional host allowlist | App (`ZENITH_WEBHOOK_ALLOWED_HOSTS`) — always set in prod |
| 2 | Allowlist forward proxy / sidecar | Compose profile `egress` or your mesh |
| 3 | Cloud / K8s NetworkPolicy / firewall | Deny egress except proxy + deps |

Zenith does **not** ship a multi-tenant managed egress gateway. Use your
platform’s egress proxy when you need SLA, audit logs, and rebinding guarantees.

## Simple allowlist sidecar (this repo)

Path: `deploy/egress-allowlist/`

* Tiny Python forward proxy (HTTP absolute-URI + HTTPS `CONNECT`)
* `EGRESS_ALLOWED_HOSTS` — comma-separated hostnames
* After DNS resolve, rejects private / loopback / link-local / metadata IPs
  (basic DNS-rebinding guard for allowlisted names)

### Compose

```bash
# 1) Put partner webhook hosts in compose.env
EGRESS_ALLOWED_HOSTS=hooks.partner.example
ZENITH_WEBHOOK_ALLOWED_HOSTS=hooks.partner.example
HTTP_PROXY=http://egress-allowlist:8888
HTTPS_PROXY=http://egress-allowlist:8888
NO_PROXY=redis,postgis,otel-collector,localhost,127.0.0.1

# 2) Start with the egress profile
docker compose --env-file compose.env --profile egress up --build
```

`httpx` (used for webhook delivery) honors `HTTP_PROXY` / `HTTPS_PROXY` when
`trust_env` is left at its default (`True`). Keep Redis/PostGIS/OTel on
`NO_PROXY` so internal traffic does not go through the sidecar.

### Standalone

```bash
cd deploy/egress-allowlist
EGRESS_ALLOWED_HOSTS=hooks.partner.example python proxy.py
# listen default: 0.0.0.0:8888
```

## What this does **not** replace

* Production IdP, managed Redis, real OTel backends, tile CDN, managed queue
* Full DNS-rebinding-safe enterprise gateways (pin IPs, mTLS, per-tenant ACLs)
* App-level allowlist — still set `ZENITH_WEBHOOK_ALLOWED_HOSTS` in prod

## Rollback

Stop the `egress` profile / unset `HTTP(S)_PROXY`. Webhooks fall back to direct
egress with only the in-app soft SSRF + allowlist checks.

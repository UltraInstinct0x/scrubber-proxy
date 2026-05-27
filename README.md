# scrubber-proxy v0.5.0

PII/secret scrubber HTTP service. Regex + dictionary. No LLM, no hallucinated detections. Reversible by design (encrypted sqlite mapping store). Clustered, authenticated, metered.

Consumer #1: [panel](https://panel.goku.codes) — sanitizes technical-pool unit bodies before they leave to raters.

## what it does

POST text or an agent trace; returns the same body with PII/secrets replaced by typed tokens (`<EMAIL_1>`, `<PHONE_1>`, `<TCKN_1>`, ...). Optionally reversible if you pass `reversible: true` — get back a `mapping_id`, store it, later POST `/reverse` to recover the original.

## what it doesn't do (v0)

- **not magic.** regex + dictionary recall, not 100%. treat as defense-in-depth, not a guarantee.
- **no NLP / NER.** doesn't catch novel name patterns or context-dependent PII. add a rule pack or post-process if you need that.
- **no irreversibility.** mappings are stored encrypted under a static env key. that's a *feature* for audit/legal-hold, document it honestly to your buyers.
- **symmetric HS256 key management only.** v0.5 adds `kid` rotation with env-managed keys; KMS-backed key management remains future work.

## attestation tokens (v0.2)

Every `/scrub` (and `/v1/scrub`) response includes a short-lived HS256 JWT bound to the sanitized output. Consumers (e.g. panel ingest) verify it to prove "this payload went through the scrubber".

Token payload:

```json
{ "jti":"<hex16>", "iat":1234567890, "exp":1234568190,
  "input_hash":"<sha256(input_raw)>",
  "output_hash":"<sha256(sanitized_output)>",
  "mode":"text|trace",
  "engine_version":"0.3.0" }
```

Signing key: `SCRUBBER_JWT_SECRET` (HS256, 32 bytes hex). Lives in `~/.secrets/scrubber.env` (600). Consumers share the same secret in their own env. TTL: 300s.

Verification roundtrip: `GET /v1/attestations/:jti` → `{jti, iat, exp, input_hash, output_hash, mode, engine_version, valid}`.

The `output_hash` is the critical bit — without checking it on the consumer side, the JWT degrades into a generic bearer token replayable across any payload.

## v0.5.0 — enterprise upgrades

What's new in v0.5.0:

### clustering
- `node:cluster` stdlib, one worker per CPU core
- Primary process handles health/management; workers handle requests
- DB migrations, GC, and attestation cleanup run in primary only
- Graceful worker restart on `SIGTERM`

### api key auth
- All endpoints (except `/health` and `/metrics`) require `x-scrubber-key` header
- Set via `SCRUBBER_API_KEY` env var
- Bypass with `SCRUBBER_AUTH=none` for local dev
- Adds tenant-aware store isolation via `x-tenant-id` and `/admin/tenants` lifecycle endpoints

### rate limiting
- Token bucket per source IP (configurable)
- Default: 1000 req/s burst 2000
- Returns `429 Too Many Requests` with `Retry-After` header
- CIDR bypass list via `SCRUBBER_RATE_LIMIT_BYPASS_CIDR`
- Per-tenant rate-limit policy metadata accepted on tenant creation (enforcement can be layered later)

### structured logging
- pino JSON lines to stdout
- Every request logged with: `request_id`, `method`, `path`, `duration_ms`, `status`
- Configurable level via `SCRUBBER_LOG_LEVEL` (default: `info`)
- `request_id` propagated from `x-request-id` header or auto-generated

### prometheus metrics
- `GET /metrics` returns prometheus-text format counters + histograms
- Preserved: `scrub_requests_total` (for dashboard continuity)
- New: `scrub_duration_ms` (histogram), `active_connections`, `errors_total`
- Existing panel dashboards unaffected

## endpoints

| method | path | auth | purpose |
|---|---|---|---|
| GET | `/health` | no | liveness + worker_id + version + loaded packs |
| GET | `/metrics` | no | prometheus-text metrics |
| GET | `/rules` | yes | list available rule packs + counts |
| POST | `/scrub?rules=base,medical,tr` | yes | scrub `{text}` or `{trace:[{role,content}]}` (alias: `/v1/scrub`) |
| POST | `/proxy?rules=base&target=<url>` | yes | HTTP reverse proxy with request/response scrubbing |
| GET | `/ws?rules=base&target=<ws-url>` | yes (upgrade) | bidirectional WebSocket text-frame scrubbing |
| GET | `/v1/attestations/:jti` | yes | look up a previously-issued attestation |
| GET | `/v1/jwks.json` | yes | returns symmetric-key metadata (`kid`, `alg`, `kty`, `use`) without exposing secret bytes |
| POST | `/reverse` | yes | `{mapping_id, token}` → `{original}` |
| POST | `/admin/tenants` | yes + admin | create tenant store directory + sqlite DB |
| GET | `/admin/tenants` | yes + admin | list tenants |
| DELETE | `/admin/tenants/:id` | yes + admin | delete tenant store directory (requires confirmation header) |
| GET | `/v1/audit/verify[?tenant=acme]` | yes | verify audit hash chain integrity |
| GET | `/v1/audit?...` | yes + admin | paginated admin audit query |
| GET | `/v1/audit/export?...` | yes + admin | CSV audit export |

### example

```bash
curl -s -X POST http://127.0.0.1:3017/scrub?rules=base,tr \
  -H 'content-type: application/json' \
  -H 'x-scrubber-key: sk-your-key-here' \
  -d '{"text":"call +90 532 555 1234 or jane@example.com. tc: 10000000146"}'
```

Response:

```json
{
  "text": "call <PHONE_TR_1> or <EMAIL_1>. tc: <TCKN_1>",
  "detections": [...],
  "rules_applied": ["base", "tr"],
  "engine_version": "0.3.0",
  "mapping_id": null,
  "attestation": "<jwt>"
}
```

## rule packs

JSON files under `rules/`. Each rule:

```json
{ "token": "EMAIL", "pattern": "<regex>", "flags": "g", "validator": "luhn|tckn|iban_mod97" }
```

Add a pack by dropping a new `rules/<name>.json` and restarting the service. Request with `?rules=<name>` (or compose: `?rules=base,medical,eu`).

Built-in packs:

- `base` — email, phone, credit card (luhn-validated), IPv4, bearer tokens, PEM keys, OpenAI/AWS key shapes.
- `eu` — IBAN (mod-97), EU country codes, UK NIN.
- `tr` — TC Kimlik No (checksum-validated), Turkish mobile.
- `medical` — ICD-10/NDC/MRN code shapes (TODO: full ICD-10 prefix table from CMS).

## configuration

All via environment variables:

| var | default | description |
|---|---|---|
| `SCRUBBER_PORT` | `3017` | listen port |
| `SCRUBBER_HOST` | `127.0.0.1` | listen address |
| `SCRUBBER_API_KEY` | — | required for auth (unless `SCRUBBER_AUTH=none`) |
| `SCRUBBER_ADMIN_KEY` | — | required for `/admin/*` and admin audit endpoints |
| `SCRUBBER_AUTH` | `required` | `required` or `none` (bypass all auth) |
| `SCRUBBER_JWT_SECRET` | — | HS256 signing key (32 bytes hex) |
| `SCRUBBER_JWT_PRIMARY_KEY` | — | primary HS256 signing key for new attestations (`kid=hs256-primary`) |
| `SCRUBBER_JWT_VERIFICATION_KEYS` | — | comma-separated `kid:secret` pairs for verifier keyring and no-`kid` fallback |
| `SCRUBBER_REVERSAL_KEY` | — | AES-256-GCM mapping encryption key |
| `SCRUBBER_RATE_LIMIT_RPS` | `1000` | requests per second per IP |
| `SCRUBBER_RATE_LIMIT_BURST` | `2000` | burst window |
| `SCRUBBER_RATE_LIMIT_BYPASS_CIDR` | — | comma-separated CIDRs (e.g. `10.0.0.0/8,192.168.0.0/16`) |
| `SCRUBBER_LOG_LEVEL` | `info` | pino level (`trace`, `debug`, `info`, `warn`, `error`, `fatal`) |
| `SCRUBBER_DATA_DIR` | `./data` | sqlite mapping store location |
| `SCRUBBER_CLUSTER_WORKERS` | auto | number of workers (default: cpu count) |
| `SCRUBBER_UPSTREAM_TIMEOUT` | `30000` | upstream HTTP timeout in ms for `/proxy` |
| `SCRUBBER_CONNECTION_TIMEOUT` | `5000` | connection timeout in ms for upstream WS handshake |
| `SCRUBBER_PROXY_ALLOW_PRIVATE` | `false` | allow private/loopback targets (dev/testing only) |
| `SCRUBBER_WS_MAX_CONNECTIONS` | `500` | max active `/ws` proxied connections |
| `SCRUBBER_AUDIT_ENABLED` | `true` | enables append-only audit logging |
| `SCRUBBER_AUDIT_BUFFER` | `0` | audit batch size (`0` = synchronous write per event) |
| `SCRUBBER_AUDIT_RETENTION_DAYS` | `90` | prune audit rows older than N days during maintenance |

## fail-closed contract for panel

panel's `/api/units/next` does not serve a `pool=technical` unit if `SCRUBBER_URL` is set and the scrubber call fails. There is no "scrub locally, trust me" path.

## deploy

```bash
# via systemd-user on the goku.codes host
systemctl --user daemon-reload
systemctl --user enable --now scrubber
curl -s http://127.0.0.1:3017/health

# push to main deploys automatically via self-hosted runner
git push origin main
```

Public via nginx: `~/bin/add-vhost.sh scrubber 3017` → https://scrubber.goku.codes

## self-host

See `~/panel/deploy/docker-compose.yml` — brings up panel + scrubber side-by-side. Operators bring their own ingress.

## roadmap

- [x] attestation jwts (v0.2)
- [x] landing page at scrubber.goku.codes (v0.2)
- [x] auto-deploy via self-hosted runner (v0.2–0.3)
- [x] clustering, auth, rate limiting, structured logging, prom metrics (v0.3)
- [x] HTTP reverse proxy (`/proxy`) — drop scrubber in front of any API (v0.4)
- [x] WebSocket proxy (`/ws`) — bidirectional real-time scrubbing (v0.4)
- [x] KMS-prep key rotation (`kid` + keyring), multi-tenant stores, audit hash chain (v0.5)
- [ ] OpenAPI spec + batch endpoint + JS/Python SDKs (v0.6)
- [ ] presidio NER long-tail
- [ ] image subpipeline (EXIF strip + face blur + OCR rescrub)
- [ ] TR address heuristics, full ICD-10 prefix list

## repo

[github.com/UltraInstinct0x/scrubber-proxy](https://github.com/UltraInstinct0x/scrubber-proxy)

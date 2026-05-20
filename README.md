# scrubber-proxy v0

PII/secret scrubber HTTP service. Regex + dictionary. No LLM, no hallucinated detections. Reversible by design (encrypted sqlite mapping store).

Consumer #1: [panel](https://panel.goku.codes) — sanitizes technical-pool unit bodies before they leave to raters.

## what it does

POST text or an agent trace; returns the same body with PII/secrets replaced by typed tokens (`<EMAIL_1>`, `<PHONE_1>`, `<TCKN_1>`, ...). Optionally reversible if you pass `reversible: true` — get back a `mapping_id`, store it, later POST `/reverse` to recover the original.

## what it doesn't do (v0)

- **not magic.** regex + dictionary recall, not 100%. treat as defense-in-depth, not a guarantee.
- **no NLP / NER.** doesn't catch novel name patterns or context-dependent PII. add a rule pack or post-process if you need that.
- **no irreversibility.** mappings are stored encrypted under a static env key. that's a *feature* for audit/legal-hold, document it honestly to your buyers.
- **single env key, no rotation.** PoC-grade. swap in KMS for v1.

## attestation tokens (v0.2)

every `/scrub` (and `/v1/scrub`) response now includes a short-lived HS256 JWT bound to the sanitized output. consumers (e.g. panel ingest) verify it to prove "this payload went through the scrubber".

token payload:

```json
{ "jti":"<hex16>", "iat":1234567890, "exp":1234568190,
  "input_hash":"<sha256(input_raw)>",
  "output_hash":"<sha256(sanitized_output)>",
  "mode":"text|trace",
  "engine_version":"0.2.0" }
```

signing key: `SCRUBBER_JWT_SECRET` (HS256, 32 bytes hex). lives in `~/.secrets/scrubber.env` (600). consumers share the same secret in their own env. ttl: 300s.

verification roundtrip: `GET /v1/attestations/:jti` → `{jti, iat, exp, input_hash, output_hash, mode, engine_version, valid}`.

the `output_hash` is the critical bit — without checking it on the consumer side, the JWT degrades into a generic bearer token replayable across any payload.

## endpoints

| method | path | purpose |
|---|---|---|
| GET | `/health` | liveness + version + loaded packs |
| GET | `/rules` | list available rule packs + counts |
| POST | `/scrub?rules=base,medical,tr` | scrub `{text}` or `{trace:[{role,content}]}` (alias: `/v1/scrub`) |
| GET | `/v1/attestations/:jti` | look up a previously-issued attestation |
| POST | `/reverse` | `{mapping_id, token}` → `{original}` |

### example

```bash
curl -s -X POST http://127.0.0.1:3017/scrub?rules=base,tr \
  -H 'content-type: application/json' \
  -d '{"text":"call +90 532 555 1234 or jane@example.com. tc: 10000000146"}'
```

response:

```json
{
  "text": "call <PHONE_TR_1> or <EMAIL_1>. tc: <TCKN_1>",
  "detections": [...],
  "rules_applied": ["base", "tr"],
  "engine_version": "0.1.0",
  "mapping_id": null
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

## fail-closed contract for panel

panel's `/api/units/next` does not serve a `pool=technical` unit if `SCRUBBER_URL` is set and the scrubber call fails. there is no "scrub locally, trust me" path.

## deploy

systemd-user on the goku.codes host:

```bash
systemctl --user daemon-reload
systemctl --user enable --now scrubber
curl -s http://127.0.0.1:3017/health
```

Public via nginx: `~/bin/add-vhost.sh scrubber 3017` → https://scrubber.goku.codes

## self-host

See `~/panel/deploy/docker-compose.yml` — brings up panel + scrubber side-by-side. Operators bring their own ingress.

## roadmap

- attestation jwt (per `Scrubber Proxy Design.md`)
- presidio NER long-tail
- image subpipeline (EXIF strip + face blur + OCR rescrub)
- batch endpoint + webhook
- KMS key rotation
- TR address heuristics, full ICD-10 prefix list

## repo

Standalone dir on host (`~/scrubber-proxy/`) for v0. Will graduate to `github.com/UltraInstinct0x/scrubber-proxy` when it stabilizes (target: v0.2 with attestation jwt).

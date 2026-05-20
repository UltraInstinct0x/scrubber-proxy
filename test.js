#!/usr/bin/env node
// minimal integration test for scrubber-proxy v0.2 — attestation JWT issuance + verify roundtrip.
'use strict';

const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const SECRET = 'a'.repeat(64);
const PORT = 13917 + Math.floor(Math.random() * 100);
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'scrubber-test-'));

function req(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const r = http.request(
      { host: '127.0.0.1', port: PORT, path: urlPath, method, headers: data ? { 'content-type': 'application/json', 'content-length': data.length } : {} },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); } catch { resolve({ status: res.statusCode, body: raw }); }
        });
      },
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

function b64uDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

(async () => {
  const proc = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1', SCRUBBER_JWT_SECRET: SECRET, SCRUBBER_DATA_DIR: TMP },
    stdio: ['ignore', 'inherit', 'inherit'],
  });
  // wait for listen
  for (let i = 0; i < 50; i++) {
    await new Promise((r) => setTimeout(r, 100));
    try { const h = await req('GET', '/health'); if (h.status === 200) break; } catch {}
  }
  let failed = 0;
  function assert(cond, msg) { if (!cond) { console.error('FAIL', msg); failed++; } else { console.log('ok  ', msg); } }
  try {
    const r = await req('POST', '/v1/scrub?rules=base', { text: 'hi jane@example.com' });
    assert(r.status === 200, '/v1/scrub returns 200');
    assert(typeof r.body.attestation === 'string' && r.body.attestation.split('.').length === 3, 'attestation is a JWT');
    assert(r.body.attestation_meta && /^[a-f0-9]{32}$/.test(r.body.attestation_meta.jti), 'jti format');

    // verify signature
    const [h, p, s] = r.body.attestation.split('.');
    const expected = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest();
    const got = b64uDecode(s);
    assert(expected.equals(got), 'HS256 signature verifies');

    // output_hash matches actual sanitized text
    const sanitized = r.body.text;
    const oh = crypto.createHash('sha256').update(sanitized).digest('hex');
    assert(oh === r.body.attestation_meta.output_hash, 'output_hash matches sanitized text');

    // attestation lookup endpoint
    const g = await req('GET', `/v1/attestations/${r.body.attestation_meta.jti}`);
    assert(g.status === 200 && g.body.valid === true, 'GET /v1/attestations/:jti returns valid');
    assert(g.body.output_hash === oh, 'attestation row output_hash matches');

    // bad jti
    const bad = await req('GET', '/v1/attestations/deadbeef');
    assert(bad.status === 400, 'bad jti rejected with 400');
  } finally {
    proc.kill('SIGTERM');
  }
  if (failed > 0) { console.error(`\n${failed} failed`); process.exit(1); }
  console.log('\nall green');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });

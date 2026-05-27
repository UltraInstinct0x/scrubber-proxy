#!/usr/bin/env node
'use strict';

const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { WebSocketServer, WebSocket } = require('ws');

const LEGACY_SECRET = 'a'.repeat(64);
const PRIMARY_SECRET = 'b'.repeat(64);
const API_KEY = 'test-key';
const ADMIN_KEY = 'admin-key';
const PORT = 13917 + Math.floor(Math.random() * 100);
const UPSTREAM_HTTP_PORT = PORT + 200;
const UPSTREAM_WS_PORT = PORT + 400;
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'scrubber-test-'));

function req(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body ? Buffer.from(JSON.stringify(body)) : null;
    const headers = {
      'x-scrubber-key': API_KEY,
      ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}),
    };
    const r = http.request(
      { host: '127.0.0.1', port: PORT, path: urlPath, method, headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          try { resolve({ status: res.statusCode, body: JSON.parse(raw), headers: res.headers }); } catch { resolve({ status: res.statusCode, body: raw, headers: res.headers }); }
        });
      },
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

function wsRoundtrip(url, text) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { headers: { 'x-scrubber-key': API_KEY } });
    ws.once('open', () => ws.send(text));
    ws.once('message', (msg) => {
      resolve(msg.toString('utf8'));
      ws.close();
    });
    ws.once('error', reject);
  });
}

function b64uDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function jwtHeader(token) {
  const [h] = token.split('.');
  return JSON.parse(b64uDecode(h).toString('utf8'));
}

function jwtVerifyWith(token, secret) {
  const [h, p, s] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest();
  const got = b64uDecode(s);
  return expected.equals(got);
}

(async () => {
  const upstreamHttp = http.createServer((reqIn, resIn) => {
    const chunks = [];
    reqIn.on('data', (c) => chunks.push(c));
    reqIn.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      resIn.setHeader('content-type', 'application/json');
      resIn.end(JSON.stringify({ got: raw, upstream_note: 'reply from jane@example.com' }));
    });
  });
  await new Promise((resolve) => upstreamHttp.listen(UPSTREAM_HTTP_PORT, '127.0.0.1', resolve));

  const upstreamWsServer = new WebSocketServer({ port: UPSTREAM_WS_PORT, host: '127.0.0.1' });
  upstreamWsServer.on('connection', (socket) => {
    socket.on('message', (data, isBinary) => {
      socket.send(data, { binary: isBinary });
    });
  });

  const proc = spawn(process.execPath, [path.join(__dirname, 'server.js')], {
    env: {
      ...process.env,
      PORT: String(PORT),
      HOST: '127.0.0.1',
      SCRUBBER_JWT_SECRET: LEGACY_SECRET,
      SCRUBBER_JWT_PRIMARY_KEY: PRIMARY_SECRET,
      SCRUBBER_JWT_VERIFICATION_KEYS: `hs256-legacy:${LEGACY_SECRET},hs256-primary:${PRIMARY_SECRET}`,
      SCRUBBER_DATA_DIR: TMP,
      SCRUBBER_API_KEY: API_KEY,
      SCRUBBER_ADMIN_KEY: ADMIN_KEY,
      SCRUBBER_AUDIT_ENABLED: 'true',
      SCRUBBER_PROXY_ALLOW_PRIVATE: 'true',
      SCRUBBER_CLUSTER_WORKERS: '1',
    },
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

    assert(jwtHeader(r.body.attestation).kid === 'hs256-primary', 'new attestations include hs256-primary kid');
    assert(jwtVerifyWith(r.body.attestation, PRIMARY_SECRET), 'HS256 primary signature verifies');

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

    const proxyReq = await req(
      'POST',
      `/proxy?rules=base&scrub_response=true&target=${encodeURIComponent(`http://127.0.0.1:${UPSTREAM_HTTP_PORT}/echo`)}`,
      { text: 'contact me at jane@example.com', reversible: true },
    );
    assert(proxyReq.status === 200, '/proxy returns 200');
    assert(typeof proxyReq.body.got === 'string' && proxyReq.body.got.includes('<EMAIL_1>'), '/proxy scrubs outbound request body');
    assert(proxyReq.body.upstream_note.includes('<EMAIL_1>'), '/proxy scrubs inbound response body when scrub_response=true');
    assert(typeof proxyReq.headers['x-scrubber-attestation'] === 'string', '/proxy sets x-scrubber-attestation');
    assert(typeof proxyReq.headers['x-scrub-mapping-id-req'] === 'string', '/proxy sets x-scrub-mapping-id-req in reversible mode');
    assert(typeof proxyReq.headers['x-scrub-mapping-id-res'] === 'string', '/proxy sets x-scrub-mapping-id-res when response scrubbed in reversible mode');

    const wsUrl = `ws://127.0.0.1:${PORT}/ws?rules=base&target=${encodeURIComponent(`ws://127.0.0.1:${UPSTREAM_WS_PORT}`)}`;
    const wsResult = await wsRoundtrip(wsUrl, 'ws email jane@example.com');
    assert(wsResult.includes('<EMAIL_1>'), '/ws scrubs text frame in bidirectional flow');

    const jwks = await req('GET', '/v1/jwks.json');
    assert(jwks.status === 200, '/v1/jwks.json returns 200');
    assert(Array.isArray(jwks.body.keys) && jwks.body.keys.some((k) => k.kid === 'hs256-primary') && jwks.body.keys.some((k) => k.kid === 'hs256-legacy'), 'jwks exposes both kids without k');
    assert(!JSON.stringify(jwks.body).includes('"k"'), 'jwks does not expose symmetric key bytes');

    const noAdmin = await new Promise((resolve, reject) => {
      const data = Buffer.from(JSON.stringify({ tenant_id: 'acme', allowed_rules: ['base'], rate_limit_rps: 500 }));
      const rq = http.request({ host: '127.0.0.1', port: PORT, path: '/admin/tenants', method: 'POST', headers: { 'x-scrubber-key': API_KEY, 'content-type': 'application/json', 'content-length': data.length } }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      rq.on('error', reject);
      rq.write(data);
      rq.end();
    });
    assert(noAdmin.status === 401, 'POST /admin/tenants with wrong admin key returns 401');

    const mkTenant = await new Promise((resolve, reject) => {
      const payload = { tenant_id: 'acme', allowed_rules: ['base', 'eu', 'medical'], rate_limit_rps: 500 };
      const data = Buffer.from(JSON.stringify(payload));
      const rq = http.request({ host: '127.0.0.1', port: PORT, path: '/admin/tenants', method: 'POST', headers: { 'x-scrubber-key': API_KEY, 'x-scrubber-admin-key': ADMIN_KEY, 'content-type': 'application/json', 'content-length': data.length } }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
      });
      rq.on('error', reject);
      rq.write(data);
      rq.end();
    });
    assert(mkTenant.status === 201 && mkTenant.body.tenant_id === 'acme', 'POST /admin/tenants with admin key creates tenant');
    assert(fs.existsSync(path.join(TMP, 'tenants', 'acme', 'mappings.db')), 'tenant sqlite file created on disk');

    const tenantReq = (method, urlPath, body) => new Promise((resolve, reject) => {
      const data = body ? Buffer.from(JSON.stringify(body)) : null;
      const headers = { 'x-scrubber-key': API_KEY, 'x-tenant-id': 'acme', ...(data ? { 'content-type': 'application/json', 'content-length': data.length } : {}) };
      const rq = http.request({ host: '127.0.0.1', port: PORT, path: urlPath, method, headers }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          try { resolve({ status: res.statusCode, body: JSON.parse(raw), headers: res.headers }); } catch { resolve({ status: res.statusCode, body: raw, headers: res.headers }); }
        });
      });
      rq.on('error', reject);
      if (data) rq.write(data);
      rq.end();
    });

    const tenantScrub = await tenantReq('POST', '/scrub?rules=base', { text: 'tenant jane@example.com', reversible: true });
    assert(tenantScrub.status === 200 && typeof tenantScrub.body.mapping_id === 'string', 'tenant scrub creates tenant-scoped mapping');
    const reverseDefault = await req('POST', '/reverse', { mapping_id: tenantScrub.body.mapping_id, token: '<EMAIL_1>' });
    assert(reverseDefault.status === 404, '/reverse without tenant does not see tenant mapping');
    const reverseTenant = await tenantReq('POST', '/reverse', { mapping_id: tenantScrub.body.mapping_id, token: '<EMAIL_1>' });
    assert(reverseTenant.status === 200 && reverseTenant.body.original === 'jane@example.com', '/reverse with tenant can resolve mapping');

    const auditVerify = await req('GET', '/v1/audit/verify');
    assert(auditVerify.status === 200 && auditVerify.body.valid === true, '/v1/audit/verify is valid on clean chain');

    const adb = new (require('better-sqlite3'))(path.join(TMP, 'audit.db'));
    adb.prepare("UPDATE audit_events SET metadata = '{\"tampered\":true}' WHERE seq = (SELECT MIN(seq) FROM audit_events)").run();
    adb.close();
    const auditBroken = await req('GET', '/v1/audit/verify');
    assert(auditBroken.status === 200 && auditBroken.body.valid === false, '/v1/audit/verify detects tampering');

    const auditList = await new Promise((resolve, reject) => {
      const rq = http.request({ host: '127.0.0.1', port: PORT, path: '/v1/audit?limit=5&offset=0', method: 'GET', headers: { 'x-scrubber-key': API_KEY, 'x-scrubber-admin-key': ADMIN_KEY } }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
      });
      rq.on('error', reject);
      rq.end();
    });
    assert(auditList.status === 200 && Array.isArray(auditList.body.events), '/v1/audit returns paginated events');
  } finally {
    proc.kill('SIGTERM');
    upstreamHttp.close();
    upstreamWsServer.close();
  }
  if (failed > 0) { console.error(`\n${failed} failed`); process.exit(1); }
  console.log('\nall green');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });

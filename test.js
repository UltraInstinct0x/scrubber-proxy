#!/usr/bin/env node
// minimal integration test for scrubber-proxy v0.2 — attestation JWT issuance + verify roundtrip.
'use strict';

const http = require('http');
const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { WebSocketServer, WebSocket } = require('ws');

const SECRET = 'a'.repeat(64);
const API_KEY = 'test-key';
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
      SCRUBBER_JWT_SECRET: SECRET,
      SCRUBBER_DATA_DIR: TMP,
      SCRUBBER_API_KEY: API_KEY,
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
  } finally {
    proc.kill('SIGTERM');
    upstreamHttp.close();
    upstreamWsServer.close();
  }
  if (failed > 0) { console.error(`\n${failed} failed`); process.exit(1); }
  console.log('\nall green');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });

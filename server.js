#!/usr/bin/env node
// scrubber-proxy v0 — regex + dictionary PII/secret scrubber.
// no LLM. no hallucinated detections. reversible via encrypted sqlite mapping.

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const PORT = parseInt(process.env.PORT || '3017', 10);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.SCRUBBER_DATA_DIR || path.join(__dirname, 'data');
const RULES_DIR = path.join(__dirname, 'rules');
const REVERSAL_KEY_RAW = process.env.SCRUBBER_REVERSAL_KEY || 'dev-key-do-not-use-in-prod-dev-key-do-not-use-in-prod';
const REVERSAL_KEY = crypto.createHash('sha256').update(REVERSAL_KEY_RAW).digest();
const VERSION = '0.2.0';
const JWT_SECRET = process.env.SCRUBBER_JWT_SECRET || '';
const JWT_TTL_SECONDS = 300;
if (!JWT_SECRET) {
  console.warn('[scrubber] SCRUBBER_JWT_SECRET unset — attestation JWTs disabled');
}

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'mappings.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS mappings (
  mapping_id TEXT NOT NULL,
  token TEXT NOT NULL,
  iv BLOB NOT NULL,
  tag BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (mapping_id, token)
);
CREATE INDEX IF NOT EXISTS idx_mappings_created ON mappings(created_at);
CREATE TABLE IF NOT EXISTS attestations (
  jti TEXT PRIMARY KEY,
  iat INTEGER NOT NULL,
  exp INTEGER NOT NULL,
  input_hash TEXT NOT NULL,
  output_hash TEXT NOT NULL,
  mode TEXT NOT NULL,
  engine_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attestations_exp ON attestations(exp);
`);

// Garbage-collect rows older than 30d
function gc() {
  const cutoff = Math.floor(Date.now() / 1000) - 30 * 86400;
  db.prepare('DELETE FROM mappings WHERE created_at < ?').run(cutoff);
}
setInterval(gc, 6 * 3600 * 1000);

// ---------- rule loading ----------

const RULE_PACKS = {};
function loadRules() {
  for (const f of fs.readdirSync(RULES_DIR)) {
    if (!f.endsWith('.json')) continue;
    const pack = JSON.parse(fs.readFileSync(path.join(RULES_DIR, f), 'utf8'));
    RULE_PACKS[pack.name] = pack;
  }
  console.log('[scrubber] loaded rule packs:', Object.keys(RULE_PACKS).join(','));
}
loadRules();

// ---------- validators ----------

const VALIDATORS = {
  luhn(s) {
    const d = s.replace(/[^0-9]/g, '');
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0, alt = false;
    for (let i = d.length - 1; i >= 0; i--) {
      let n = parseInt(d[i], 10);
      if (alt) { n *= 2; if (n > 9) n -= 9; }
      sum += n; alt = !alt;
    }
    return sum % 10 === 0;
  },
  tckn(s) {
    if (!/^\d{11}$/.test(s)) return false;
    const d = s.split('').map(Number);
    if (d[0] === 0) return false;
    const oddSum = d[0] + d[2] + d[4] + d[6] + d[8];
    const evenSum = d[1] + d[3] + d[5] + d[7];
    const c10 = ((oddSum * 7) - evenSum) % 10;
    const c11 = (oddSum + evenSum + d[9]) % 10;
    return ((c10 + 10) % 10) === d[9] && c11 === d[10];
  },
  iban_mod97(s) {
    const c = s.replace(/\s+/g, '').toUpperCase();
    if (c.length < 15 || c.length > 34) return false;
    const re = c.slice(4) + c.slice(0, 4);
    let num = '';
    for (const ch of re) {
      const code = ch.charCodeAt(0);
      if (code >= 48 && code <= 57) num += ch;
      else if (code >= 65 && code <= 90) num += (code - 55).toString();
      else return false;
    }
    // mod 97 over big number string
    let rem = 0;
    for (const ch of num) rem = (rem * 10 + parseInt(ch, 10)) % 97;
    return rem === 1;
  },
};

// ---------- scrubber core ----------

function scrubText(text, ruleNames, mappingId) {
  if (typeof text !== 'string' || !text) return { text: text || '', detections: [] };
  let out = text;
  const detections = [];
  const counters = {};
  // Run specialized packs before 'base' so narrow validators (TCKN, IBAN) win over greedy PHONE.
  const ordered = [...ruleNames].sort((a, b) => (a === 'base' ? 1 : 0) - (b === 'base' ? 1 : 0));
  for (const name of ordered) {
    const pack = RULE_PACKS[name];
    if (!pack) continue;
    for (const rule of pack.rules) {
      const re = new RegExp(rule.pattern, rule.flags || 'g');
      out = out.replace(re, (match) => {
        if (rule.validator && VALIDATORS[rule.validator] && !VALIDATORS[rule.validator](match)) {
          return match; // skip — failed validator
        }
        counters[rule.token] = (counters[rule.token] || 0) + 1;
        const placeholder = `<${rule.token}_${counters[rule.token]}>`;
        detections.push({ token: placeholder, category: rule.token, pack: name });
        if (mappingId) storeMapping(mappingId, placeholder, match);
        return placeholder;
      });
    }
  }
  return { text: out, detections };
}

function scrubTrace(trace, ruleNames, mappingId) {
  if (!Array.isArray(trace)) return { trace: [], detections: [] };
  const all = [];
  const scrubbed = trace.map((msg) => {
    const r = scrubText(typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content), ruleNames, mappingId);
    all.push(...r.detections);
    return { ...msg, content: r.text };
  });
  return { trace: scrubbed, detections: all };
}

// ---------- mapping (AES-256-GCM, encrypted at rest) ----------

function storeMapping(mappingId, token, original) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', REVERSAL_KEY, iv);
  const ct = Buffer.concat([cipher.update(original, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  db.prepare(
    'INSERT OR REPLACE INTO mappings (mapping_id, token, iv, tag, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(mappingId, token, iv, tag, ct, Math.floor(Date.now() / 1000));
}

function reverseMapping(mappingId, token) {
  const row = db.prepare('SELECT iv, tag, ciphertext FROM mappings WHERE mapping_id = ? AND token = ?').get(mappingId, token);
  if (!row) return null;
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', REVERSAL_KEY, row.iv);
    decipher.setAuthTag(row.tag);
    const pt = Buffer.concat([decipher.update(row.ciphertext), decipher.final()]);
    return pt.toString('utf8');
  } catch (e) {
    return null;
  }
}

// ---------- metrics (prometheus text format, stdlib only) ----------

const METRICS = {
  scrub_requests_total: 0,
  detections_total: new Map(), // key: `${category}|${pack}`
  latency_buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  latency_counts: [], // filled on first read
  latency_sum: 0,
  latency_count: 0,
};
METRICS.latency_counts = new Array(METRICS.latency_buckets.length + 1).fill(0);

function recordLatency(seconds) {
  METRICS.latency_sum += seconds;
  METRICS.latency_count += 1;
  let placed = false;
  for (let i = 0; i < METRICS.latency_buckets.length; i++) {
    if (seconds <= METRICS.latency_buckets[i]) {
      METRICS.latency_counts[i] += 1;
      placed = true;
      break;
    }
  }
  if (!placed) METRICS.latency_counts[METRICS.latency_counts.length - 1] += 1;
}

function recordDetections(detections) {
  for (const d of detections) {
    const k = `${d.category}|${d.pack}`;
    METRICS.detections_total.set(k, (METRICS.detections_total.get(k) || 0) + 1);
  }
}

function escapeLabel(v) {
  return String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function renderMetrics() {
  const lines = [];
  lines.push('# HELP scrub_requests_total Total /scrub requests processed.');
  lines.push('# TYPE scrub_requests_total counter');
  lines.push(`scrub_requests_total ${METRICS.scrub_requests_total}`);

  lines.push('# HELP detections_total Total detections by category and rule pack.');
  lines.push('# TYPE detections_total counter');
  for (const [k, v] of METRICS.detections_total) {
    const [category, pack] = k.split('|');
    lines.push(`detections_total{category="${escapeLabel(category)}",pack="${escapeLabel(pack)}"} ${v}`);
  }

  lines.push('# HELP scrub_latency_seconds Latency of /scrub requests.');
  lines.push('# TYPE scrub_latency_seconds histogram');
  let cum = 0;
  for (let i = 0; i < METRICS.latency_buckets.length; i++) {
    cum += METRICS.latency_counts[i];
    lines.push(`scrub_latency_seconds_bucket{le="${METRICS.latency_buckets[i]}"} ${cum}`);
  }
  cum += METRICS.latency_counts[METRICS.latency_counts.length - 1];
  lines.push(`scrub_latency_seconds_bucket{le="+Inf"} ${cum}`);
  lines.push(`scrub_latency_seconds_sum ${METRICS.latency_sum}`);
  lines.push(`scrub_latency_seconds_count ${METRICS.latency_count}`);

  return lines.join('\n') + '\n';
}

// ---------- attestation JWT (HS256) ----------

function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function issueAttestation({ inputHash, outputHash, mode }) {
  if (!JWT_SECRET) return null;
  const jti = crypto.randomBytes(16).toString('hex');
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + JWT_TTL_SECONDS;
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { jti, iat, exp, input_hash: inputHash, output_hash: outputHash, mode, engine_version: VERSION };
  const signingInput = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(payload))}`;
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(signingInput).digest();
  const token = `${signingInput}.${b64u(sig)}`;
  db.prepare(
    'INSERT OR REPLACE INTO attestations (jti, iat, exp, input_hash, output_hash, mode, engine_version) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(jti, iat, exp, inputHash, outputHash, mode, VERSION);
  return { token, jti, iat, exp };
}
function getAttestation(jti) {
  return db.prepare('SELECT jti, iat, exp, input_hash, output_hash, mode, engine_version FROM attestations WHERE jti = ?').get(jti);
}

// ---------- http server ----------

function send(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function parseRules(url) {
  const q = new URL(url, 'http://x').searchParams.get('rules');
  if (!q) return ['base'];
  const names = q.split(',').map((s) => s.trim()).filter(Boolean);
  return names.length ? names : ['base'];
}

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    if (req.method === 'GET' && u.pathname === '/health') {
      return send(res, 200, { ok: true, version: VERSION, rules: Object.keys(RULE_PACKS) });
    }
    if (req.method === 'GET' && u.pathname === '/rules') {
      const summary = Object.values(RULE_PACKS).map((p) => ({
        name: p.name, version: p.version, description: p.description, rule_count: p.rules.length,
      }));
      return send(res, 200, { packs: summary });
    }
    if (req.method === 'GET' && u.pathname === '/metrics') {
      res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
      return res.end(renderMetrics());
    }
    if (req.method === 'POST' && (u.pathname === '/scrub' || u.pathname === '/v1/scrub')) {
      const body = await readBody(req);
      const rules = parseRules(req.url);
      const wantReversible = body.reversible === true;
      const mappingId = wantReversible ? crypto.randomBytes(12).toString('hex') : null;

      const t0 = process.hrtime.bigint();
      let result;
      let detections;
      let mode;
      let sanitizedPayload;
      if (typeof body.text === 'string') {
        const r = scrubText(body.text, rules, mappingId);
        result = { text: r.text, detections: r.detections };
        detections = r.detections;
        mode = 'text';
        sanitizedPayload = r.text;
      } else if (Array.isArray(body.trace)) {
        const r = scrubTrace(body.trace, rules, mappingId);
        result = { trace: r.trace, detections: r.detections };
        detections = r.detections;
        mode = 'trace';
        sanitizedPayload = JSON.stringify(r.trace);
      } else {
        return send(res, 400, { error: 'body must include {text} or {trace:[]}' });
      }
      const elapsed = Number(process.hrtime.bigint() - t0) / 1e9;
      METRICS.scrub_requests_total += 1;
      recordLatency(elapsed);
      recordDetections(detections);

      // attestation JWT — bind to input + sanitized output hash so it can't be replayed across payloads.
      const inputRaw = typeof body.text === 'string' ? body.text : JSON.stringify(body.trace);
      const inputHash = sha256Hex(inputRaw);
      const outputHash = sha256Hex(sanitizedPayload);
      const att = issueAttestation({ inputHash, outputHash, mode });

      return send(res, 200, {
        ...result,
        rules_applied: rules,
        engine_version: VERSION,
        mapping_id: mappingId,
        mode,
        attestation: att ? att.token : null,
        attestation_meta: att ? { jti: att.jti, iat: att.iat, exp: att.exp, input_hash: inputHash, output_hash: outputHash } : null,
      });
    }
    if (req.method === 'GET' && u.pathname.startsWith('/v1/attestations/')) {
      const jti = u.pathname.slice('/v1/attestations/'.length);
      if (!jti || !/^[a-f0-9]{32}$/.test(jti)) return send(res, 400, { error: 'bad_jti' });
      const row = getAttestation(jti);
      if (!row) return send(res, 404, { error: 'not_found' });
      const now = Math.floor(Date.now() / 1000);
      return send(res, 200, { ...row, valid: row.exp > now });
    }
    if (req.method === 'POST' && u.pathname === '/reverse') {
      const body = await readBody(req);
      if (!body.mapping_id || !body.token) {
        return send(res, 400, { error: 'mapping_id and token required' });
      }
      const original = reverseMapping(body.mapping_id, body.token);
      if (original === null) return send(res, 404, { error: 'not_found' });
      return send(res, 200, { original });
    }
    return send(res, 404, { error: 'not_found' });
  } catch (e) {
    console.error('[scrubber] error', e);
    return send(res, 500, { error: String(e && e.message || e) });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`[scrubber] listening on ${HOST}:${PORT}`);
});

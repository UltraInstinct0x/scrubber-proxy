#!/usr/bin/env node
'use strict';

const cluster = require('cluster');
const os = require('os');
const http = require('http');
const dns = require('dns').promises;
const net = require('net');
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const pino = require('pino');
const { Registry, collectDefaultMetrics, Counter, Histogram, Gauge } = require('prom-client');
const { WebSocket, WebSocketServer } = require('ws');

const logger = pino({ name: 'scrubber-proxy' });

const PORT = parseInt(process.env.PORT || '3017', 10);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.SCRUBBER_DATA_DIR || path.join(__dirname, 'data');
const RULES_DIR = path.join(__dirname, 'rules');
const REVERSAL_KEY_RAW = process.env.SCRUBBER_REVERSAL_KEY || 'dev-key-do-not-use-in-prod-dev-key-do-not-use-in-prod';
const REVERSAL_KEY = crypto.createHash('sha256').update(REVERSAL_KEY_RAW).digest();
const VERSION = '0.4.0';
const JWT_SECRET = process.env.SCRUBBER_JWT_SECRET || '';
const JWT_TTL_SECONDS = 300;
const SCRUBBER_AUTH = (process.env.SCRUBBER_AUTH || 'key').toLowerCase();
const SCRUBBER_API_KEY = process.env.SCRUBBER_API_KEY || '';
const RATE_LIMIT_TOKENS_PER_SECOND = 1000;
const RATE_LIMIT_CAPACITY = 1000;
const PUBLIC_PATHS = new Set(['/', '/health', '/metrics']);
const SCRUBBER_UPSTREAM_TIMEOUT = parseInt(process.env.SCRUBBER_UPSTREAM_TIMEOUT || '30000', 10);
const SCRUBBER_CONNECTION_TIMEOUT = parseInt(process.env.SCRUBBER_CONNECTION_TIMEOUT || '5000', 10);
const SCRUBBER_PROXY_ALLOW_PRIVATE = (process.env.SCRUBBER_PROXY_ALLOW_PRIVATE || 'false').toLowerCase() === 'true';
const SCRUBBER_WS_MAX_CONNECTIONS = parseInt(process.env.SCRUBBER_WS_MAX_CONNECTIONS || '500', 10);
const FORWARDED_REQUEST_HEADERS = new Set([
  'content-type', 'authorization', 'x-api-key', 'x-request-id', 'x-tenant-id', 'user-agent', 'accept', 'accept-language', 'cache-control',
]);
const BLOCKED_REQUEST_HEADERS = new Set(['cookie', 'set-cookie', 'host', 'transfer-encoding', 'connection', 'upgrade']);
const BLOCKED_RESPONSE_HEADERS = new Set(['transfer-encoding', 'connection', 'upgrade']);

if (!JWT_SECRET) {
  logger.warn('SCRUBBER_JWT_SECRET unset — attestation JWTs disabled');
}

fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_PATH = path.join(DATA_DIR, 'mappings.db');

function openDb() {
  const db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');
  db.pragma('synchronous = NORMAL');
  return db;
}

function runMigrations(db) {
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
CREATE TABLE IF NOT EXISTS service_metrics (
  name TEXT PRIMARY KEY,
  value INTEGER NOT NULL
);
INSERT OR IGNORE INTO service_metrics (name, value) VALUES ('scrub_requests_total', 0);
`);
}

function gc(db) {
  const cutoff = Math.floor(Date.now() / 1000) - 30 * 86400;
  db.prepare('DELETE FROM mappings WHERE created_at < ?').run(cutoff);
}

function initPrimaryMaintenance() {
  const primaryDb = openDb();
  runMigrations(primaryDb);
  gc(primaryDb);
  setInterval(() => gc(primaryDb), 6 * 3600 * 1000);
}

const RULE_PACKS = {};
function loadRules() {
  for (const f of fs.readdirSync(RULES_DIR)) {
    if (!f.endsWith('.json')) continue;
    const pack = JSON.parse(fs.readFileSync(path.join(RULES_DIR, f), 'utf8'));
    RULE_PACKS[pack.name] = pack;
  }
  logger.info({ packs: Object.keys(RULE_PACKS) }, 'loaded rule packs');
}
loadRules();

const VALIDATORS = {
  luhn(s) {
    const d = s.replace(/[^0-9]/g, '');
    if (d.length < 13 || d.length > 19) return false;
    let sum = 0; let alt = false;
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
    let rem = 0;
    for (const ch of num) rem = (rem * 10 + parseInt(ch, 10)) % 97;
    return rem === 1;
  },
};

function makeMetrics() {
  const register = new Registry();
  collectDefaultMetrics({ register });
  const detectionsTotal = new Counter({
    name: 'detections_total',
    help: 'Total detections by category and rule pack.',
    labelNames: ['category', 'pack'],
    registers: [register],
  });
  const scrubLatencySeconds = new Histogram({
    name: 'scrub_latency_seconds',
    help: 'Latency of /scrub requests.',
    buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
    registers: [register],
  });
  const scrubProxyRequestsTotal = new Counter({
    name: 'scrub_proxy_requests_total',
    help: 'Total /proxy requests processed.',
    registers: [register],
  });
  const scrubWsActiveConnections = new Gauge({
    name: 'scrub_ws_active_connections',
    help: 'Current active websocket proxy connections.',
    registers: [register],
  });
  const scrubWsFramesProcessedTotal = new Counter({
    name: 'scrub_ws_frames_processed_total',
    help: 'Total websocket frames processed by direction.',
    labelNames: ['direction'],
    registers: [register],
  });
  const scrubWsBytesScrubbedTotal = new Counter({
    name: 'scrub_ws_bytes_scrubbed_total',
    help: 'Total websocket bytes scrubbed by direction.',
    labelNames: ['direction'],
    registers: [register],
  });
  return {
    register,
    detectionsTotal,
    scrubLatencySeconds,
    scrubProxyRequestsTotal,
    scrubWsActiveConnections,
    scrubWsFramesProcessedTotal,
    scrubWsBytesScrubbedTotal,
  };
}

function isPrivateIp(ip) {
  if (net.isIP(ip) === 4) {
    const parts = ip.split('.').map((v) => parseInt(v, 10));
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    return false;
  }
  if (net.isIP(ip) === 6) {
    const s = ip.toLowerCase();
    if (s === '::1') return true;
    if (s.startsWith('fe80:')) return true;
    if (s.startsWith('fc') || s.startsWith('fd')) return true;
    return false;
  }
  return false;
}

function normalizeIp(ip) {
  if (typeof ip !== 'string') return ip;
  const s = ip.toLowerCase();
  if (s.startsWith('::ffff:')) {
    return s.slice(7);
  }
  return ip;
}

async function assertSafeTarget(target) {
  let u;
  try {
    u = new URL(target);
  } catch {
    const err = new Error('bad_target');
    err.code = 'bad_target';
    throw err;
  }
  if (!['http:', 'https:', 'ws:', 'wss:'].includes(u.protocol)) {
    const err = new Error('bad_target');
    err.code = 'bad_target';
    throw err;
  }
  const host = u.hostname;
  if (SCRUBBER_PROXY_ALLOW_PRIVATE) {
    const resolved = net.isIP(host) ? [{ address: normalizeIp(host), family: net.isIP(host) }] : await dns.lookup(host, { all: true, verbatim: true });
    if (!resolved.length) {
      const err = new Error('bad_target');
      err.code = 'bad_target';
      throw err;
    }
    return { url: u, pinnedAddress: normalizeIp(resolved[0].address), family: resolved[0].family };
  }
  if (net.isIP(host) && isPrivateIp(normalizeIp(host))) {
    const err = new Error('ssrf_blocked');
    err.code = 'ssrf_blocked';
    throw err;
  }
  const addrs = await dns.lookup(host, { all: true, verbatim: true });
  if (!addrs.length) {
    const err = new Error('bad_target');
    err.code = 'bad_target';
    throw err;
  }
  for (const entry of addrs) {
    if (isPrivateIp(normalizeIp(entry.address))) {
      const err = new Error('ssrf_blocked');
      err.code = 'ssrf_blocked';
      throw err;
    }
  }
  return { url: u, pinnedAddress: normalizeIp(addrs[0].address), family: addrs[0].family };
}

function forwardRequestHeaders(headers) {
  const out = {};
  for (const [key, val] of Object.entries(headers || {})) {
    const lk = String(key).toLowerCase();
    if (lk.startsWith('x-scrubber-')) continue;
    if (BLOCKED_REQUEST_HEADERS.has(lk)) continue;
    if (!FORWARDED_REQUEST_HEADERS.has(lk)) continue;
    out[lk] = val;
  }
  return out;
}

function setForwardResponseHeaders(res, headers) {
  for (const [key, val] of headers.entries()) {
    const lk = key.toLowerCase();
    if (lk.startsWith('x-scrubber-')) continue;
    if (BLOCKED_RESPONSE_HEADERS.has(lk)) continue;
    res.setHeader(key, val);
  }
}

function setScrubbedForwardResponseHeaders(res, headers) {
  for (const [key, val] of headers.entries()) {
    const lk = key.toLowerCase();
    if (lk.startsWith('x-scrubber-')) continue;
    if (BLOCKED_RESPONSE_HEADERS.has(lk)) continue;
    if (lk === 'content-length' || lk === 'etag') continue;
    res.setHeader(key, val);
  }
}

function scrubSseText(raw, rules, wantReversible, db) {
  const lines = raw.split('\n');
  const out = [];
  const responseMappingId = wantReversible ? crypto.randomBytes(12).toString('hex') : null;
  let detections = [];
  for (const line of lines) {
    if (line.startsWith('data: ')) {
      const payload = line.slice(6);
      const r = scrubText(payload, rules, responseMappingId, db);
      detections = detections.concat(r.detections);
      out.push(`data: ${r.text}`);
    } else {
      out.push(line);
    }
  }
  return { text: out.join('\n'), detections, mappingId: responseMappingId };
}

function scrubText(text, ruleNames, mappingId, db) {
  if (typeof text !== 'string' || !text) return { text: text || '', detections: [] };
  let out = text;
  const detections = [];
  const counters = {};
  const ordered = [...ruleNames].sort((a, b) => (a === 'base' ? 1 : 0) - (b === 'base' ? 1 : 0));
  for (const name of ordered) {
    const pack = RULE_PACKS[name];
    if (!pack) continue;
    for (const rule of pack.rules) {
      const re = new RegExp(rule.pattern, rule.flags || 'g');
      out = out.replace(re, (match) => {
        if (rule.validator && VALIDATORS[rule.validator] && !VALIDATORS[rule.validator](match)) {
          return match;
        }
        counters[rule.token] = (counters[rule.token] || 0) + 1;
        const placeholder = `<${rule.token}_${counters[rule.token]}>`;
        detections.push({ token: placeholder, category: rule.token, pack: name });
        if (mappingId) storeMapping(db, mappingId, placeholder, match);
        return placeholder;
      });
    }
  }
  return { text: out, detections };
}

function scrubTrace(trace, ruleNames, mappingId, db) {
  if (!Array.isArray(trace)) return { trace: [], detections: [] };
  const all = [];
  const scrubbed = trace.map((msg) => {
    const r = scrubText(typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content), ruleNames, mappingId, db);
    all.push(...r.detections);
    return { ...msg, content: r.text };
  });
  return { trace: scrubbed, detections: all };
}

function storeMapping(db, mappingId, token, original) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', REVERSAL_KEY, iv);
  const ct = Buffer.concat([cipher.update(original, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  db.prepare(
    'INSERT OR REPLACE INTO mappings (mapping_id, token, iv, tag, ciphertext, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(mappingId, token, iv, tag, ct, Math.floor(Date.now() / 1000));
}

function reverseMapping(db, mappingId, token) {
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

function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function issueAttestation(db, { inputHash, outputHash, mode }) {
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

function getAttestation(db, jti) {
  return db.prepare('SELECT jti, iat, exp, input_hash, output_hash, mode, engine_version FROM attestations WHERE jti = ?').get(jti);
}

function parseRules(url) {
  const q = new URL(url, 'http://x').searchParams.get('rules');
  if (!q) return ['base'];
  const names = q.split(',').map((s) => s.trim()).filter(Boolean);
  return names.length ? names : ['base'];
}

function getClientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.length > 0) {
    return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function createRateLimiter() {
  if (cluster.isWorker && process.send) {
    const pending = new Map();
    let requestId = 0;

    process.on('message', (msg) => {
      if (!msg || msg.type !== 'rate-limit-response') return;
      const resolve = pending.get(msg.id);
      if (!resolve) return;
      pending.delete(msg.id);
      resolve(msg);
    });

    return (req, res, next) => {
      const id = ++requestId;
      const ip = getClientIp(req);
      pending.set(id, (result) => {
        if (result.allowed) return next();
        res.setHeader('Retry-After', String(result.retryAfter));
        return res.status(429).json({ error: 'rate_limited' });
      });
      process.send({ type: 'rate-limit-check', id, ip });
    };
  }

  const buckets = new Map();
  return (req, res, next) => {
    const now = Date.now() / 1000;
    const key = getClientIp(req);
    const current = buckets.get(key) || { tokens: RATE_LIMIT_CAPACITY, last: now };
    const elapsed = Math.max(0, now - current.last);
    current.tokens = Math.min(RATE_LIMIT_CAPACITY, current.tokens + elapsed * RATE_LIMIT_TOKENS_PER_SECOND);
    current.last = now;

    if (current.tokens < 1) {
      const retryAfter = Math.max(1, Math.ceil((1 - current.tokens) / RATE_LIMIT_TOKENS_PER_SECOND));
      res.setHeader('Retry-After', String(retryAfter));
      buckets.set(key, current);
      return res.status(429).json({ error: 'rate_limited' });
    }

    current.tokens -= 1;
    buckets.set(key, current);
    return next();
  };
}

function checkLocalRateLimit(buckets, ip) {
  const now = Date.now() / 1000;
  const current = buckets.get(ip) || { tokens: RATE_LIMIT_CAPACITY, last: now };
  const elapsed = Math.max(0, now - current.last);
  current.tokens = Math.min(RATE_LIMIT_CAPACITY, current.tokens + elapsed * RATE_LIMIT_TOKENS_PER_SECOND);
  current.last = now;
  if (current.tokens < 1) {
    const retryAfter = Math.max(1, Math.ceil((1 - current.tokens) / RATE_LIMIT_TOKENS_PER_SECOND));
    buckets.set(ip, current);
    return { allowed: false, retryAfter };
  }
  current.tokens -= 1;
  buckets.set(ip, current);
  return { allowed: true, retryAfter: 0 };
}

function isAuthorized(req) {
  if (SCRUBBER_AUTH === 'none') return true;
  if (PUBLIC_PATHS.has(new URL(req.url || '/', 'http://x').pathname)) return true;
  if (!SCRUBBER_API_KEY) return false;
  const key = req.headers['x-scrubber-key'];
  return typeof key === 'string' && key === SCRUBBER_API_KEY;
}

function readGlobalScrubRequestsTotal(db) {
  const row = db.prepare("SELECT value FROM service_metrics WHERE name = 'scrub_requests_total'").get();
  return row ? Number(row.value) : 0;
}

function incrementGlobalScrubRequestsTotal(db) {
  db.prepare("UPDATE service_metrics SET value = value + 1 WHERE name = 'scrub_requests_total'").run();
}

function createAuthMiddleware() {
  return (req, res, next) => {
    if (SCRUBBER_AUTH === 'none') return next();
    if (PUBLIC_PATHS.has(req.path)) return next();
    if (!SCRUBBER_API_KEY) {
      return res.status(503).json({ error: 'auth_misconfigured' });
    }
    const key = req.headers['x-scrubber-key'];
    if (typeof key === 'string' && key === SCRUBBER_API_KEY) return next();
    return res.status(401).json({ error: 'unauthorized' });
  };
}

function createApp() {
  const db = openDb();
  const metrics = makeMetrics();
  const app = express();

  app.use(express.json({ limit: '1mb' }));
  app.use(createRateLimiter());
  app.use(createAuthMiddleware());
  app.use(express.static('public'));

  app.get('/', (req, res) => {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  app.get('/health', (req, res) => {
    return res.status(200).json({ ok: true, version: VERSION, rules: Object.keys(RULE_PACKS), worker_id: cluster.isWorker ? cluster.worker.id : null });
  });

  app.get('/rules', (req, res) => {
    const summary = Object.values(RULE_PACKS).map((p) => ({
      name: p.name, version: p.version, description: p.description, rule_count: p.rules.length,
    }));
    return res.status(200).json({ packs: summary });
  });

  app.get('/metrics', async (req, res) => {
    const globalScrubRequests = readGlobalScrubRequestsTotal(db);
    const legacyLines = [
      '# HELP scrub_requests_total Total /scrub requests processed.',
      '# TYPE scrub_requests_total counter',
      `scrub_requests_total ${globalScrubRequests}`,
    ].join('\n');

    res.set('Content-Type', metrics.register.contentType);
    return res.status(200).send(`${legacyLines}\n${await metrics.register.metrics()}`);
  });

  async function handleScrub(req, res) {
    const body = req.body || {};
    const rules = parseRules(req.originalUrl || req.url);
    const wantReversible = body.reversible === true;
    const mappingId = wantReversible ? crypto.randomBytes(12).toString('hex') : null;

    const t0 = process.hrtime.bigint();
    let result;
    let detections;
    let mode;
    let sanitizedPayload;
    if (typeof body.text === 'string') {
      const r = scrubText(body.text, rules, mappingId, db);
      result = { text: r.text, detections: r.detections };
      detections = r.detections;
      mode = 'text';
      sanitizedPayload = r.text;
    } else if (Array.isArray(body.trace)) {
      const r = scrubTrace(body.trace, rules, mappingId, db);
      result = { trace: r.trace, detections: r.detections };
      detections = r.detections;
      mode = 'trace';
      sanitizedPayload = JSON.stringify(r.trace);
    } else {
      return res.status(400).json({ error: 'body must include {text} or {trace:[]}' });
    }

    const elapsed = Number(process.hrtime.bigint() - t0) / 1e9;
    incrementGlobalScrubRequestsTotal(db);
    metrics.scrubLatencySeconds.observe(elapsed);
    for (const d of detections) {
      metrics.detectionsTotal.labels(d.category, d.pack).inc();
    }

    const inputRaw = typeof body.text === 'string' ? body.text : JSON.stringify(body.trace);
    const inputHash = sha256Hex(inputRaw);
    const outputHash = sha256Hex(sanitizedPayload);
    const att = issueAttestation(db, { inputHash, outputHash, mode });

    return res.status(200).json({
      ...result,
      rules_applied: rules,
      engine_version: VERSION,
      mapping_id: mappingId,
      mode,
      attestation: att ? att.token : null,
      attestation_meta: att ? { jti: att.jti, iat: att.iat, exp: att.exp, input_hash: inputHash, output_hash: outputHash } : null,
    });
  }

  async function scrubPayload(body, rules, db) {
    const wantReversible = body && body.reversible === true;
    const mappingId = wantReversible ? crypto.randomBytes(12).toString('hex') : null;
    if (typeof body.text === 'string') {
      const r = scrubText(body.text, rules, mappingId, db);
      return {
        result: { text: r.text, detections: r.detections },
        detections: r.detections,
        mode: 'text',
        sanitizedPayload: r.text,
        inputRaw: body.text,
        mappingId,
      };
    }
    if (Array.isArray(body.trace)) {
      const r = scrubTrace(body.trace, rules, mappingId, db);
      return {
        result: { trace: r.trace, detections: r.detections },
        detections: r.detections,
        mode: 'trace',
        sanitizedPayload: JSON.stringify(r.trace),
        inputRaw: JSON.stringify(body.trace),
        mappingId,
      };
    }
    const raw = typeof body === 'string' ? body : JSON.stringify(body || {});
    const r = scrubText(raw, rules, mappingId, db);
    return {
      result: { text: r.text, detections: r.detections },
      detections: r.detections,
      mode: 'text',
      sanitizedPayload: r.text,
      inputRaw: raw,
      mappingId,
    };
  }

  app.post('/proxy', async (req, res, next) => {
    try {
      const qs = new URL(req.originalUrl || req.url, 'http://x').searchParams;
      const target = qs.get('target');
      const scrubResponse = (qs.get('scrub_response') || 'false').toLowerCase() === 'true';
      if (!target) return res.status(400).json({ error: 'target_required' });
      const safe = await assertSafeTarget(target);
      if (!['http:', 'https:'].includes(safe.url.protocol)) return res.status(400).json({ error: 'bad_target' });

      const rules = parseRules(req.originalUrl || req.url);
      const inputBody = req.body || {};
      if (!(typeof inputBody.text === 'string' || Array.isArray(inputBody.trace))) {
        return res.status(400).json({ error: 'body must include {text} or {trace:[]}' });
      }
      const scrubbedReq = await scrubPayload(inputBody, rules, db);
      const reqInputHash = sha256Hex(scrubbedReq.inputRaw);
      const reqOutputHash = sha256Hex(scrubbedReq.sanitizedPayload);
      const reqAtt = issueAttestation(db, { inputHash: reqInputHash, outputHash: reqOutputHash, mode: scrubbedReq.mode });

      const forwardedHeaders = forwardRequestHeaders(req.headers);
      forwardedHeaders['x-scrubbed-by'] = 'scrubber-proxy';

      const bodyForUpstream = typeof inputBody.text === 'string'
        ? { ...inputBody, text: scrubbedReq.result.text }
        : { ...inputBody, trace: scrubbedReq.result.trace };
      const bodyText = JSON.stringify(bodyForUpstream);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), SCRUBBER_UPSTREAM_TIMEOUT);
      let upstream;
      try {
        upstream = await fetch(safe.url.toString(), {
          method: req.method,
          headers: forwardedHeaders,
          body: bodyText,
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      let responseBody = await upstream.text();
      let responseMappingId = null;
      if (scrubResponse) {
        const ctype = upstream.headers.get('content-type') || '';
        if (ctype.includes('text/event-stream')) {
          const scrubbed = scrubSseText(responseBody, rules, inputBody.reversible === true, db);
          responseBody = scrubbed.text;
          responseMappingId = scrubbed.mappingId;
        } else {
          const mappingId = inputBody.reversible === true ? crypto.randomBytes(12).toString('hex') : null;
          const scrubbed = scrubText(responseBody, rules, mappingId, db);
          responseBody = scrubbed.text;
          responseMappingId = mappingId;
        }
      }

      metrics.scrubProxyRequestsTotal.inc();
      res.status(upstream.status);
      if (scrubResponse) setScrubbedForwardResponseHeaders(res, upstream.headers);
      else setForwardResponseHeaders(res, upstream.headers);
      if (reqAtt && reqAtt.token) res.setHeader('x-scrubber-attestation', reqAtt.token);
      if (scrubbedReq.mappingId) res.setHeader('x-scrub-mapping-id-req', scrubbedReq.mappingId);
      if (responseMappingId) res.setHeader('x-scrub-mapping-id-res', responseMappingId);
      return res.send(responseBody);
    } catch (e) {
      if (e && e.code === 'ssrf_blocked') return res.status(400).json({ error: 'ssrf_blocked' });
      if (e && e.code === 'bad_target') return res.status(400).json({ error: 'bad_target' });
      return next(e);
    }
  });

  app.post('/scrub', async (req, res, next) => {
    try {
      return await handleScrub(req, res);
    } catch (e) {
      return next(e);
    }
  });

  app.post('/v1/scrub', async (req, res, next) => {
    try {
      return await handleScrub(req, res);
    } catch (e) {
      return next(e);
    }
  });

  app.get('/v1/attestations/:jti', (req, res) => {
    const jti = req.params.jti;
    if (!jti || !/^[a-f0-9]{32}$/.test(jti)) return res.status(400).json({ error: 'bad_jti' });
    const row = getAttestation(db, jti);
    if (!row) return res.status(404).json({ error: 'not_found' });
    const now = Math.floor(Date.now() / 1000);
    return res.status(200).json({ ...row, valid: row.exp > now });
  });

  app.post('/reverse', (req, res) => {
    const body = req.body || {};
    if (!body.mapping_id || !body.token) {
      return res.status(400).json({ error: 'mapping_id and token required' });
    }
    const original = reverseMapping(db, body.mapping_id, body.token);
    if (original === null) return res.status(404).json({ error: 'not_found' });
    return res.status(200).json({ original });
  });

  app.use((req, res) => {
    return res.status(404).json({ error: 'not_found' });
  });

  app.use((err, req, res, next) => {
    logger.error({ err }, 'request failed');
    return res.status(500).json({ error: String((err && err.message) || err) });
  });

  return { app, metrics, db };
}

function startWorker() {
  const { app, metrics, db } = createApp();
  const server = http.createServer(app);
  const wss = new WebSocketServer({ noServer: true });
  let activeWsConnections = 0;
  const wsRateBuckets = new Map();
  const wsCapacityPending = new Map();
  let wsCapacityRequestId = 0;

  process.on('message', (msg) => {
    if (!msg || msg.type !== 'ws-capacity-response') return;
    const resolve = wsCapacityPending.get(msg.id);
    if (!resolve) return;
    wsCapacityPending.delete(msg.id);
    resolve(msg.allowed === true);
  });

  function acquireGlobalWsSlot() {
    if (!(cluster.isWorker && process.send)) return Promise.resolve(true);
    return new Promise((resolve) => {
      const id = ++wsCapacityRequestId;
      wsCapacityPending.set(id, resolve);
      process.send({ type: 'ws-capacity-acquire', id });
    });
  }

  function releaseGlobalWsSlot() {
    if (cluster.isWorker && process.send) {
      process.send({ type: 'ws-capacity-release' });
    }
  }

  server.on('upgrade', async (req, socket, head) => {
    try {
      if (req.url == null || !req.url.startsWith('/ws')) {
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
        return;
      }

      if (!isAuthorized(req)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      const ip = req.socket.remoteAddress || 'unknown';
      const rl = checkLocalRateLimit(wsRateBuckets, ip);
      if (!rl.allowed) {
        socket.write(`HTTP/1.1 429 Too Many Requests\r\nRetry-After: ${rl.retryAfter}\r\n\r\n`);
        socket.destroy();
        return;
      }

      const slotGranted = await acquireGlobalWsSlot();
      if (!slotGranted || activeWsConnections >= SCRUBBER_WS_MAX_CONNECTIONS) {
        socket.write('HTTP/1.1 503 Service Unavailable\r\nX-Error: ws-capacity-exceeded\r\n\r\n');
        socket.destroy();
        if (slotGranted) releaseGlobalWsSlot();
        return;
      }

      const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
      const target = reqUrl.searchParams.get('target');
      if (!target) {
        socket.write('HTTP/1.1 400 Bad Request\r\nX-Error: target-required\r\n\r\n');
        socket.destroy();
        return;
      }
      const safeTarget = await assertSafeTarget(target);
      if (!['ws:', 'wss:'].includes(safeTarget.url.protocol)) {
        socket.write('HTTP/1.1 400 Bad Request\r\nX-Error: bad-target\r\n\r\n');
        socket.destroy();
        releaseGlobalWsSlot();
        return;
      }

      const rules = parseRules(req.url);
      const upstreamHeaders = forwardRequestHeaders(req.headers);
      const upstream = new WebSocket(safeTarget.url.toString(), {
        handshakeTimeout: SCRUBBER_CONNECTION_TIMEOUT,
        headers: upstreamHeaders,
      });

      const onUpstreamConnectError = () => {
        if (socket.writable) {
          socket.write('HTTP/1.1 502 Bad Gateway\r\nX-Error: upstream-connection-failed\r\n\r\n');
        }
        socket.destroy();
        releaseGlobalWsSlot();
      };
      upstream.once('error', onUpstreamConnectError);

      upstream.once('open', () => {
        upstream.off('error', onUpstreamConnectError);
        wss.handleUpgrade(req, socket, head, (client) => {
          activeWsConnections += 1;
          metrics.scrubWsActiveConnections.set(activeWsConnections);

          client.on('message', (data, isBinary) => {
            if (isBinary) {
              upstream.send(data, { binary: true });
              return;
            }
            const text = data.toString('utf8');
            const scrubbed = scrubText(text, rules, null, db).text;
            metrics.scrubWsFramesProcessedTotal.labels('outbound').inc();
            metrics.scrubWsBytesScrubbedTotal.labels('outbound').inc(Buffer.byteLength(scrubbed, 'utf8'));
            upstream.send(scrubbed, { binary: false });
          });

          upstream.on('message', (data, isBinary) => {
            if (isBinary) {
              client.send(data, { binary: true });
              return;
            }
            const text = data.toString('utf8');
            const scrubbed = scrubText(text, rules, null, db).text;
            metrics.scrubWsFramesProcessedTotal.labels('inbound').inc();
            metrics.scrubWsBytesScrubbedTotal.labels('inbound').inc(Buffer.byteLength(scrubbed, 'utf8'));
            client.send(scrubbed, { binary: false });
          });

          client.on('close', (code, reason) => {
            if (upstream.readyState === WebSocket.OPEN) upstream.close(code, reason);
          });
          upstream.on('close', (code, reason) => {
            if (client.readyState === WebSocket.OPEN) client.close(code, reason);
          });

          let settled = false;
          const settle = () => {
            if (settled) return;
            settled = true;
            activeWsConnections = Math.max(0, activeWsConnections - 1);
            metrics.scrubWsActiveConnections.set(activeWsConnections);
            releaseGlobalWsSlot();
          };
          client.once('close', settle);
          upstream.once('close', settle);
          client.on('error', settle);
          upstream.on('error', settle);
        });
      });
    } catch (e) {
      if (e && e.code === 'ssrf_blocked') {
        socket.write('HTTP/1.1 400 Bad Request\r\nX-Error: ssrf_blocked\r\n\r\n');
        socket.destroy();
        releaseGlobalWsSlot();
        return;
      }
      socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
      socket.destroy();
      releaseGlobalWsSlot();
    }
  });

  server.listen(PORT, HOST, () => {
    logger.info({ host: HOST, port: PORT, worker_id: cluster.isWorker ? cluster.worker.id : null }, 'listening');
  });
}

if (cluster.isPrimary) {
  const rateBuckets = new Map();
  let activeWsConnectionsGlobal = 0;

  cluster.on('message', (worker, msg) => {
    if (!msg || msg.type !== 'rate-limit-check') return;
    const now = Date.now() / 1000;
    const current = rateBuckets.get(msg.ip) || { tokens: RATE_LIMIT_CAPACITY, last: now };
    const elapsed = Math.max(0, now - current.last);
    current.tokens = Math.min(RATE_LIMIT_CAPACITY, current.tokens + elapsed * RATE_LIMIT_TOKENS_PER_SECOND);
    current.last = now;

    if (current.tokens < 1) {
      const retryAfter = Math.max(1, Math.ceil((1 - current.tokens) / RATE_LIMIT_TOKENS_PER_SECOND));
      rateBuckets.set(msg.ip, current);
      worker.send({ type: 'rate-limit-response', id: msg.id, allowed: false, retryAfter });
      return;
    }

    current.tokens -= 1;
    rateBuckets.set(msg.ip, current);
    worker.send({ type: 'rate-limit-response', id: msg.id, allowed: true, retryAfter: 0 });
  });

  cluster.on('message', (worker, msg) => {
    if (!msg || msg.type !== 'ws-capacity-acquire') return;
    if (activeWsConnectionsGlobal >= SCRUBBER_WS_MAX_CONNECTIONS) {
      worker.send({ type: 'ws-capacity-response', id: msg.id, allowed: false });
      return;
    }
    activeWsConnectionsGlobal += 1;
    worker.send({ type: 'ws-capacity-response', id: msg.id, allowed: true });
  });

  cluster.on('message', (worker, msg) => {
    if (!msg || msg.type !== 'ws-capacity-release') return;
    activeWsConnectionsGlobal = Math.max(0, activeWsConnectionsGlobal - 1);
  });

  initPrimaryMaintenance();
  const workerCount = os.cpus().length;
  logger.info({ workers: workerCount }, 'starting cluster');
  for (let i = 0; i < workerCount; i += 1) {
    cluster.fork();
  }
  cluster.on('exit', (worker) => {
    logger.warn({ worker_id: worker.id }, 'worker exited, restarting');
    cluster.fork();
  });
} else {
  startWorker();
}

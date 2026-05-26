#!/usr/bin/env node
'use strict';

const cluster = require('cluster');
const os = require('os');
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const pino = require('pino');
const { Registry, collectDefaultMetrics, Counter, Histogram } = require('prom-client');

const logger = pino({ name: 'scrubber-proxy' });

const PORT = parseInt(process.env.PORT || '3017', 10);
const HOST = process.env.HOST || '127.0.0.1';
const DATA_DIR = process.env.SCRUBBER_DATA_DIR || path.join(__dirname, 'data');
const RULES_DIR = path.join(__dirname, 'rules');
const REVERSAL_KEY_RAW = process.env.SCRUBBER_REVERSAL_KEY || 'dev-key-do-not-use-in-prod-dev-key-do-not-use-in-prod';
const REVERSAL_KEY = crypto.createHash('sha256').update(REVERSAL_KEY_RAW).digest();
const VERSION = '0.3.0';
const JWT_SECRET = process.env.SCRUBBER_JWT_SECRET || '';
const JWT_TTL_SECONDS = 300;
const SCRUBBER_AUTH = (process.env.SCRUBBER_AUTH || 'key').toLowerCase();
const SCRUBBER_API_KEY = process.env.SCRUBBER_API_KEY || '';
const RATE_LIMIT_TOKENS_PER_SECOND = 1000;
const RATE_LIMIT_CAPACITY = 1000;
const PUBLIC_PATHS = new Set(['/', '/health', '/metrics']);

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
  return { register, detectionsTotal, scrubLatencySeconds };
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

  return app;
}

function startWorker() {
  const app = createApp();
  app.listen(PORT, HOST, () => {
    logger.info({ host: HOST, port: PORT, worker_id: cluster.isWorker ? cluster.worker.id : null }, 'listening');
  });
}

if (cluster.isPrimary) {
  const rateBuckets = new Map();

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

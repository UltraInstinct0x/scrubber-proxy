#!/usr/bin/env node
/**
 * Tier corpus runner — gates CI on per-tier reliability targets.
 *
 * For each tier folder under tests/corpus/<tier>/, walks every `*.txt` fixture
 * with its sibling `*.txt.expected.json` and verifies the scrubber engine
 * produced the expected category multiset.
 *
 * Modes:
 *   --offline (default) : load engine in-process (no HTTP, no auth, no DB).
 *   --remote <url>      : exercise a running scrubber instance over HTTP.
 *
 * Exits 0 iff every tier marked target=100% has 0 mismatches.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CORPUS = path.join(__dirname, 'corpus');
const TIERS = JSON.parse(fs.readFileSync(path.join(__dirname, 'tiers.json'), 'utf8'));

const argv = process.argv.slice(2);
const remoteIdx = argv.indexOf('--remote');
const REMOTE_URL = remoteIdx >= 0 ? argv[remoteIdx + 1] : null;

async function loadEngine() {
  if (REMOTE_URL) {
    return async function scrubRemote(text) {
      const res = await fetch(`${REMOTE_URL.replace(/\/$/, '')}/scrub?rules=base`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text }),
      });
      if (!res.ok) throw new Error(`remote ${res.status}: ${await res.text()}`);
      const j = await res.json();
      return j.detections || [];
    };
  }
  // Offline path — replay the engine's rule logic without booting the HTTP server.
  const VALIDATORS = require('../server.validators.js');
  const RULES_DIR = path.join(ROOT, 'rules');
  const PACKS = {};
  for (const f of fs.readdirSync(RULES_DIR)) {
    if (!f.endsWith('.json')) continue;
    const pack = JSON.parse(fs.readFileSync(path.join(RULES_DIR, f), 'utf8'));
    PACKS[pack.name] = pack;
  }
  function scrub(text, ruleNames = ['base']) {
    let out = text;
    const detections = [];
    const counters = {};
    const ordered = [...ruleNames].sort((a, b) => (a === 'base' ? 1 : 0) - (b === 'base' ? 1 : 0));
    for (const name of ordered) {
      const pack = PACKS[name];
      if (!pack) continue;
      const sorted = [...pack.rules].sort((a, b) => (a.priority ?? 1000) - (b.priority ?? 1000));
      for (const rule of sorted) {
        const re = new RegExp(rule.pattern, rule.flags || 'g');
        out = out.replace(re, (match) => {
          if (rule.validator && VALIDATORS[rule.validator] && !VALIDATORS[rule.validator](match)) {
            return match;
          }
          counters[rule.token] = (counters[rule.token] || 0) + 1;
          const placeholder = `<${rule.token}_${counters[rule.token]}>`;
          detections.push({ token: placeholder, category: rule.category || rule.token, pack: name });
          return placeholder;
        });
      }
    }
    return detections;
  }
  return async (text) => scrub(text);
}

function multisetDiff(actual, expected) {
  const a = new Map();
  const e = new Map();
  for (const c of actual) a.set(c, (a.get(c) || 0) + 1);
  for (const c of expected) e.set(c, (e.get(c) || 0) + 1);
  const missing = [];
  const extra = [];
  const keys = new Set([...a.keys(), ...e.keys()]);
  for (const k of keys) {
    const da = a.get(k) || 0;
    const de = e.get(k) || 0;
    if (de > da) missing.push({ category: k, count: de - da });
    if (da > de) extra.push({ category: k, count: da - de });
  }
  return { missing, extra };
}

async function main() {
  const scrub = await loadEngine();
  const report = {};
  let hardFail = false;

  for (const tier of Object.keys(TIERS)) {
    const dir = path.join(CORPUS, tier);
    if (!fs.existsSync(dir)) {
      report[tier] = { skipped: true, reason: 'no corpus dir' };
      continue;
    }
    const fixtures = fs.readdirSync(dir).filter((f) => f.endsWith('.txt.b64'));
    const results = [];
    for (const f of fixtures) {
      const inputPath = path.join(dir, f);
      const expectedPath = `${inputPath}.expected.json`;
      if (!fs.existsSync(expectedPath)) {
        results.push({ fixture: f, status: 'NO_EXPECTED' });
        hardFail = true;
        continue;
      }
      const text = Buffer.from(fs.readFileSync(inputPath, 'utf8').trim(), 'base64').toString('utf8');
      const expected = JSON.parse(fs.readFileSync(expectedPath, 'utf8')).categories || [];
      const detections = await scrub(text);
      const actualCats = detections.map((d) => d.category);
      const { missing, extra } = multisetDiff(actualCats, expected);
      const pass = missing.length === 0 && extra.length === 0;
      results.push({ fixture: f, status: pass ? 'PASS' : 'FAIL', missing, extra, actual: actualCats });
      if (!pass && TIERS[tier].target === '100%') hardFail = true;
    }
    const passed = results.filter((r) => r.status === 'PASS').length;
    report[tier] = {
      label: TIERS[tier].label,
      target: TIERS[tier].target,
      total: results.length,
      passed,
      failed: results.length - passed,
      results,
    };
  }

  console.log('\nSCRUBBER TIER REPORT');
  console.log('====================');
  for (const tier of Object.keys(report)) {
    const r = report[tier];
    if (r.skipped) { console.log(`  ${tier}: SKIPPED (${r.reason})`); continue; }
    const verdict = r.failed === 0 ? 'OK' : 'FAIL';
    console.log(`  [${verdict}] ${tier.padEnd(15)} ${r.passed}/${r.total} passed  target=${r.target}  — ${r.label}`);
    if (r.failed > 0) {
      for (const f of r.results.filter((x) => x.status !== 'PASS')) {
        console.log(`     - ${f.fixture}: status=${f.status}`);
        if (f.missing && f.missing.length) console.log(`         missing: ${JSON.stringify(f.missing)}`);
        if (f.extra && f.extra.length)   console.log(`         extra:   ${JSON.stringify(f.extra)}`);
        if (f.actual)                    console.log(`         actual:  ${JSON.stringify(f.actual)}`);
      }
    }
  }
  console.log('');

  if (hardFail) {
    console.error('FAIL: one or more promised tiers did not hit 100%.');
    process.exit(1);
  }
  console.log('All promised tiers at 100%.');
}

main().catch((e) => { console.error(e); process.exit(2); });

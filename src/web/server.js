// S3 web app (C12-C14). Node http only, no framework.
// - Analysis runs out of the request path, in a child CLI process (C14).
// - Queue with concurrency 1-2, per-IP rate limit on the correct client IP, daily
//   cap on model calls persisted across restarts (C13, X7).
// - Every dynamic string is escaped, strict CSP with a per-response nonce (S3-SEC a).
// - Only validated argv reaches the CLI, never a shell string (S3-SEC b).
// - Receipt ids are the CLI's own task ids; the route accepts only that format (c).
// - The model key stays in this process env and the CLI child's; never sent out (d).
// - Binds one port in 8080-8089, no Docker or admin endpoint (e).
// - SIGINT/SIGTERM interrupts running tasks; their teardown is the CLI's (f, AF-7).
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { parseRegistrySpec } = require('../spec');
const { clientIp, parseTrusted } = require('./clientip');
const { createRateLimit, createDailyCap } = require('./limits');
const render = require('./render');
const formats = require('../formats');

// Absolute links in the Markdown/SARIF exports (e.g. https://qp.example.com). Only a
// plain origin is accepted; anything else leaves the links relative.
const PUBLIC_URL = /^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$/;
const publicUrlOf = (v) => (PUBLIC_URL.test(String(v || '')) ? String(v) : '');

const RECEIPT_ID = /^[a-f0-9]{10}$/;
const JOB_ID = /^[a-f0-9]{16}$/;
const RANGE = /^([\^~]|>=|<=|=)?\d+(\.(\d+|x)){0,2}(-[0-9A-Za-z][0-9A-Za-z.-]{0,40})?$/;

// S3-SEC (b): npm name grammar plus an exact version or a semver range; no tags,
// URLs, git, file or tarball specs (parseRegistrySpec already refuses those).
function validateWebSpec(input) {
  const s = String(input || '').trim();
  if (s.length > 260) return { ok: false, error: 'too long' };
  const r = parseRegistrySpec(s);
  if (!r.ok) return r;
  if (!r.version) return { ok: false, error: 'give a version or range, e.g. lodash@4.17.21' };
  if (!RANGE.test(r.version)) return { ok: false, error: 'the version must be an exact version or a semver range (^, ~, x)' };
  return r;
}

function webConfig(env = process.env) {
  const port = Number(env.QP_WEB_PORT || 8080);
  if (!Number.isInteger(port) || port < 8080 || port > 8089) throw new Error('QP_WEB_PORT must be within 8080-8089');
  const concurrency = Number(env.QP_WEB_CONCURRENCY || 1);
  if (![1, 2].includes(concurrency)) throw new Error('QP_WEB_CONCURRENCY must be 1 or 2');
  return {
    port,
    host: env.QP_WEB_HOST || '127.0.0.1',
    concurrency,
    queueMax: Number(env.QP_WEB_QUEUE_MAX || 5),
    rateMax: Number(env.QP_WEB_RATE_MAX || 5),
    rateWindowMs: Number(env.QP_WEB_RATE_WINDOW_S || 600) * 1000,
    rateGlobalMax: Number(env.QP_WEB_RATE_GLOBAL_MAX || 30),
    modelCap: Number(env.QP_WEB_MODEL_CAP || 60),
    trusted: parseTrusted(env.QP_WEB_TRUSTED_PROXIES || ''),
    stateFile: path.resolve(env.QP_WEB_STATE_FILE || path.join(process.cwd(), 'state', 'web-state.json')),
    publicUrl: publicUrlOf(env.QP_PUBLIC_URL),
  };
}

// Default job runner: the CLI in a child process, argv only.
function cliRunner({ repoRoot, env }) {
  return function run(target) {
    const args = [path.join(repoRoot, 'src', 'cli.js'), 'analyse', ...(target.kind === 'fixture' ? ['--fixture', target.fixture] : [target.spec])];
    const child = spawn(process.execPath, args, { cwd: repoRoot, env, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let out = '';
    child.stdout.on('data', (d) => { if (out.length < 65536) out += d; });
    child.stderr.on('data', () => {}); // never echoed to clients
    const done = new Promise((resolve) => child.on('close', (code) => {
      let summary = null;
      try { summary = JSON.parse(out.trim().split(/\r?\n/).pop()); } catch (_) { summary = null; }
      resolve({ code, summary });
    }));
    return { child, done };
  };
}

function createApp(opts) {
  const cfg = opts.cfg;
  const clock = opts.clock || { now: () => Date.now() };
  const receiptsDir = opts.receiptsDir;
  const runner = opts.runner;
  const readReceipt = opts.readReceipt || ((id) => JSON.parse(fs.readFileSync(path.join(receiptsDir, `${id}.json`), 'utf8')));
  const rate = createRateLimit({ max: cfg.rateMax, windowMs: cfg.rateWindowMs, globalMax: cfg.rateGlobalMax || Infinity, clock });
  const cap = createDailyCap({ cap: cfg.modelCap, file: cfg.stateFile, clock });
  const jobs = new Map();
  const queue = [];
  const running = new Set();

  function pump() {
    while (running.size < cfg.concurrency && queue.length) {
      const job = queue.shift();
      job.status = 'running';
      const h = runner(job.target);
      running.add(h);
      job.handle = h;
      h.done.then(({ summary }) => {
        running.delete(h);
        job.handle = null;
        if (summary && RECEIPT_ID.test(String(summary.taskId || ''))) {
          job.status = 'done';
          job.receiptId = summary.taskId;
          try {
            const rc = readReceipt(summary.taskId);
            cap.add((rc && rc.model && Array.isArray(rc.model.attempts) ? rc.model.attempts.length : 0)
              + (rc && rc.outcomeExplanation && Array.isArray(rc.outcomeExplanation.attempts) ? rc.outcomeExplanation.attempts.length
                : rc && rc.outcomeExplanation && rc.outcomeExplanation.attempt ? 1 : 0)); // S7/S8: outcome calls (incl. the retry) count too
          } catch (_) { /* receipt unreadable: nothing counted */ }
        } else {
          job.status = 'failed';
          job.message = 'the analysis did not produce a receipt';
        }
        pump();
      });
    }
  }

  function headers(res, nonce, type = 'text/html; charset=utf-8') {
    res.setHeader('Content-Type', type);
    res.setHeader('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cache-Control', 'no-store');
  }
  const send = (res, status, body, nonce, type) => { res.statusCode = status; headers(res, nonce, type); res.end(body); };

  function readForm(req) {
    return new Promise((resolve) => {
      let body = '';
      let over = false;
      req.on('data', (d) => { if (body.length + d.length > 4096) { over = true; } else body += d; });
      req.on('end', () => resolve(over ? null : new URLSearchParams(body)));
      req.on('error', () => resolve(null));
    });
  }

  // Shared admission: demo or validated spec, then cap, queue and per-IP rate limit.
  function submit(ip, demo, spec) {
    let target;
    if (demo) {
      const d = render.DEMOS.find((x) => x.id === demo);
      if (!d) return { ok: false, status: 400, title: 'Unknown demo', message: 'That demo does not exist.' };
      target = d.kind === 'fixture' ? { kind: 'fixture', fixture: d.fixture, label: d.label } : { kind: 'registry', spec: d.spec, label: d.label };
    } else {
      const v = validateWebSpec(spec);
      if (!v.ok) return { ok: false, status: 400, title: 'Not accepted', message: v.error };
      target = { kind: 'registry', spec: v.spec, label: v.spec };
    }
    if (cap.exhausted()) return { ok: false, status: 503, title: 'Daily limit reached', message: 'The daily limit of model calls is reached. New analyses resume tomorrow (UTC); existing receipts stay available.' };
    if (queue.length >= cfg.queueMax) return { ok: false, status: 503, title: 'Queue full', message: 'Too many analyses are waiting. Try again in a few minutes; existing receipts stay available.' };
    const r = rate.take(ip);
    if (!r.ok) return { ok: false, status: 429, title: 'Too many requests', message: r.global ? `The service is busy. Try again in ${r.retryAfterS} s.` : `Rate limit reached for your address. Try again in ${r.retryAfterS} s.`, retryAfterS: r.retryAfterS };
    const job = { id: crypto.randomBytes(8).toString('hex'), target, label: target.label, status: 'queued', receiptId: null, message: '' };
    jobs.set(job.id, job);
    queue.push(job);
    pump();
    return { ok: true, job };
  }

  function readJson(req) {
    return new Promise((resolve) => {
      let body = '';
      let over = false;
      req.on('data', (d) => { if (body.length + d.length > 4096) over = true; else body += d; });
      req.on('end', () => {
        if (over) return resolve(null);
        try {
          const v = JSON.parse(body || '{}');
          if (!v || typeof v !== 'object' || Array.isArray(v)) return resolve(null);
          resolve({ get: (k) => (typeof v[k] === 'string' ? v[k] : null) });
        } catch (_) { resolve(null); }
      });
      req.on('error', () => resolve(null));
    });
  }

  async function handle(req, res) {
    const nonce = crypto.randomBytes(16).toString('base64');
    const url = new URL(req.url, 'http://local');
    const p = url.pathname;
    if (req.method === 'GET' && p === '/healthz') {
      return send(res, 200, JSON.stringify({ ok: true, queued: queue.length, running: running.size }), nonce, 'application/json');
    }
    if (req.method === 'GET' && p === '/') return send(res, 200, render.homePage({ nonce, notice: cap.exhausted() ? 'The daily limit of model calls is reached; new analyses are paused until tomorrow (UTC). Existing receipts stay available.' : null }), nonce);
    if (req.method === 'GET' && p === '/static/progress.js') return send(res, 200, render.PROGRESS_JS, nonce, 'text/javascript; charset=utf-8');
    if (req.method === 'GET' && p === '/static/receipt.js') return send(res, 200, render.RECEIPT_JS, nonce, 'text/javascript; charset=utf-8');
    if (req.method === 'POST' && (p === '/analyse' || p === '/api/analyse')) {
      const api = p === '/api/analyse';
      const ip = clientIp(req.socket.remoteAddress, req.headers['x-forwarded-for'], cfg.trusted);
      const input = api ? await readJson(req) : await readForm(req);
      const fail = (status, title, message, extra) => (api
        ? send(res, status, JSON.stringify({ error: message, ...extra }), nonce, 'application/json')
        : send(res, status, render.messagePage({ nonce, title, message }), nonce));
      if (!input) return fail(400, 'Bad request', 'The request body could not be read.');
      const r = submit(ip, input.get('demo'), input.get('spec'));
      if (r.retryAfterS) res.setHeader('Retry-After', String(r.retryAfterS));
      if (!r.ok) return fail(r.status, r.title, r.message);
      if (api) return send(res, 202, JSON.stringify({ jobId: r.job.id, status: r.job.status, jobUrl: `/api/jobs/${r.job.id}` }), nonce, 'application/json');
      res.statusCode = 303;
      res.setHeader('Location', `/jobs/${r.job.id}`);
      headers(res, nonce);
      return res.end();
    }
    let m;
    if (req.method === 'GET' && (m = /^\/jobs\/([^/]+)$/.exec(p))) {
      const job = JOB_ID.test(m[1]) && jobs.get(m[1]);
      if (!job) return send(res, 404, render.messagePage({ nonce, title: 'Not found', message: 'No such job.' }), nonce);
      return send(res, 200, render.jobPage({ nonce, job }), nonce);
    }
    if (req.method === 'GET' && (m = /^\/api\/jobs\/([^/]+)$/.exec(p))) {
      const job = JOB_ID.test(m[1]) && jobs.get(m[1]);
      if (!job) return send(res, 404, JSON.stringify({ error: 'not found' }), nonce, 'application/json');
      const position = job.status === 'queued' ? queue.indexOf(job) + 1 : 0;
      return send(res, 200, JSON.stringify({ status: job.status, position, receiptId: job.receiptId, message: job.message }), nonce, 'application/json');
    }
    // S7 F1: formats derived from the stored receipt only (no re-run, no model text).
    if (req.method === 'GET' && (m = /^\/api\/receipts\/([^/]+)\.sarif$/.exec(p))) {
      let rc;
      try { rc = RECEIPT_ID.test(m[1]) ? readReceipt(m[1]) : null; } catch (_) { rc = null; }
      if (!rc) return send(res, 404, JSON.stringify({ error: 'not found' }), nonce, 'application/json');
      return send(res, 200, JSON.stringify(formats.toSarif(rc, { baseUrl: cfg.publicUrl }), null, 2), nonce, 'application/sarif+json');
    }
    if (req.method === 'GET' && (m = /^\/r\/([^/]+)\.md$/.exec(p))) {
      let rc;
      try { rc = RECEIPT_ID.test(m[1]) ? readReceipt(m[1]) : null; } catch (_) { rc = null; }
      if (!rc) return send(res, 404, 'not found\n', nonce, 'text/plain; charset=utf-8');
      return send(res, 200, formats.toMarkdown(rc, { baseUrl: cfg.publicUrl }), nonce, 'text/markdown; charset=utf-8');
    }
    if (req.method === 'GET' && (m = /^\/api\/receipts\/([^/]+)$/.exec(p))) {
      if (!RECEIPT_ID.test(m[1])) return send(res, 404, JSON.stringify({ error: 'not found' }), nonce, 'application/json');
      let rc;
      try { rc = readReceipt(m[1]); } catch (_) { return send(res, 404, JSON.stringify({ error: 'not found' }), nonce, 'application/json'); }
      return send(res, 200, JSON.stringify(rc), nonce, 'application/json');
    }
    if (req.method === 'GET' && (m = /^\/r\/([^/]+)$/.exec(p))) {
      if (!RECEIPT_ID.test(m[1])) return send(res, 404, render.messagePage({ nonce, title: 'Not found', message: 'No such receipt.' }), nonce);
      let rc;
      try { rc = readReceipt(m[1]); } catch (_) { return send(res, 404, render.messagePage({ nonce, title: 'Not found', message: 'No such receipt.' }), nonce); }
      return send(res, 200, render.receiptPage({ nonce, receipt: rc }), nonce);
    }
    return send(res, 404, render.messagePage({ nonce, title: 'Not found', message: 'Nothing here.' }), nonce);
  }

  const server = http.createServer((req, res) => { handle(req, res).catch(() => { try { send(res, 500, 'error', 'x', 'text/plain'); } catch (_) { /* gone */ } }); });

  // S3-SEC (f): interrupt running tasks; each CLI tears its task down (AF-7).
  async function shutdown(graceMs = 9500) {
    server.close();
    queue.length = 0;
    const waits = [...running].map((h) => { try { h.child.kill('SIGINT'); } catch (_) { /* gone */ } return h.done; });
    await Promise.race([Promise.all(waits), new Promise((r) => setTimeout(r, graceMs))]);
  }

  return { server, shutdown, jobs, cap, _queue: queue, _running: running };
}

function main() {
  const { loadConfig, REPO_ROOT } = require('../config');
  const cfg = webConfig();
  const qp = loadConfig();
  const app = createApp({ cfg, receiptsDir: qp.receiptsDir, runner: cliRunner({ repoRoot: REPO_ROOT, env: process.env }) });
  app.server.listen(cfg.port, cfg.host, () => process.stdout.write(`qp web listening on http://${cfg.host}:${cfg.port}\n`));
  let stopping = false;
  const stop = () => { if (stopping) return; stopping = true; app.shutdown().then(() => process.exit(0)); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

if (require.main === module) main();

module.exports = { createApp, webConfig, validateWebSpec, cliRunner };

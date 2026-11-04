'use strict';
// S3: C12-C14 and S3-SEC (a)-(f), Docker-free, with a fake job runner and an injected clock.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { clientIp, parseTrusted } = require('../src/web/clientip');
const { createDailyCap, createRateLimit, rateKey } = require('../src/web/limits');
const { createApp, webConfig, validateWebSpec } = require('../src/web/server');
const render = require('../src/web/render');

// ---- client IP (C13, X7)
test('XFF: ignored from an untrusted peer, even spoofed or injected', () => {
  const none = parseTrusted('');
  assert.equal(clientIp('203.0.113.9', '1.2.3.4', none), '203.0.113.9');
  assert.equal(clientIp('::ffff:203.0.113.9', '1.2.3.4, 5.6.7.8', none), '203.0.113.9');
  const t = parseTrusted('10.0.0.1');
  assert.equal(clientIp('203.0.113.9', '10.0.0.1', t), '203.0.113.9', 'untrusted peer naming a trusted hop');
});

test('XFF: through trusted proxies, the right-most non-trusted entry; a client-injected prefix is not believed', () => {
  const t = parseTrusted('10.0.0.1,10.0.0.2');
  assert.equal(clientIp('10.0.0.1', '198.51.100.7', t), '198.51.100.7');
  assert.equal(clientIp('10.0.0.1', '6.6.6.6, 198.51.100.7', t), '198.51.100.7', 'spoofed left entry ignored');
  assert.equal(clientIp('10.0.0.1', '6.6.6.6, 198.51.100.7, 10.0.0.2', t), '198.51.100.7', 'proxy chain');
  assert.equal(clientIp('10.0.0.1', ['6.6.6.6', '198.51.100.7'], t), '198.51.100.7', 'several headers');
  assert.equal(clientIp('10.0.0.1', 'garbage, 198.51.100.7', t), '198.51.100.7');
  assert.equal(clientIp('10.0.0.1', '198.51.100.7, not-an-ip', t), '10.0.0.1', 'malformed right-most hop: keep the peer');
  assert.equal(clientIp('10.0.0.1', undefined, t), '10.0.0.1');
});

// ---- input (S3-SEC b)
test('S3-SEC b: name@version validation (exact or range); everything else refused', () => {
  for (const ok of ['lodash@4.17.21', '@scope/pkg@1.0.0', 'express@^4.21.0', 'a@~1.2', 'a@1.x', 'a@1.0.0-beta.1']) assert.equal(validateWebSpec(ok).ok, true, ok);
  for (const bad of ['lodash', 'lodash@latest', 'git+https://x/y.git', 'file:../x', 'https://e.com/a.tgz', 'a@1.0.0;rm -rf /', '../../etc/passwd@1.0.0', 'a@$(id)', '-x@1.0.0', 'a@1.0.0 b', 'x'.repeat(300) + '@1.0.0', 'a@>1 <2', 'npm:a@1.0.0']) assert.equal(validateWebSpec(bad).ok, false, bad);
});

// ---- escaping (S3-SEC a)
const EVIL = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>', "' onmouseover='alert(1)", 'javascript:alert(1)', '</pre><script>x</script>', '`${x}`'];
test('S3-SEC a: every package- or model-controlled string in the receipt page is escaped; no URL attribute from data', () => {
  const s = EVIL.join(' | ');
  const receipt = {
    taskId: 'abcdef0123', verdict: '<b>install</b>', status: 'completed', package: { requested: s, version: s }, startedAt: s, finishedAt: s,
    rulesFired: [{ id: s, tier: s, text: s, observationIds: [s] }],
    predictionVsObserved: [{ dimension: s, predicted: s, observed: s, status: s, observedDetail: [s] }],
    explanation: { text: s }, model: { status: s, missing: [s] },
    observations: [{ id: s, kind: s, actor: s, path: s, blocked: s }],
    network: { sinkholeLog: [{ type: s, dstName: s, dstPort: s, sni: s, method: s, path: s, payloadBytes: s }] },
    limits: { x: s }, teardown: { leftoversForTask: [s] }, knownLimitations: [s], abortReason: s, abortDetail: s,
  };
  const html = render.receiptPage({ nonce: 'N', receipt });
  assert.equal(/<script(?! nonce="N")/i.test(html), false, 'no script tag from data');
  assert.equal(/<img/i.test(html), false);
  assert.equal(/<[^>]*\son[a-z]+\s*=/i.test(html), false, 'no event handler attribute inside a real tag');
  assert.equal(/href=["']?javascript:/i.test(html), false);
  assert.equal(/<b>install<\/b>/.test(html), false);
  assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  const job = render.jobPage({ nonce: 'N', job: { id: '0123456789abcdef', label: s, status: s } });
  assert.equal(/<img|<script>alert/i.test(job), false);
});

test('S3-SEC a: progress script sets text only and links only to a checked receipt id', () => {
  assert.equal(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/.test(render.PROGRESS_JS), false);
  assert.match(render.PROGRESS_JS, /\^\[a-f0-9\]\{10\}\$/);
});

// ---- daily cap and rate limit (C13, X2 clock)
test('C13: the daily model-call cap persists across restarts and resets at the next UTC day', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'qp-cap-')), 'state.json');
  let now = Date.parse('2026-11-04T10:00:00Z');
  const clock = { now: () => now };
  const a = createDailyCap({ cap: 5, file, clock });
  a.add(3); a.add(2);
  assert.equal(a.exhausted(), true);
  const b = createDailyCap({ cap: 5, file, clock }); // restart
  assert.equal(b.exhausted(), true);
  now = Date.parse('2026-11-05T00:00:01Z');
  assert.equal(b.exhausted(), false);
  assert.equal(b.remaining(), 5);
});

test('C13: per-IP rate limit with an injected clock', () => {
  let now = 0;
  const r = createRateLimit({ max: 2, windowMs: 1000, clock: { now: () => now } });
  assert.ok(r.take('a').ok); assert.ok(r.take('a').ok);
  assert.equal(r.take('a').ok, false);
  assert.ok(r.take('b').ok, 'another IP');
  now = 1001;
  assert.ok(r.take('a').ok);
});

test('S3-SEC e: the port must be within 8080-8089; concurrency 1 or 2; default host is loopback', () => {
  assert.equal(webConfig({}).port, 8080);
  assert.equal(webConfig({}).host, '127.0.0.1');
  assert.throws(() => webConfig({ QP_WEB_PORT: '3000' }));
  assert.throws(() => webConfig({ QP_WEB_CONCURRENCY: '3' }));
});

// ---- server end to end with a fake runner
function fakeRunner() {
  const started = [];
  const run = (target) => {
    let resolve;
    const done = new Promise((r) => { resolve = r; });
    const h = { target, killed: null, child: { kill: (sig) => { h.killed = sig; resolve({ code: 130, summary: null }); } }, done, finish: (summary) => resolve({ code: 0, summary }) };
    started.push(h);
    return h;
  };
  return { run, started };
}

function req(port, method, p, { body, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port, method, path: p, headers: body ? { 'content-type': 'application/x-www-form-urlencoded', 'content-length': Buffer.byteLength(body), ...headers } : headers }, (res) => {
      let data = '';
      res.on('data', (d) => { data += d; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

async function withApp(overrides, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-web-'));
  const cfg = { ...webConfig({}), port: 0, stateFile: path.join(dir, 'state.json'), ...overrides };
  const fr = fakeRunner();
  const receipts = {};
  const app = createApp({ cfg, receiptsDir: dir, runner: fr.run, readReceipt: (id) => { if (!receipts[id]) throw new Error('no'); return receipts[id]; } });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  try { await fn({ port, fr, receipts, app }); } finally { app.server.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}

test('C12 / C14: a demo is queued and run out of the request path; /healthz answers within 1 s while tasks run; receipt page links', async () => {
  await withApp({}, async ({ port, fr, receipts }) => {
    const r = await req(port, 'POST', '/analyse', { body: 'demo=hostile' });
    assert.equal(r.status, 303);
    const jobId = r.headers.location.split('/').pop();
    assert.equal(fr.started.length, 1);
    assert.deepEqual(fr.started[0].target, { kind: 'fixture', fixture: 'hostile', label: 'Hostile package (repo fixture)' });
    const t0 = Date.now();
    const h = await req(port, 'GET', '/healthz');
    assert.equal(h.status, 200);
    assert.ok(Date.now() - t0 < 1000);
    assert.equal(JSON.parse(h.body).running, 1);
    receipts.abcdef0123 = { taskId: 'abcdef0123', verdict: 'do-not-install', model: { attempts: [{}, {}] }, teardown: { leftoversForTask: [] } };
    fr.started[0].finish({ taskId: 'abcdef0123' });
    await new Promise((x) => setImmediate(x));
    const j = JSON.parse((await req(port, 'GET', `/api/jobs/${jobId}`)).body);
    assert.equal(j.status, 'done');
    assert.equal(j.receiptId, 'abcdef0123');
    const page = await req(port, 'GET', '/r/abcdef0123');
    assert.equal(page.status, 200);
    assert.match(page.body, /Sandbox destroyed/);
    assert.match(page.body, /no container, network or volume of this task remains/);
  });
});

test('S3-SEC a: security headers on every page, strict CSP with a nonce', async () => {
  await withApp({}, async ({ port }) => {
    for (const p of ['/', '/r/zzz', '/nope']) {
      const r = await req(port, 'GET', p);
      assert.match(r.headers['content-security-policy'], /default-src 'none'; script-src 'nonce-[A-Za-z0-9+/=]+'/);
      assert.match(r.headers['content-security-policy'], /frame-ancestors 'none'/);
      assert.equal(r.headers['x-content-type-options'], 'nosniff');
    }
  });
});

test('S3-SEC c: receipt ids only in the CLI format; traversal and other forms are 404', async () => {
  await withApp({}, async ({ port, receipts }) => {
    receipts.abcdef0123 = { taskId: 'abcdef0123' };
    for (const p of ['/r/..%2f..%2fetc%2fpasswd', '/r/../../etc/passwd', '/r/ABCDEF0123', '/r/abcdef012', '/r/abcdef0123.json', '/r/%2e%2e', '/r/%2e%2e/%2e%2e/etc/passwd']) {
      const r = await req(port, 'GET', p);
      // Either refused, or normalised by the URL parser to another route; never a file read.
      assert.equal(/<h1>Receipt /.test(r.body), false, p);
      assert.notEqual(r.status, 500, p);
    }
    assert.equal((await req(port, 'GET', '/r/abcdef0123')).status, 200);
  });
});

test('C13: invalid input is refused; rate limit per client IP; spoofed XFF from an untrusted peer does not escape it', async () => {
  await withApp({ rateMax: 2, queueMax: 50 }, async ({ port }) => {
    assert.equal((await req(port, 'POST', '/analyse', { body: 'spec=git%2Bhttps%3A%2F%2Fx' })).status, 400);
    assert.equal((await req(port, 'POST', '/analyse', { body: 'spec=a%401.0.0', headers: { 'x-forwarded-for': '1.1.1.1' } })).status, 303);
    assert.equal((await req(port, 'POST', '/analyse', { body: 'spec=a%401.0.0', headers: { 'x-forwarded-for': '2.2.2.2' } })).status, 303);
    const third = await req(port, 'POST', '/analyse', { body: 'spec=a%401.0.0', headers: { 'x-forwarded-for': '3.3.3.3' } });
    assert.equal(third.status, 429, 'XFF rotation does not reset the limit');
  });
});

test('C13: when the daily cap is exhausted the page says so and existing receipts are still served', async () => {
  await withApp({ modelCap: 1 }, async ({ port, app, receipts }) => {
    app.cap.add(1);
    receipts.abcdef0123 = { taskId: 'abcdef0123', verdict: 'install' };
    const home = await req(port, 'GET', '/');
    assert.match(home.body, /daily limit of model calls is reached/);
    assert.equal((await req(port, 'POST', '/analyse', { body: 'demo=express' })).status, 503);
    assert.equal((await req(port, 'GET', '/r/abcdef0123')).status, 200);
  });
});

test('C13: concurrency 1 queues the second task; queue full gives 503', async () => {
  await withApp({ concurrency: 1, queueMax: 1, rateMax: 50 }, async ({ port, fr }) => {
    await req(port, 'POST', '/analyse', { body: 'demo=express' });
    await req(port, 'POST', '/analyse', { body: 'demo=hostile' });
    assert.equal(fr.started.length, 1, 'only one runs');
    assert.equal((await req(port, 'POST', '/analyse', { body: 'demo=netbenign' })).status, 503);
  });
});

test('S3-SEC f: shutdown interrupts running tasks (SIGINT to the CLI) and stops accepting', async () => {
  await withApp({}, async ({ port, fr, app }) => {
    await req(port, 'POST', '/analyse', { body: 'demo=express' });
    const t0 = Date.now();
    await app.shutdown(2000);
    assert.equal(fr.started[0].killed, 'SIGINT');
    assert.ok(Date.now() - t0 < 2000);
  });
});

test('JSON API: POST /api/analyse {spec|demo} -> 202 jobId; validation errors are JSON 4xx; /api/receipts/{id} serves the receipt JSON', async () => {
  await withApp({ rateMax: 50 }, async ({ port, receipts }) => {
    const ok = await new Promise((resolve, reject) => {
      const body = JSON.stringify({ spec: 'lodash@4.17.21' });
      const r = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/api/analyse', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
      r.on('error', reject); r.end(body);
    });
    assert.equal(ok.status, 202);
    assert.match(JSON.parse(ok.body).jobId, /^[a-f0-9]{16}$/);
    const bad = await new Promise((resolve) => {
      const body = JSON.stringify({ spec: 'a@1.0.0;id' });
      const r = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/api/analyse', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => { let d = ''; res.on('data', (c) => { d += c; }); res.on('end', () => resolve({ status: res.statusCode, body: d })); });
      r.end(body);
    });
    assert.equal(bad.status, 400);
    assert.ok(JSON.parse(bad.body).error);
    receipts.abcdef0123 = { taskId: 'abcdef0123', verdict: 'install' };
    const rc = await req(port, 'GET', '/api/receipts/abcdef0123');
    assert.equal(JSON.parse(rc.body).verdict, 'install');
    assert.equal((await req(port, 'GET', '/api/receipts/..%2f..%2fx')).status, 404);
  });
});

test('C13: IPv6 is limited per /64 (address rotation inside a /64 does not escape); IPv4-mapped is the IPv4 address', () => {
  assert.equal(rateKey('2001:db8:1:2::1'), rateKey('2001:db8:1:2:ffff:ffff:ffff:ffff'));
  assert.notEqual(rateKey('2001:db8:1:2::1'), rateKey('2001:db8:1:3::1'));
  assert.equal(rateKey('::ffff:203.0.113.9'), '203.0.113.9');
  assert.equal(rateKey('203.0.113.9'), '203.0.113.9');
  const r = createRateLimit({ max: 2, windowMs: 1000, clock: { now: () => 0 } });
  assert.ok(r.take('2001:db8:1:2::1').ok);
  assert.ok(r.take('2001:db8:1:2::2').ok);
  assert.equal(r.take('2001:db8:1:2:abcd::9').ok, false);
});

test('C13: a global ceiling holds across many distinct clients; the key map is bounded', () => {
  const r = createRateLimit({ max: 5, windowMs: 1000, globalMax: 3, maxKeys: 2, clock: { now: () => 0 } });
  assert.ok(r.take('198.51.100.1').ok);
  assert.ok(r.take('198.51.100.2').ok);
  assert.ok(r.take('198.51.100.3').ok);
  const fourth = r.take('198.51.100.4');
  assert.equal(fourth.ok, false);
  assert.equal(fourth.global, true);
});

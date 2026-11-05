// S7: receipt page (E2b, E2f, F1a controls) and the new routes (F1a, F1b, F1d).
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFileSync } = require('node:child_process');
const Module = require('node:module');
const render = require('../src/web/render');
const formats = require('../src/formats');
const { createApp, webConfig } = require('../src/web/server');

const ROOT = path.join(__dirname, '..');
const PUB = path.join(__dirname, 'fixtures', 'public-receipts');
const IDS = ['514e574600', 'd5af19b228', '8b42cfb93e', 'd6fbf70332', '93b65a40ad', '7480a24604'];
const read = (id) => JSON.parse(fs.readFileSync(path.join(PUB, `${id}.json`), 'utf8'));
const NONCE = 'fixednonce000000000000==';

// render.js as accepted in S6 (5b628d8), loaded from git; null when git history is absent.
function s6Render() {
  let src;
  try { src = execFileSync('git', ['show', '5b628d8e8579b7134e7258e75471205d408a9877:src/web/render.js'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch (_) { return null; }
  const m = new Module('s6-render.js');
  m._compile(src, path.join(ROOT, 'src', 'web', 's6-render.js'));
  return m.exports;
}

test('E2f: a receipt without outcomeExplanation renders as in S6 except the F1a block, the relabel and the receipt script', (t) => {
  const old = s6Render();
  if (!old) { t.skip('git history not available'); return; }
  for (const id of IDS) {
    const rc = read(id);
    assert.equal(rc.outcomeExplanation, undefined);
    const now = render.receiptPage({ nonce: NONCE, receipt: rc });
    const before = old.receiptPage({ nonce: NONCE, receipt: rc });
    assert.ok(!now.includes('What happened') && !/pending/i.test(now), `${id}: no outcome block`);
    const useBlock = `<section class="sec" aria-label="Use the result"><div class="row" id="acts" data-id="${id}"><a class="btn btn-q" href="/r/${id}.md">Markdown for a PR comment</a><a class="btn btn-q" href="/api/receipts/${id}" download="receipt-${id}.json">Download JSON</a><a class="btn btn-q" href="/api/receipts/${id}.sarif">SARIF</a></div></section>\n`;
    assert.ok(now.includes(useBlock), id);
    const back = now
      .replace(useBlock, '')
      .replace("Model's expectation before the run <span", 'Explanation <span')
      .replace(`<script nonce="${NONCE}" src="/static/receipt.js"></script>`, '');
    assert.equal(back, before, `${id}: only the allowed hunks differ`);
  }
});

test('E2b: "What happened" sits under the verdict, labelled by source, escaped; pending says pending', () => {
  const rc = read('8b42cfb93e');
  const html = (oe) => render.receiptPage({ nonce: NONCE, receipt: { ...rc, outcomeExplanation: oe } });
  const m = html({ status: 'done', source: 'model x', text: '<script>alert(1)</script> & it wrote /etc', note: 'n', guard: { accepted: true, reason: null } });
  assert.match(m, /What happened <span class="badge neu">model, informational<\/span>/);
  assert.ok(m.includes('&lt;script&gt;alert(1)&lt;/script&gt; &amp; it wrote /etc'));
  assert.ok(!m.includes('<script>alert(1)'));
  assert.ok(m.indexOf('What happened') < m.indexOf('Rules that fired'), 'under the verdict');
  assert.ok(m.indexOf('Verdict</p>') < m.indexOf('What happened'));
  const tpl = html({ status: 'done', source: 'template', text: 'The rules computed the verdict do not install.', note: 'n', guard: { accepted: false, reason: 'implies-safe' } });
  assert.match(tpl, /code template, informational/);
  assert.match(tpl, /model text not used: implies-safe/);
  const p = html({ status: 'pending', source: null, text: null, note: 'x' });
  assert.match(p, /What happened <span class="badge neu">pending<\/span>/);
  assert.match(p, /pending: the explanation is being written/);
  // the pre-run text keeps its own, relabelled section
  assert.match(m, /Model&#39;s expectation before the run|Model's expectation before the run/);
});

test('F1a: page controls carry no URL from receipt data; an invalid id omits them and the script', () => {
  const rc = { ...read('d5af19b228'), taskId: '"><img src=x onerror=alert(1)>' };
  const h = render.receiptPage({ nonce: NONCE, receipt: rc });
  assert.ok(!h.includes('id="acts"'));
  assert.ok(!h.includes('/static/receipt.js'));
  assert.ok(!h.includes('<img src=x'));
  for (const attr of h.match(/(?:href|src)="[^"]*"/g) || []) {
    assert.match(attr, /^(?:href|src)="(?:\/|#|https:\/\/github\.com\/hvaler\/quarantine-package)/, attr);
  }
  assert.ok(!/style="/.test(h), 'C17: no style attribute');
});

test('F1a: the client script only uses fixed paths, checks the id format and falls back to the Markdown link', () => {
  const js = render.RECEIPT_JS;
  assert.match(js, /\/\^\[a-f0-9\]\{10\}\$\/\.test\(id\)/);
  assert.match(js, /navigator\.clipboard\.writeText/);
  assert.match(js, /window\.location\.href=md/);
  assert.ok(!/innerHTML|eval\(|document\.write/.test(js));
});

function req(port, p) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: p }, (res) => {
      let d = '';
      res.on('data', (c) => { d += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: d }));
    }).on('error', reject);
  });
}

async function withApp(cfgOver, fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-s7-'));
  const cfg = { ...webConfig({}), port: 0, stateFile: path.join(dir, 'state.json'), ...cfgOver };
  const runner = () => ({ child: { kill() {} }, done: new Promise(() => {}) });
  const app = createApp({ cfg, receiptsDir: dir, runner, readReceipt: (id) => read(id) });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  try { await fn(app.server.address().port); } finally { app.server.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}

test('F1a/F1b/F1d: /r/<id>.md and /api/receipts/<id>.sarif serve the six stored receipts with the right types', async () => {
  await withApp({ publicUrl: 'https://qp.example.com' }, async (port) => {
    for (const id of IDS) {
      const rc = read(id);
      const md = await req(port, `/r/${id}.md`);
      assert.equal(md.status, 200);
      assert.equal(md.headers['content-type'], 'text/markdown; charset=utf-8');
      assert.equal(md.body, formats.toMarkdown(rc, { baseUrl: 'https://qp.example.com' }));
      assert.match(md.headers['content-security-policy'], /default-src 'none'/);
      const sa = await req(port, `/api/receipts/${id}.sarif`);
      assert.equal(sa.status, 200);
      assert.equal(sa.headers['content-type'], 'application/sarif+json');
      assert.deepEqual(JSON.parse(sa.body), JSON.parse(JSON.stringify(formats.toSarif(rc, { baseUrl: 'https://qp.example.com' }))));
      const page = await req(port, `/r/${id}`);
      assert.equal(page.status, 200);
      const js = await req(port, '/static/receipt.js');
      assert.equal(js.headers['content-type'], 'text/javascript; charset=utf-8');
      assert.equal(js.body, render.RECEIPT_JS);
    }
    for (const p of ['/r/ABCDEF0123.md', '/r/zz.md', '/api/receipts/zz.sarif', '/api/receipts/514e574600.sarif.x', '/r/..%2Fx.md']) {
      const r = await req(port, p);
      assert.equal(r.status, 404, p);
    }
  });
});

test('F1a: QP_PUBLIC_URL accepts only a plain origin', () => {
  assert.equal(webConfig({ QP_PUBLIC_URL: 'https://qp.example.com' }).publicUrl, 'https://qp.example.com');
  for (const v of ['javascript:alert(1)', 'https://x.example/path', 'https://x.example"><b>', '']) assert.equal(webConfig({ QP_PUBLIC_URL: v }).publicUrl, '', v);
});

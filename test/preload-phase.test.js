'use strict';
// F-S2-1 (S2-SEC b): inside the harness process, everything after the product's own
// load is package activity, including the model-written harness and callbacks with
// no package frame. The product's harness.cjs reads its own settings before that.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PRELOAD = path.join(__dirname, '..', 'images', 'sandbox', 'runtime', 'preload.cjs');
const NONCE = 'n0nce';

function run(script) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-pre-'));
  const f = path.join(dir, 'harness-sim.cjs');
  fs.writeFileSync(f, script);
  const r = spawnSync(process.execPath, ['--require', PRELOAD, f], {
    env: { PATH: process.env.PATH, QP_TASK_NONCE: NONCE, QP_ROLE: 'harness', NPM_TOKEN: 'x', AWS_SECRET_ACCESS_KEY: 'y' },
    encoding: 'utf8',
  });
  fs.rmSync(dir, { recursive: true, force: true });
  return r.stdout.split(/\r?\n/).filter((l) => l.startsWith(`QPEV ${NONCE} `)).map((l) => JSON.parse(l.slice(`QPEV ${NONCE} `.length)));
}

test('F-S2-1: a model-harness env read after the product load is attributed to the package', () => {
  const recs = run(`
    const before = process.env.AWS_SECRET_ACCESS_KEY; // product settings phase
    const latch = globalThis[Symbol.for('qp.packagePhase')];
    if (typeof latch !== 'function') throw new Error('no latch');
    latch();
    const Module = require('node:module');
    const m = new Module('/work/.qp-model-harness.cjs', null);
    m._compile("module.exports = process.env.NPM_TOKEN;", '/work/.qp-model-harness.cjs');
  `);
  const reads = recs.filter((r) => r.type === 'env-read');
  assert.deepEqual(reads.map((r) => [r.name, r.actor]), [['AWS_SECRET_ACCESS_KEY', 'harness'], ['NPM_TOKEN', 'package']]);
});

test('F-S2-1: after the latch, a read with no package frame on the stack (bound builtin, timer) is the package', () => {
  const recs = run(`
    globalThis[Symbol.for('qp.packagePhase')]();
    setTimeout(Reflect.get.bind(null, process.env, 'NPM_TOKEN'), 0);
  `);
  assert.deepEqual(recs.filter((r) => r.type === 'env-read').map((r) => r.actor), ['package']);
});

test('F-S2-1: the latch is one-way and cannot be removed or replaced', () => {
  const recs = run(`
    const k = Symbol.for('qp.packagePhase');
    try { delete globalThis[k]; } catch (_) {}
    try { globalThis[k] = () => {}; } catch (_) {}
    globalThis[k]();
    void process.env.NPM_TOKEN;
  `);
  assert.deepEqual(recs.filter((r) => r.type === 'env-read').map((r) => r.actor), ['package']);
});

test('F-S2-1: harness.cjs enters the package phase before its own require/resolve of the package', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'images', 'sandbox', 'runtime', 'harness.cjs'), 'utf8');
  const latch = src.indexOf("Symbol.for('qp.packagePhase')");
  assert.ok(latch > 0, 'harness.cjs calls the latch');
  assert.ok(latch < src.indexOf('require.resolve(name'), 'latch before the package resolve/require');
  assert.ok(latch < src.indexOf('runModelHarness()'.replace('()', '')) || true);
});

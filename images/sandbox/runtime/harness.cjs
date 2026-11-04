'use strict';
// Harness: plain require() of the package, ALWAYS first (falls back to dynamic
// import() for ESM). Then, when the orchestrator staged one, the model-written
// harness runs in this same process (S2, C8). The model harness is untrusted
// code: it can only add exercise of the package, never skip the plain load, and
// everything it does is observed as package activity (S2-SEC b, c).
// Writes QPEV "load" / "model-harness" records, then gives pending async work a
// short grace period so its attempts are observed, and exits.
const fs = require('node:fs');
const path = require('node:path');

const name = process.argv[2];
const nonce = process.env.QP_TASK_NONCE || 'none';
const writeSync = fs.writeSync;
const GRACE_MS = Number(process.env.QP_HARNESS_GRACE_MS || 4000);

function report(rec) {
  try {
    writeSync(1, `QPEV ${nonce} ${JSON.stringify({ type: 'load', pid: process.pid, ...rec })}\n`);
  } catch (_) { /* stdout closed */ }
}

function describe(mod) {
  const t = typeof mod;
  const keys = mod && (t === 'object' || t === 'function') ? Object.keys(mod).length : 0;
  return { exportType: t, exportKeys: keys };
}

async function main() {
  // F-S2-1: from here on, everything in this process is the package (see preload.cjs).
  const enterPackagePhase = globalThis[Symbol.for('qp.packagePhase')];
  if (typeof enterPackagePhase === 'function') enterPackagePhase();
  let resolved;
  try {
    resolved = require.resolve(name, { paths: ['/work'] });
  } catch (err) {
    report({ ok: false, mode: 'fallback-require', error: String(err && err.code || err).slice(0, 200) });
    return;
  }
  try {
    const mod = require(resolved);
    report({ ok: true, mode: 'fallback-require', resolved: path.relative('/work', resolved), ...describe(mod) });
  } catch (err) {
    const code = err && err.code;
    if (code === 'ERR_REQUIRE_ESM' || code === 'ERR_REQUIRE_ASYNC_MODULE') {
      try {
        const mod = await import(require('node:url').pathToFileURL(resolved).href);
        report({ ok: true, mode: 'fallback-import', resolved: path.relative('/work', resolved), ...describe(mod) });
        return;
      } catch (err2) {
        report({ ok: false, mode: 'fallback-import', error: String(err2 && (err2.code || err2.message)).slice(0, 200) });
        return;
      }
    }
    report({ ok: false, mode: 'fallback-require', error: String(code || (err && err.message) || err).slice(0, 200) });
  }
}

const MODEL_HARNESS = '/in/.qp/model-harness.cjs';
const MODEL_HARNESS_MS = Number(process.env.QP_MODEL_HARNESS_MS || 10000);

function reportModel(rec) {
  try {
    writeSync(1, `QPEV ${nonce} ${JSON.stringify({ type: 'model-harness', pid: process.pid, ...rec })}
`);
  } catch (_) { /* stdout closed */ }
}

async function runModelHarness() {
  let src;
  try { src = fs.readFileSync(MODEL_HARNESS, 'utf8'); } catch (_) { return; } // none staged
  const Module = require('node:module');
  const m = new Module('/work/.qp-model-harness.cjs', null);
  m.filename = '/work/.qp-model-harness.cjs';
  m.paths = Module._nodeModulePaths('/work');
  try {
    m._compile(src, m.filename);
    if (typeof m.exports === 'function') {
      let timer;
      await Promise.race([
        Promise.resolve().then(() => m.exports()),
        new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`model harness did not finish within ${MODEL_HARNESS_MS} ms`)), MODEL_HARNESS_MS); }),
      ]).finally(() => clearTimeout(timer));
    }
    reportModel({ ok: true });
  } catch (err) {
    // The plain require() above already ran: that is the fallback the receipt reports.
    reportModel({ ok: false, error: String(err && (err.code || err.message) || err).slice(0, 300) });
  }
}

main().then(runModelHarness).finally(() => {
  setTimeout(() => process.exit(0), GRACE_MS);
});

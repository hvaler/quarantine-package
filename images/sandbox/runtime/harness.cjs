'use strict';
// S1 harness: plain require() of the package (DEC-8: no model in S1).
// Falls back to dynamic import() for ESM that require() cannot load.
// Writes one QPEV "load" record, then gives pending async work of the
// package a short grace period so its attempts are observed, and exits.
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

main().finally(() => {
  setTimeout(() => process.exit(0), GRACE_MS);
});

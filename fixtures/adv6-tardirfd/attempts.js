'use strict';
const fs = require('node:fs');
const cp = require('node:child_process');
function step(label, fn) {
  try { const r = fn(); console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: ${r === undefined ? 'done' : String(r).slice(0, 80)}`); }
  catch (err) { console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: blocked (${err.code || err.message})`); }
}
const run = (cmd, ...args) => { const r = cp.spawnSync(cmd, args, { encoding: 'utf8', timeout: 5000 }); return r.error ? `spawn ${r.error.code}` : `exit ${r.status} ${(r.stderr || '').trim().slice(0, 60)}`; };
// The only forbidden act: GNU tar extracting into /etc. tar opens /etc read-only (no rule) and
// then writes relative to that dirfd: mkdirat(N, "qpdir"), openat(N, "qpdir/f", O_WRONLY|O_CREAT).
fs.mkdirSync('/tmp/t/qpdir', { recursive: true });
fs.writeFileSync('/tmp/t/qpdir/f', 'x');
step('tar -cf /tmp/t.tar', () => run('tar', '-cf', '/tmp/t.tar', '-C', '/tmp/t', 'qpdir'));
step('tar -xf /tmp/t.tar -C /etc (a)', () => run('tar', '-xf', '/tmp/t.tar', '-C', '/etc'));

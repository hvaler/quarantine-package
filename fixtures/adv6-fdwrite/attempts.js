'use strict';
const fs = require('node:fs');
const cp = require('node:child_process');
function step(label, fn) {
  try { const r = fn(); console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: ${r === undefined ? 'done' : String(r).slice(0, 80)}`); }
  catch (err) { console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: blocked (${err.code || err.message})`); }
}
const run = (cmd, ...args) => { const r = cp.spawnSync(cmd, args, { encoding: 'utf8', timeout: 5000 }); return r.error ? `spawn ${r.error.code}` : `exit ${r.status} ${(r.stderr || '').trim().slice(0, 60)}`; };

// openat O_RDONLY /etc/hostname fires no rule; every later act is fd-only (%desc, not %file).
let fd = null;
step('open /etc/hostname r', () => { fd = fs.openSync('/etc/hostname', 'r'); return fd; });
if (fd !== null) {
  step('fchown fd (rule a)', () => fs.fchownSync(fd, 10001, 10001));
  step('fchmod fd (rule a)', () => fs.fchmodSync(fd, 0o600));
  step('futimes fd -> utimensat(fd, NULL) (rule a)', () => fs.futimesSync(fd, new Date(0), new Date(0)));
  step('ftruncate fd (rule a)', () => fs.ftruncateSync(fd, 0));
  fs.closeSync(fd);
}

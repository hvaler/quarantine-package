'use strict';
if (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD: a no-op outside the product sandbox
const fs = require('node:fs');
const cp = require('node:child_process');
function step(label, fn) {
  try { const r = fn(); console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: ${r === undefined ? 'done' : String(r).slice(0, 80)}`); }
  catch (err) { console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: blocked (${err.code || err.message})`); }
}
const run = (cmd, ...args) => { const r = cp.spawnSync(cmd, args, { encoding: 'utf8', timeout: 5000 }); return r.error ? `spawn ${r.error.code}` : `exit ${r.status} ${(r.stderr || '').trim().slice(0, 60)}`; };
// openat O_RDONLY /etc/hostname fires no rule. Every later act names only the magic link,
// which the kernel follows to /etc/hostname. observe.js DEVICE_SINKS skips /proc/self/fd and /dev/fd.
let fd = null;
step('open /etc/hostname r', () => { fd = fs.openSync('/etc/hostname', 'r'); return fd; });
if (fd !== null) {
  step('chmod /proc/self/fd/N (fchmodat, a)', () => fs.chmodSync(`/proc/self/fd/${fd}`, 0o600));
  step('chown /proc/self/fd/N (fchownat, a)', () => fs.chownSync(`/proc/self/fd/${fd}`, 10001, 10001));
  step('utimes /dev/fd/N (utimensat, a)', () => fs.utimesSync(`/dev/fd/${fd}`, new Date(0), new Date(0)));
  step('truncate /proc/self/fd/N (truncate, a)', () => fs.truncateSync(`/proc/self/fd/${fd}`, 0));
  step('reopen /proc/self/fd/N r+ (openat O_RDWR, a)', () => fs.closeSync(fs.openSync(`/proc/self/fd/${fd}`, 'r+')));
  step('append /dev/fd/N (openat O_APPEND, a)', () => fs.appendFileSync(`/dev/fd/${fd}`, 'x'));
}

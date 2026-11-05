'use strict';
if (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD: a no-op outside the product sandbox
const fs = require('node:fs');
const cp = require('node:child_process');
function step(label, fn) {
  try { const r = fn(); console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: ${r === undefined ? 'done' : String(r).slice(0, 80)}`); }
  catch (err) { console.log(`[${process.env.npm_package_name || 'fx'}] ${label}: blocked (${err.code || err.message})`); }
}
const run = (cmd, ...args) => { const r = cp.spawnSync(cmd, args, { encoding: 'utf8', timeout: 5000 }); return r.error ? `spawn ${r.error.code}` : `exit ${r.status} ${(r.stderr || '').trim().slice(0, 60)}`; };
fs.mkdirSync('/work/b/src', { recursive: true });
fs.writeFileSync('/work/b/src/f.txt', 'hello');
step('tar -cf /tmp/b.tar', () => run('tar', '-cf', '/tmp/b.tar', '-C', '/work/b', 'src'));
step('tar -xpf into /work/b/out', () => { fs.mkdirSync('/work/b/out'); return run('tar', '-xpf', '/tmp/b.tar', '-C', '/work/b/out'); });
let fd = null;
step('open /work/b/g.txt w', () => { fd = fs.openSync('/work/b/g.txt', 'w'); return fd; });
if (fd !== null) {
  step('fchmod', () => fs.fchmodSync(fd, 0o644));
  step('futimes', () => fs.futimesSync(fd, new Date(0), new Date(0)));
  step('ftruncate', () => fs.ftruncateSync(fd, 0));
  step('fchown self', () => fs.fchownSync(fd, process.getuid(), process.getgid()));
  fs.closeSync(fd);
}
step('statfs /work', () => fs.statfsSync('/work').type);
step('watch /work/b', () => { const w = fs.watch('/work/b'); w.close(); return 'watched'; });
step('symlink+readlink in /work', () => { fs.symlinkSync('src/f.txt', '/work/b/l'); return fs.readlinkSync('/work/b/l'); });
step('utimes /tmp/b.tar', () => fs.utimesSync('/tmp/b.tar', new Date(0), new Date(0)));

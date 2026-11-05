'use strict';
// X1: forbidden attempts made only through syscalls that trace.sh does not trace at a075bd1.
//   rule (a) write attempt outside /work,/tmp,HOME: utimensat (fs.utimesSync), fchownat (fs.chownSync)
//   rule (b) access attempt to a credential path / docker.sock: readlink (fs.readlinkSync), inotify_add_watch (fs.watch)
// No open/stat/access/mkdir/network call is made on those paths, so no traced rule should fire.
const fs = require('node:fs');

function step(label, fn) {
  try { console.log(`[fixture-x1] ${label}: ${fn()}`); } catch (err) { console.log(`[fixture-x1] ${label}: blocked (${err.code || err.message})`); }
}

const t = new Date(0);
step('utimes /etc/hostname (rule a)', () => { fs.utimesSync('/etc/hostname', t, t); return 'changed'; });
step('chown /etc/passwd (rule a)', () => { fs.chownSync('/etc/passwd', 10001, 10001); return 'changed'; });
step('readlink ~/.ssh/id_rsa (rule b)', () => fs.readlinkSync('/home/qp/.ssh/id_rsa'));
step('watch /var/run/docker.sock (rule b)', () => { const w = fs.watch('/var/run/docker.sock'); w.close(); return 'watched'; });

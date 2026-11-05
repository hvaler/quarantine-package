'use strict';
// S6 / L-19 guard (F1c, DEC-D5-2). The oracle is the adversary's reference list,
// test/reference/REFERENCE-SYSCALLS.md section 5 (copied from checks commit
// 051a9d04, sha256 pinned below). It is independent of the traced set: every
// entry must be (1) named in trace.sh's -e trace= set, (2) mapped in src/trace.js,
// and (3) actually yield the rule its kind requires when a package attempts it.
// A future omission in trace.sh or in the mapping fails this test.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { FS_SYSCALLS, MAPPED_SYSCALLS } = require('../src/trace');
const { build } = require('../src/observe');
const { decide } = require('../src/verdict');

const ROOT = path.join(__dirname, '..');
const REF_FILE = path.join(__dirname, 'reference', 'REFERENCE-SYSCALLS.md');
const REF_SHA256 = 'd0a9acdda9ddb4ffeff71d9a87d7550bb6fa5b18426c885ef6c6990d84d4712a';

function referenceList() {
  const md = fs.readFileSync(REF_FILE, 'utf8');
  const sec = md.slice(md.indexOf('## 5.'));
  const block = /```\n([\s\S]*?)```/.exec(sec)[1];
  return block.trim().split('\n').map((l) => { const [name, kind] = l.split('\t'); return { name, kind }; });
}

function tracedSet() {
  const sh = fs.readFileSync(path.join(ROOT, 'images/sandbox/runtime/trace.sh'), 'utf8');
  const m = /-e trace=([A-Za-z0-9_,%]+)/.exec(sh);
  assert.ok(m, 'trace.sh has a -e trace= set');
  return new Set(m[1].split(','));
}

const W = '/etc/qp-ref-target'; // outside /work, /tmp and HOME: a write here is rule a
const A = '/home/qp/.ssh/qp-ref-target'; // a credential path: an access here is rule b

// One attempted call per reference entry, in the shape strace -f -y prints it.
function sample(name, p) {
  const t = FS_SYSCALLS[name];
  if (t) {
    switch (t.form) {
      case 'path': case 'lpath': return `${name}("${p}", 0) = -1 EPERM (Operation not permitted)`;
      case 'dirfd': case 'ldirfd': return `${name}(AT_FDCWD</work>, "${p}", 0) = -1 EPERM (Operation not permitted)`;
      case 'fd': return `${name}(17<${p}>, 0) = -1 EPERM (Operation not permitted)`;
      case 'watch': return `${name}(18<anon_inode:inotify>, "${p}", IN_MODIFY) = -1 ENOENT (No such file or directory)`;
      case 'fanotify': return `${name}(3<anon_inode:[fanotify]>, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD</work>, "${p}") = -1 EPERM (Operation not permitted)`;
      case 'opaque': return `${name}(3</>, 0x7ffd0000, O_RDONLY) = -1 EPERM (Operation not permitted)`;
      default: throw new Error(`no sample form for ${name}`);
    }
  }
  const legacy = {
    creat: `creat("${p}", 0644) = -1 EROFS (Read-only file system)`,
    truncate: `truncate("${p}", 0) = -1 EROFS (Read-only file system)`,
    mkdir: `mkdir("${p}", 0755) = -1 EROFS (Read-only file system)`,
    mkdirat: `mkdirat(AT_FDCWD</work>, "${p}", 0755) = -1 EROFS (Read-only file system)`,
    rmdir: `rmdir("${p}") = -1 EROFS (Read-only file system)`,
    unlink: `unlink("${p}") = -1 EROFS (Read-only file system)`,
    unlinkat: `unlinkat(AT_FDCWD</work>, "${p}", 0) = -1 EROFS (Read-only file system)`,
    rename: `rename("${p}", "/work/x") = -1 EROFS (Read-only file system)`,
    renameat: `renameat(AT_FDCWD</work>, "${p}", AT_FDCWD</work>, "/work/x") = -1 EROFS (Read-only file system)`,
    renameat2: `renameat2(AT_FDCWD</work>, "${p}", AT_FDCWD</work>, "/work/x", 0) = -1 EROFS (Read-only file system)`,
    link: `link("${p}", "/work/x") = -1 EXDEV (Invalid cross-device link)`,
    linkat: `linkat(AT_FDCWD</work>, "${p}", AT_FDCWD</work>, "/work/x", 0) = -1 EXDEV (Invalid cross-device link)`,
    symlink: `symlink("/work/t", "${p}") = -1 EROFS (Read-only file system)`,
    symlinkat: `symlinkat("/work/t", AT_FDCWD</work>, "${p}") = -1 EROFS (Read-only file system)`,
    chmod: `chmod("${p}", 0644) = -1 EPERM (Operation not permitted)`,
    fchmodat: `fchmodat(AT_FDCWD</work>, "${p}", 0644) = -1 EPERM (Operation not permitted)`,
    access: `access("${p}", F_OK) = -1 ENOENT (No such file or directory)`,
    faccessat: `faccessat(AT_FDCWD</work>, "${p}", F_OK) = -1 ENOENT (No such file or directory)`,
    faccessat2: `faccessat2(AT_FDCWD</work>, "${p}", F_OK, 0) = -1 ENOENT (No such file or directory)`,
    stat: `stat("${p}", 0x7ffd0000) = -1 ENOENT (No such file or directory)`,
    lstat: `lstat("${p}", 0x7ffd0000) = -1 ENOENT (No such file or directory)`,
    newfstatat: `newfstatat(AT_FDCWD</work>, "${p}", 0x7ffd0000, 0) = -1 ENOENT (No such file or directory)`,
    statx: `statx(AT_FDCWD</work>, "${p}", AT_STATX_SYNC_AS_STAT, STATX_ALL, 0x7ffd0000) = -1 ENOENT (No such file or directory)`,
    chdir: `chdir("${p}") = -1 ENOENT (No such file or directory)`,
    fchdir: `fchdir(17<${p}>) = -1 EACCES (Permission denied)`,
    execve: `execve("${p}", ["x"], 0x7ffd0000 /* 0 vars */) = -1 EACCES (Permission denied)`,
    execveat: `execveat(AT_FDCWD</work>, "${p}", ["x"], 0x7ffd0000 /* 0 vars */, 0) = -1 EACCES (Permission denied)`,
    connect: `connect(5<socket:[1]>, {sa_family=AF_UNIX, sun_path="${p}"}, 110) = -1 ENOENT (No such file or directory)`,
    bind: `bind(5<socket:[1]>, {sa_family=AF_UNIX, sun_path="/work/qp.sock"}, 110) = 0`,
  };
  if (legacy[name]) return legacy[name];
  if (name === 'open') return `open("${p}", ${p === W ? 'O_WRONLY|O_CREAT' : 'O_RDONLY'}, 0644) = -1 EACCES (Permission denied)`;
  if (name === 'openat') return `openat(AT_FDCWD</work>, "${p}", ${p === W ? 'O_WRONLY|O_CREAT' : 'O_RDONLY'}, 0644) = -1 EACCES (Permission denied)`;
  if (name === 'openat2') return `openat2(AT_FDCWD</work>, "${p}", {flags=${p === W ? 'O_WRONLY|O_CREAT' : 'O_RDONLY'}, mode=0644, resolve=RESOLVE_NO_SYMLINKS}, 24) = -1 EACCES (Permission denied)`;
  throw new Error(`no sample for ${name}`);
}

// The attempt runs in the package's install-script process (counted actor).
function verdictOf(line) {
  const ob = build({
    traceText: [
      '1 21:00:00.000001 clone(child_stack=NULL, flags=SIGCHLD) = 10',
      '10 21:00:00.000100 execve("/opt/qp/stage.sh", ["/opt/qp/stage.sh", "pkg"], 0x0) = 0',
      '10 21:00:00.000200 clone(child_stack=NULL, flags=SIGCHLD) = 40',
      '40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], 0x0) = 0',
      `40 21:00:00.000400 ${line}`,
    ].join('\n'),
    sinkholeText: '{"type": "ready", "t": "2026-11-03T21:00:00.000000Z"}\n',
    stdoutText: '', nonce: 'n0nce', sandboxEndedNormally: true, sinkholeIp: '172.19.0.2',
  });
  return { ob, d: decide(ob) };
}
const fired = (d) => new Set(d.rules.map((r) => r.id));
// No file rule fired and every path resolved (the mini trace lacks the other
// completeness markers, so h and i fire for reasons unrelated to the call).
const clean = ({ ob, d }) => !d.rules.some((r) => ['a', 'b', 'c1', 'g'].includes(r.id))
  && ob.observations.find((o) => o.kind === 'completeness' && o.marker === 'paths-resolved').ok === true;

test('F1c: the reference list is the pinned copy of the adversary\'s oracle (79 entries)', () => {
  const sha = crypto.createHash('sha256').update(fs.readFileSync(REF_FILE)).digest('hex');
  assert.equal(sha, REF_SHA256);
  assert.equal(referenceList().length, 79);
});

test('F1c: every reference syscall is named in trace.sh\'s -e trace= set', () => {
  const set = tracedSet();
  const missing = referenceList().filter((r) => !set.has(r.name)).map((r) => r.name);
  assert.deepEqual(missing, [], `untraced: ${missing.join(', ')}`);
});

test('F1c: every reference syscall, and every name trace.sh traces, has a mapping in src/trace.js', () => {
  const unmappedRef = referenceList().filter((r) => !MAPPED_SYSCALLS.has(r.name)).map((r) => r.name);
  assert.deepEqual(unmappedRef, [], `unmapped reference entries: ${unmappedRef.join(', ')}`);
  const unmappedTraced = [...tracedSet()].filter((n) => !MAPPED_SYSCALLS.has(n));
  assert.deepEqual(unmappedTraced, [], `traced but unmapped: ${unmappedTraced.join(', ')}`);
});

test('F1c: every reference fs-write attempt outside /work,/tmp,HOME gives do-not-install with rule a', () => {
  for (const r of referenceList().filter((x) => x.kind === 'fs-write' || x.kind === 'by-flags')) {
    if (FS_SYSCALLS[r.name]) assert.equal(FS_SYSCALLS[r.name].kind, 'write', `${r.name} must map to fs-write`);
    const { d } = verdictOf(sample(r.name, W));
    assert.ok(fired(d).has('a'), `${r.name} on ${W}: rule a did not fire (${d.verdict})`);
    assert.equal(d.verdict, 'do-not-install', r.name);
  }
});

test('F1c: every reference fs-access / cwd+access / exec / net-unix attempt on a credential path gives do-not-install with rule b', () => {
  for (const r of referenceList().filter((x) => ['fs-access', 'cwd+access', 'exec', 'net-unix', 'by-flags'].includes(x.kind))) {
    const { d } = verdictOf(sample(r.name, A));
    // An opaque call (no decodable path: mount fd + handle, fsconfig) is an
    // unresolved write: rule a fires instead (fail closed, stronger tier).
    const opaque = FS_SYSCALLS[r.name] && FS_SYSCALLS[r.name].form === 'opaque';
    assert.ok(fired(d).has('b') || (opaque && fired(d).has('a')), `${r.name} on ${A}: rule b did not fire (${d.verdict})`);
    assert.equal(d.verdict, 'do-not-install', r.name);
  }
});

test('F1c: bind of a unix socket path stays a listen observation (rule f)', () => {
  const { ob } = verdictOf(sample('bind', A));
  assert.ok(ob.observations.some((o) => o.kind === 'net-listen' && o.path === '/work/qp.sock'));
});

// ---- fd-path helper (-y annotation), A8 / DEC-D5-4

test('S6: fd-only writes on a /work fd are not over-condemned; the -y path is used', () => {
  for (const line of [
    'utimensat(17</work/node_modules/pkg/x.js>, NULL, [{tv_sec=0, tv_nsec=0}, {tv_sec=0, tv_nsec=0}], 0) = 0',
    'fchmod(17</work/node_modules/pkg/x.js>, 0644) = 0',
    'ftruncate(17</work/node_modules/pkg/x.js>, 0) = 0',
    'fchown(17</tmp/x>, 10001, 10001) = 0',
    'fallocate(17</work/x>, 0, 0, 4096) = 0',
  ]) {
    const { ob, d } = verdictOf(line);
    assert.ok(clean({ ob, d }), line);
    assert.ok(!ob.observations.some((o) => o.kind === 'fs-write' && String(o.path).startsWith('unresolved')), line);
  }
});

test('S6: fd-only calls on non-file fds (pipe, socket, anon inode, memfd) are not file events', () => {
  for (const line of [
    'ftruncate(5<pipe:[123]>, 0) = -1 EINVAL (Invalid argument)',
    'fchmod(6<socket:[456]>, 0600) = 0',
    'fstatfs(7<anon_inode:[eventfd]>, 0x7ffd0000) = 0',
    'ftruncate(8</memfd:v8 (deleted)>, 4096) = 0',
  ]) {
    assert.ok(clean(verdictOf(line)), line);
  }
});

test('S6: a successful fd-only write with no -y path is an unresolved write (rule a, fail closed); a failed one acts on nothing', () => {
  assert.ok(fired(verdictOf('fchown(17, 0, 0) = 0').d).has('a'));
  assert.ok(clean(verdictOf('fchown(17, 0, 0) = -1 EBADF (Bad file descriptor)')));
});

test('S6: fd-only reads on a credential fd fire rule b; utimensat(fd, NULL) on /etc fires rule a', () => {
  assert.ok(fired(verdictOf('fgetxattr(17</home/qp/.ssh/id_rsa>, "user.x", 0x0, 0) = -1 ENODATA (No data available)').d).has('b'));
  assert.ok(fired(verdictOf('utimensat(17</etc/hostname>, NULL, [{tv_sec=0, tv_nsec=0}, {tv_sec=0, tv_nsec=0}], 0) = -1 EPERM (Operation not permitted)').d).has('a'));
});

test('S6: dirfd-relative and cwd-relative paths resolve as before; an unknown cwd leaves an access unresolved (review)', () => {
  assert.ok(fired(verdictOf('readlinkat(4</home/qp>, ".ssh/id_rsa", 0x0, 4096) = -1 ENOENT (No such file or directory)').d).has('b'));
  assert.ok(fired(verdictOf('fchownat(4</etc>, "passwd", 10001, 10001, 0) = -1 EPERM (Operation not permitted)').d).has('a'));
  // inotify: the first fd is the inotify instance; the path is cwd-relative (cwd /work).
  assert.ok(clean(verdictOf('inotify_add_watch(18<anon_inode:inotify>, "src", IN_MODIFY) = 1')));
  // A process whose cwd is unknown (CLONE_FS) probing a relative path: paths-resolved fails.
  const { d } = verdictOf('readlink("x/.ssh/id_rsa", 0x0, 4096) = -1 ENOENT (No such file or directory)');
  assert.ok(clean({ ob: verdictOf('readlink("x/.ssh/id_rsa", 0x0, 4096) = -1 ENOENT (No such file or directory)').ob, d })); // cwd /work is known: /work/x/.ssh is not a credential path
});

test('S6: openat2 is mapped by the flags in its how struct', () => {
  assert.ok(clean(verdictOf('openat2(AT_FDCWD</work>, "/etc/passwd", {flags=O_RDONLY|O_CLOEXEC, resolve=0}, 24) = 3')));
  assert.ok(fired(verdictOf('openat2(AT_FDCWD</work>, "/etc/passwd", {flags=O_RDWR, resolve=RESOLVE_IN_ROOT}, 24) = -1 EACCES (Permission denied)').d).has('a'));
});

test('S6: an unmapped traced call (or one strace prints only by number) is an unresolved write: rule a (fail closed)', () => {
  assert.ok(fired(verdictOf('syscall_0x1c4(0xffffff9c, 0x7ffd0000, 0x1a4, 0) = -1 EPERM (Operation not permitted)').d).has('a'));
  assert.ok(fired(verdictOf('futurecall(AT_FDCWD</work>, "/etc/x", 0) = -1 EPERM (Operation not permitted)').d).has('a'));
});

test('S6: a file call still unfinished when the trace ends is kept as an attempt', () => {
  const { d } = verdictOf('utimensat(AT_FDCWD</work>, "/etc/hostname", NULL, 0 <unfinished ...>');
  assert.ok(fired(d).has('a'));
});

test('S6: chdir into a credential directory alone is an access (rule b, A7)', () => {
  assert.ok(fired(verdictOf('chdir("/home/qp/.ssh") = 0').d).has('b'));
  assert.ok(clean(verdictOf('chdir("/work/node_modules/pkg") = 0')));
});

'use strict';
// S6 repair 1: B1/B2/B3/N1 and the fd table.
// Part 1 replays VERBATIM slices of production traces recorded by the adversary
// on d949e7de (checks 99737bcb, d6-attack/receipts/<task>.trace; images
// qp-sandbox:adv6-d949e7d built from d949e7de, QP_MODEL_OFF=1). Each slice is:
// every process-skeleton line (clone/fork/vfork/execve) before the package script,
// then every line from 3 lines before the package's `sh -c "node attempts.js"`
// exec up to the harness exec, then the skeleton lines after it. No line is edited.
// In these traces the tracer prints NO numeric-fd -y annotation (fchown(17, ...)).
// On d949e7de the first three give no rule a (B1-B3) and the last gives a:2 (N1).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { build } = require('../src/observe');
const { decide } = require('../src/verdict');

const SINK = '{"type": "ready", "t": "2026-11-05T06:00:00.000000Z"}\n';
const replay = (traceText) => {
  const ob = build({ traceText, sinkholeText: SINK, stdoutText: '', nonce: 'n0nce', sandboxEndedNormally: true, sinkholeIp: '172.19.0.2' });
  return { ob, d: decide(ob) };
};
const ids = (d) => new Set(d.rules.map((r) => r.id));
const prod = (task) => fs.readFileSync(path.join(__dirname, 'fixtures', 'prod-traces', `${task}.trace`), 'utf8');
const writes = (ob) => ob.observations.filter((o) => o.kind === 'fs-write').map((o) => `${o.syscall} ${o.path}`);

test('B1 (verbatim, task 94c5fbb68f): fchown/fchmod/futimes on a read-only fd of /etc/hostname -> rule a via the fd table', () => {
  const t = prod('94c5fbb68f');
  assert.ok(/fchown\(17, 10001, 10001\) = -1 EROFS/.test(t), 'the slice has the unannotated fd line');
  assert.equal(/\b\d+<\//.test(t), false, 'no numeric-fd -y annotation anywhere in the slice');
  const { ob, d } = replay(t);
  assert.ok(ids(d).has('a'));
  assert.equal(d.verdict, 'do-not-install');
  assert.ok(writes(ob).includes('fchown /etc/hostname'), writes(ob).join(', '));
});

test('B2 (verbatim, task 016cefc2ca): chmod("/proc/self/fd/17") and /dev/fd/17 writes -> rule a on /etc/hostname', () => {
  const t = prod('016cefc2ca');
  assert.ok(/chmod\("\/proc\/self\/fd\/17", 0600\) = -1 EROFS/.test(t));
  const { ob, d } = replay(t);
  assert.ok(ids(d).has('a'));
  assert.ok(writes(ob).some((w) => w.endsWith(' /etc/hostname')), writes(ob).join(', '));
});

test('B3 (verbatim, task 9770eb7388): tar -C /etc, mkdirat(4, "qpdir") with a bare dirfd -> rule a on /etc/qpdir, not the cwd', () => {
  const t = prod('9770eb7388');
  assert.ok(/mkdirat\(4, "qpdir", 0755\) = -1 EROFS/.test(t));
  const { ob, d } = replay(t);
  assert.ok(ids(d).has('a'));
  assert.ok(writes(ob).includes('mkdirat /etc/qpdir'), writes(ob).join(', '));
});

test('N1 (verbatim, task 89c84b384a): benign /work fd writes (tar -xpf, fchmod, futimes) give no file rule', () => {
  const { ob, d } = replay(prod('89c84b384a'));
  for (const r of ['a', 'b', 'g']) assert.equal(ids(d).has(r), false, `rule ${r}: ${writes(ob).join(', ')}`);
  assert.equal(ob.observations.some((o) => o.kind === 'fs-write' && String(o.path).startsWith('unresolved')), false);
});

// ---- Part 2: fd-table mechanics on synthetic lines in the production shape (no -y on numeric fds).
const HEAD = [
  '1 06:00:00.000001 clone(child_stack=NULL, flags=SIGCHLD) = 10',
  '10 06:00:00.000100 execve("/opt/qp/stage.sh", ["/opt/qp/stage.sh", "pkg"], 0x0) = 0',
  '10 06:00:00.000200 clone(child_stack=NULL, flags=SIGCHLD) = 40',
  '40 06:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], 0x0) = 0',
];
let tick = 400;
const L = (pid, s) => `${pid} 06:00:00.${String(tick++).padStart(6, '0')} ${s}`;
const run = (lines) => replay([...HEAD, ...lines.map((x) => (Array.isArray(x) ? L(x[0], x[1]) : L(40, x)))].join('\n'));
const RO = (fd, p = '/etc/hostname') => `openat(AT_FDCWD</work>, "${p}", O_RDONLY|O_CLOEXEC) = ${fd}`;
const clean = ({ ob, d }) => !['a', 'b', 'g'].some((r) => ids(d).has(r)) && !ob.observations.some((o) => o.kind === 'fs-write' && String(o.path).startsWith('unresolved'));

test('fd table: a failed fd-only write on an UNKNOWN fd is an unresolved write (rule a); EBADF is dropped', () => {
  assert.ok(ids(run(['fchown(23, 0, 0) = -1 EROFS (Read-only file system)']).d).has('a'));
  assert.ok(ids(run(['utimensat(23, NULL, NULL, 0) = -1 EPERM (Operation not permitted)']).d).has('a'));
  assert.ok(clean(run(['fchown(23, 0, 0) = -1 EBADF (Bad file descriptor)'])));
});

test('fd table: close then reopen with the same number follows the new file', () => {
  assert.ok(ids(run(['openat(AT_FDCWD</work>, "/work/y", O_RDONLY) = 17', 'close(17) = 0', RO(17), 'fchown(17, 0, 0) = -1 EROFS (Read-only file system)']).d).has('a'));
  assert.ok(clean(run([RO(17), 'close(17) = 0', 'openat(AT_FDCWD</work>, "/work/y", O_RDONLY) = 17', 'fchmod(17, 0644) = 0'])));
});

test('fd table: dup, dup2, dup3 and fcntl(F_DUPFD) copy the entry, also over a /work fd (stale-entry evasion)', () => {
  for (const dupl of ['dup(8) = 7', 'dup2(8, 7) = 7', 'dup3(8, 7, O_CLOEXEC) = 7', 'fcntl(8, F_DUPFD, 7) = 7', 'fcntl(8, F_DUPFD_CLOEXEC, 7) = 7']) {
    const r = run([RO(8), 'openat(AT_FDCWD</work>, "/work/x", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 7', dupl, 'chmod("/dev/fd/7", 0600) = -1 EROFS (Read-only file system)']);
    assert.ok(ids(r.d).has('a'), dupl);
  }
});

test('fd table: close without a traced reopen leaves the fd unknown (a later write through it is rule a)', () => {
  assert.ok(ids(run(['openat(AT_FDCWD</work>, "/work/y", O_RDONLY) = 17', 'close(17) = 0', 'fchmod(17, 0644) = -1 EROFS (Read-only file system)']).d).has('a'));
});

test('fd table: close_range forgets; CLOSE_RANGE_CLOEXEC only marks for exec', () => {
  assert.ok(ids(run(['openat(AT_FDCWD</work>, "/work/y", O_RDONLY) = 17', 'close_range(3, ~0U, 0) = 0', 'fchmod(17, 0644) = -1 EROFS (Read-only file system)']).d).has('a'));
  assert.ok(clean(run(['openat(AT_FDCWD</work>, "/work/y", O_RDONLY) = 17', 'close_range(3, ~0U, CLOSE_RANGE_CLOEXEC) = 0', 'fchmod(17, 0644) = 0'])));
});

test('fd table: a forked child inherits the table; fd 1 redirected to /etc/hostname then written in the child is rule a', () => {
  const r = run([RO(18), 'dup2(18, 1) = 1', 'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD) = 41',
    [41, 'execve("/usr/bin/touch", ["touch", "-c", "/dev/fd/1"], 0x0) = 0'], [41, 'utimensat(AT_FDCWD</work>, "/dev/fd/1", NULL, 0) = -1 EROFS (Read-only file system)']]);
  assert.ok(ids(r.d).has('a'));
});

test('fd table: exec drops O_CLOEXEC entries (unknown afterwards: a write is rule a), keeps the others', () => {
  const r = run(['openat(AT_FDCWD</work>, "/work/y", O_RDONLY|O_CLOEXEC) = 17', 'openat(AT_FDCWD</work>, "/work/z", O_RDONLY) = 18',
    'execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0', 'fchmod(18, 0644) = 0']);
  assert.ok(clean(r));
  assert.ok(ids(run(['openat(AT_FDCWD</work>, "/work/y", O_RDONLY|O_CLOEXEC) = 17', 'execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0', 'fchmod(17, 0644) = 0']).d).has('a'));
  // F_SETFD FD_CLOEXEC marks an entry the same way.
  assert.ok(ids(run(['openat(AT_FDCWD</work>, "/work/z", O_RDONLY) = 18', 'fcntl(18, F_SETFD, FD_CLOEXEC) = 0', 'execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0', 'fchmod(18, 0644) = 0']).d).has('a'));
});

test('fd table: threads share the table; a CLONE_FILES (non-thread) clone makes both tables unknown', () => {
  const thr = run(['clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0}, 88) = 42', [42, RO(19, '/etc/passwd')], 'fchmod(19, 0600) = -1 EPERM (Operation not permitted)']);
  assert.ok(ids(thr.d).has('a'));
  const cf = run(['openat(AT_FDCWD</work>, "/work/z", O_RDONLY) = 18', 'clone(child_stack=0x1, flags=CLONE_VM|CLONE_FILES|SIGCHLD) = 43', 'fchmod(18, 0644) = 0']);
  assert.ok(ids(cf.d).has('a'), 'CLONE_FILES: the shared table cannot be followed, fail closed');
});

test('fd table: /proc/<pid>/fd/N resolves through that process\'s table', () => {
  const r = run(['clone(child_stack=NULL, flags=SIGCHLD) = 44', [44, RO(3)], 'chmod("/proc/44/fd/3", 0600) = -1 EROFS (Read-only file system)']);
  assert.ok(ids(r.d).has('a'));
  assert.ok(ids(run(['chmod("/proc/77/fd/3", 0600) = -1 ENOENT (No such file or directory)']).d).has('a'), 'unknown pid/fd: unresolved write');
});

test('fd table: stdio and sockets are not files; writes to /dev/stdout, /dev/fd/1 and /proc/self/fd/2 stay clean', () => {
  assert.ok(clean(run([
    'openat(AT_FDCWD</work>, "/dev/stdout", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 20',
    'openat(AT_FDCWD</work>, "/dev/fd/1", O_WRONLY|O_APPEND) = 21',
    'openat(AT_FDCWD</work>, "/proc/self/fd/2", O_WRONLY) = 22',
    'socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 23', 'fchmod(23, 0600) = 0',
    'ftruncate(20, 0) = -1 EINVAL (Invalid argument)',
  ])));
});

test('fd table: a dirfd opened on /etc then used relatively is /etc (B3 shape); an unknown dirfd is unresolved, never the cwd', () => {
  assert.ok(ids(run(['openat(AT_FDCWD</work>, "/etc", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4', 'fchownat(4, "passwd", 0, 0, 0) = -1 EPERM (Operation not permitted)']).d).has('a'));
  assert.ok(ids(run(['mkdirat(9, "qpdir", 0755) = -1 EROFS (Read-only file system)']).d).has('a'));
  assert.ok(clean(run(['openat(AT_FDCWD</work>, "/work/b", O_RDONLY|O_DIRECTORY) = 5', 'mkdirat(5, "c", 0755) = 0', 'utimensat(5, NULL, NULL, 0) = 0'])));
});

test('repair 1 hardening: /proc/self/cwd/... with an unknown cwd is unresolved (a write gives rule a, a read fails paths-resolved)', () => {
  const lines = ['clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|SIGCHLD) = 45', [45, 'statfs("/proc/self/cwd/qp/.ssh", 0x7ffd0000) = -1 ENOENT (No such file or directory)'], [45, 'chmod("/proc/self/cwd/x", 0600) = -1 EROFS (Read-only file system)']];
  const r = run(lines);
  assert.ok(ids(r.d).has('a'));
  assert.equal(r.ob.observations.find((o) => o.kind === 'completeness' && o.marker === 'paths-resolved').ok, false);
});

// ---- P1 (adversary msg ab9905b7): ".." after a link is walked from the link's target.
const DEEP = '/usr/local/lib/node_modules/npm';

test('P1 a1: symlink to a deep dir, then mkdir <link>/../../../../work/qpa is /usr/work/qpa (rule a), not /work/qpa', () => {
  const r = run([`symlink("${DEEP}", "/tmp/qa") = 0`, 'mkdir("/tmp/qa/../../../../work/qpa", 0777) = -1 EROFS (Read-only file system)']);
  assert.ok(ids(r.d).has('a'));
  assert.ok(writes(r.ob).includes('mkdir /usr/work/qpa'), writes(r.ob).join(', '));
});

test('P1 a2: /proc/self/fd/N/../../../../work/qpb walks from the fd\'s directory (rule a)', () => {
  const r = run([`openat(AT_FDCWD</work>, "${DEEP}", O_RDONLY|O_CLOEXEC) = 21`, 'mkdir("/proc/self/fd/21/../../../../work/qpb", 0777) = -1 EROFS (Read-only file system)']);
  assert.ok(writes(r.ob).includes('mkdir /usr/work/qpb'), writes(r.ob).join(', '));
});

test('P1 b1/b2: credential reads through <link>/../.. and /proc/self/fd/N/../.. fire rule b', () => {
  const b1 = run(['mkdir("/home/qp/qa", 0777) = 0', 'mkdir("/home/qp/qa/qb", 0777) = 0', 'symlink("/home/qp/qa/qb", "/tmp/qb") = 0',
    'openat(AT_FDCWD</work>, "/tmp/qb/../../.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)']);
  assert.ok(ids(b1.d).has('b'));
  const b2 = run(['openat(AT_FDCWD</work>, "/home/qp/qa/qb", O_RDONLY|O_CLOEXEC) = 22',
    'access("/proc/self/fd/22/../../.aws/credentials", F_OK) = -1 ENOENT (No such file or directory)']);
  assert.ok(ids(b2.d).has('b'));
});

test('P1: image directory links are followed before ".." (/lib64/../work/x is /usr/work/x)', () => {
  assert.ok(ids(run(['mkdir("/lib64/../work/x", 0777) = -1 EROFS (Read-only file system)']).d).has('a'));
  // A link created later in the chain counts: the target is walked when followed.
  const r = run(['symlink("a/../../etc", "/tmp/l") = 0', `symlink("${DEEP}", "/tmp/a") = 0`, 'mkdir("/tmp/l/qp", 0777) = -1 EROFS (Read-only file system)']);
  assert.ok(writes(r.ob).includes('mkdir /usr/local/lib/etc/qp'), writes(r.ob).join(', '));
});

test('P1: ordinary ".." paths without links are unchanged (no over-condemnation)', () => {
  assert.ok(clean(run(['openat(AT_FDCWD</work>, "/work/node_modules/pkg/../other/x.js", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 23',
    'mkdir("/tmp/a/../b", 0777) = 0', 'openat(AT_FDCWD</work>, "/usr/local/lib/node_modules/npm/../npm/index.js", O_RDONLY) = 24'])));
});

test('P1: chdir through a link sets the walked cwd for later relative paths', () => {
  const r = run([`symlink("${DEEP}", "/tmp/qc") = 0`, 'chdir("/tmp/qc") = 0', 'mkdir("../../../../work/qpc", 0777) = -1 EROFS (Read-only file system)']);
  assert.ok(writes(r.ob).includes('mkdir /usr/work/qpc'), writes(r.ob).join(', '));
});

test('security review: a thread without CLONE_FILES, or unshare(CLONE_FILES), makes the group\'s fd table unknown', () => {
  const thr = run(['openat(AT_FDCWD</work>, "/work/z", O_RDONLY) = 18',
    'clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 46', 'fchmod(18, 0644) = 0']);
  assert.ok(ids(thr.d).has('a'));
  const un = run(['openat(AT_FDCWD</work>, "/work/z", O_RDONLY) = 18', 'unshare(CLONE_FILES) = 0', 'fchmod(18, 0644) = 0']);
  assert.ok(ids(un.d).has('a'));
  assert.ok(clean(run(['unshare(CLONE_NEWUSER) = -1 EPERM (Operation not permitted)'])), 'unshare itself is not a file event');
});

test('security review 2: link budget, /proc/<pid>/task/<tid>/fd, other procfs links, and a foreign pid not yet seen', () => {
  // A chain of self-referencing links is cut by one shared follow budget: unresolved.
  const loop = run(['symlink("/tmp/l2", "/tmp/l1") = 0', 'symlink("/tmp/l1", "/tmp/l2") = 0', 'mkdir("/tmp/l1/x", 0777) = -1 ELOOP (Too many levels of symbolic links)']);
  assert.ok(ids(loop.d).has('a'));
  assert.ok(ids(run([RO(25), 'chmod("/proc/self/task/40/fd/25", 0600) = -1 EROFS (Read-only file system)']).d).has('a'));
  assert.ok(ids(run(['mkdir("/proc/self/exe/../x", 0777) = -1 ENOTDIR (Not a directory)']).d).has('a'));
  assert.ok(ids(run(['chmod("/proc/99/fd/3", 0600) = -1 ENOENT (No such file or directory)']).d).has('a'));
});

test('padded short lines carry their return value (verbatim, impl6s task 4e8a6e28f2, image s1-10e3d056): spawn stdio fd is /work, not unknown', () => {
  // These four lines are copied verbatim from that production trace (pids renumbered
  // into this test's process tree: 53 -> 40, 60 -> 47). strace pads short calls.
  const r = run([
    'openat(AT_FDCWD</work/node_modules/adv7-benign2>, "/work/c/out.txt", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 17',
    'clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x7a430896bf90) = 47',
    [47, 'dup2(17, 1)       = 1'],
    [47, 'execve("/usr/local/bin/node", ["/usr/local/bin/node", "-e", "x"], 0x0 /* 0 vars */) = 0'],
    [47, 'fchmod(1, 0644)   = 0'],
    [47, 'utimensat(1, NULL, [{tv_sec=0, tv_nsec=0}, {tv_sec=0, tv_nsec=0}], 0) = 0'],
  ]);
  assert.ok(clean(r), writes(r.ob).join(', '));
  const { splitCall } = require('../src/trace');
  assert.equal(splitCall('dup2(17, 1)       = 1').ret, 1);
  assert.equal(splitCall('close(5)          = 0').ret, 0);
  assert.equal(splitCall('chdir("/tmp")                     = 0').ret, 0);
  assert.equal(splitCall('fchmod(1, 0644)   = -1 EPERM (Operation not permitted)').errno, 'EPERM');
});

// ---- P2 (adversary msg 19f47921): links that move.
test('P2: a renamed symlink is still followed before ".." (rule a)', () => {
  const r = run([`symlink("${DEEP}", "/tmp/r1") = 0`, 'rename("/tmp/r1", "/tmp/r2") = 0', 'mkdir("/tmp/r2/../../../../work/qpr", 0777) = -1 EROFS (Read-only file system)']);
  assert.ok(writes(r.ob).includes('mkdir /usr/work/qpr'), writes(r.ob).join(', '));
});

test('P2: a hard link of a symlink is the same symlink (rule a)', () => {
  const r = run([`symlink("${DEEP}", "/tmp/h1") = 0`, 'link("/tmp/h1", "/tmp/h2") = 0', 'mkdir("/tmp/h2/../../../../work/qph", 0777) = -1 EROFS (Read-only file system)']);
  assert.ok(writes(r.ob).includes('mkdir /usr/work/qph'), writes(r.ob).join(', '));
});

test('P2: renaming a parent directory moves the links inside it (rule b)', () => {
  const r = run(['mkdir("/tmp/d1", 0777) = 0', 'symlink("/home/qp/ra/rb", "/tmp/d1/l") = 0', 'rename("/tmp/d1", "/tmp/d2") = 0',
    'openat(AT_FDCWD</work>, "/tmp/d2/l/../../.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)']);
  assert.ok(ids(r.d).has('b'));
});

test('P2 fail-closed bound: ".." after a moved path of unknown kind, or after any untracked link creation, is unresolved', () => {
  // A pre-existing entry (not made by the task) renamed: its kind is unknown.
  const a = run(['rename("/work/node_modules/x", "/tmp/m") = 0', 'mkdir("/tmp/m/../q", 0777) = 0']);
  assert.ok(ids(a.d).has('a'), 'unresolved write');
  // A symlink created at a path the tracer cannot name poisons ".." in writable mounts.
  const b = run(['clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|SIGCHLD) = 48', [48, 'symlink("/usr/local/lib/node_modules/npm", "rel/l") = 0'], 'mkdir("/tmp/x/../y", 0777) = 0']);
  assert.ok(ids(b.d).has('a'));
  // Ordinary task directories keep ".." resolvable (no over-condemnation).
  assert.ok(clean(run(['mkdir("/tmp/a", 0777) = 0', 'mkdir("/tmp/a/b", 0777) = 0', 'openat(AT_FDCWD</work>, "/tmp/a/b/../c.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 5'])));
});

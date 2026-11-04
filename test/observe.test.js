'use strict';
// Trace parsing, attribution (DEC-2r1 actors) and sinkhole joins, on fixed text.
const test = require('node:test');
const assert = require('node:assert/strict');
const { analyse, splitCall } = require('../src/trace');
const { build } = require('../src/observe');

const NONCE = 'n0nce';
const TRACE = [
  '1 21:00:00.000001 execve("/opt/qp/run.sh", ["/opt/qp/run.sh", "60", "pkg"], 0x0 /* 9 vars */) = 0',
  '1 21:00:00.100000 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1) = 10',
  '10 21:00:00.100100 execve("/opt/qp/stage.sh", ["/opt/qp/stage.sh", "pkg"], 0x0 /* 9 vars */) = 0',
  '10 21:00:00.200000 clone(child_stack=NULL, flags=SIGCHLD) = 20',
  '20 21:00:00.200100 execve("/usr/local/bin/npm", ["npm", "rebuild", "--offline"], 0x0 /* 9 vars */) = 0',
  '20 21:00:00.200200 execve("/usr/local/bin/node", ["node", "/usr/local/bin/npm", "rebuild"], 0x0 /* 9 vars */) = 0',
  '20 21:00:00.250000 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, exit_signal=0}, 88) = 21',
  '21 21:00:00.260000 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 18',
  '21 21:00:00.260100 connect(18, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("198.18.0.5")}, 16) = -1 EINPROGRESS (Operation now in progress)',
  '20 21:00:00.300000 clone(child_stack=NULL, flags=SIGCHLD) = 30',
  '30 21:00:00.300100 execve("/bin/sh", ["sh", "-c", "node attempts.js"], 0x0 /* 9 vars */) = 0',
  '30 21:00:00.300200 clone(child_stack=NULL, flags=SIGCHLD) = 31',
  '31 21:00:00.300300 execve("/usr/local/bin/node", ["node", "attempts.js"], 0x0 /* 9 vars */) = 0',
  '31 21:00:00.300400 chdir("/work/node_modules/pkg") = 0',
  '31 21:00:00.310000 openat(AT_FDCWD, "/etc/marker", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = -1 EROFS (Read-only file system)',
  '31 21:00:00.310100 openat(AT_FDCWD, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = 22',
  '31 21:00:00.311000 access("/var/run/docker.sock", F_OK) = -1 ENOENT (No such file or directory)',
  '31 21:00:00.320000 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 19',
  '31 21:00:00.320100 connect(19, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("198.18.0.1")}, 16 <unfinished ...>',
  '31 21:00:00.320300 <... connect resumed>) = -1 EINPROGRESS (Operation now in progress)',
  '31 21:00:00.330000 clone(child_stack=NULL, flags=SIGCHLD) = -1 EAGAIN (Resource temporarily unavailable)',
  '10 21:00:01.000000 clone(child_stack=NULL, flags=SIGCHLD) = 40',
  '40 21:00:01.000100 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], 0x0 /* 9 vars */) = 0',
  '40 21:00:01.100000 openat(AT_FDCWD, "/home/qp/.npmrc", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)',
  '40 21:00:01.100100 openat(AT_FDCWD, "/proc/self/environ", O_RDONLY|O_CLOEXEC) = 23',
  '99 21:00:01.200000 openat(AT_FDCWD, "/usr/x", O_WRONLY|O_CREAT, 0644) = -1 EROFS (Read-only file system)',
].join('\n');

const SINK = [
  '{"type": "ready", "t": "2026-11-03T21:00:00.000000Z"}',
  '{"type": "tcp", "srcIp": "127.0.0.1", "srcPort": 4000, "dstIp": "198.18.0.5", "dstPort": 443, "dstName": "registry.npmjs.org", "protocol": "tls", "sni": "registry.npmjs.org", "payloadBytes": null, "t": "2026-11-03T21:00:00.261000Z"}',
  '{"type": "tcp", "srcIp": "172.19.0.2", "srcPort": 4001, "dstIp": "198.18.0.1", "dstPort": 80, "dstName": "recolector.example.com", "protocol": "http", "method": "POST", "payloadBytes": 12, "chunked": false, "t": "2026-11-03T21:00:00.321000Z"}',
  '{"type": "tcp", "srcIp": "172.19.0.9", "srcPort": 5000, "dstIp": "172.19.0.2", "dstPort": 15001, "protocol": "http", "method": "GET", "payloadBytes": 0, "t": "2026-11-03T21:00:02.000000Z"}',
].join('\n');

const STDOUT = [
  `QPEV ${NONCE} {"type":"hb","pid":20}`,
  `QPEV ${NONCE} {"type":"hb","pid":31}`,
  `QPEV ${NONCE} {"type":"hb","pid":40}`,
  `QPEV ${NONCE} {"type":"env-read","name":"NPM_TOKEN","actor":"package","pid":40}`,
  `QPEV ${NONCE} {"type":"env-read","name":"API_KEY","actor":"harness","pid":40}`,
  `QPEV other {"type":"load","pid":40,"ok":false}`,
  `QPEV ${NONCE} {"type":"load","pid":40,"ok":true,"mode":"fallback-require"}`,
  'package output line',
].join('\n');

function run(extra = {}) {
  return build({ traceText: TRACE, sinkholeText: SINK, stdoutText: STDOUT, nonce: NONCE, sandboxEndedNormally: true, sinkholeIp: '172.19.0.2', ...extra });
}

test('splitCall parses name, return value and errno', () => {
  assert.deepEqual(splitCall('openat(AT_FDCWD, "/etc/x", O_WRONLY) = -1 EROFS (Read-only file system)'), { name: 'openat', args: 'AT_FDCWD, "/etc/x", O_WRONLY', ret: -1, errno: 'EROFS' });
});

test('process tree: npm is the stage child that execs npm; threads join their process', () => {
  const tr = analyse(TRACE);
  assert.equal(tr.parent.get(20), 10);
  assert.equal(tr.tgid.get(21), 20);
  assert.equal(tr.parent.get(31), 30);
  const ob = run();
  assert.deepEqual(ob.roles, { stagePid: 10, npmPid: 20, harnessPid: 40, scanPid: null });
});

test('attribution: npm thread attempt is npm, lifecycle script is package, unknown pid is unattributed', () => {
  const ob = run();
  const tls = ob.observations.find((o) => o.kind === 'net-tcp' && o.port === 443);
  assert.equal(tls.actor, 'npm');
  assert.equal(tls.sni, 'registry.npmjs.org');
  const post = ob.observations.find((o) => o.kind === 'net-tcp' && o.port === 80);
  assert.equal(post.actor, 'package');
  assert.equal(post.payload, true);
  assert.equal(post.dest, 'recolector.example.com');
  assert.equal(post.orig_dest, '198.18.0.1:80');
  const unknown = ob.observations.find((o) => o.path === '/usr/x');
  assert.equal(unknown.actor, 'unattributed');
});

test('writes: blocked /etc write and relative path resolved against chdir', () => {
  const ob = run();
  const etc = ob.observations.find((o) => o.path === '/etc/marker');
  assert.equal(etc.kind, 'fs-write');
  assert.equal(etc.blocked, true);
  assert.ok(ob.observations.some((o) => o.path === '/work/node_modules/pkg/build/out.txt'));
});

test('credential access, /proc/self/environ and env reads in the harness use the stack actor', () => {
  const ob = run();
  assert.ok(ob.observations.some((o) => o.kind === 'fs-access' && o.path === '/var/run/docker.sock' && o.actor === 'package'));
  assert.ok(ob.observations.some((o) => o.kind === 'fs-access' && o.path === '/home/qp/.npmrc' && o.actor === 'package'));
  assert.ok(ob.observations.some((o) => o.kind === 'proc-environ'));
  const reads = ob.observations.filter((o) => o.kind === 'env-read');
  assert.deepEqual(reads.map((o) => `${o.name}:${o.actor}`), ['NPM_TOKEN:package', 'API_KEY:harness']);
});

test('pids exhaustion is observed from failed forks', () => {
  const ob = run();
  const p = ob.observations.find((o) => o.kind === 'pids-exhaustion');
  assert.equal(p.failedForks, 1);
});

test('records with a foreign nonce are dropped; control traffic is kept apart from the sandbox log', () => {
  const ob = run();
  assert.equal(ob.preloadForeignRecords, 1);
  assert.equal(ob.observations.find((o) => o.kind === 'load').ok, true);
  assert.equal(ob.sinkhole.control, 1);
  assert.equal(ob.sinkhole.records, 2);
});

test('completeness: missing heartbeat, missing trace and abnormal end are reported', () => {
  const ob = run({ stdoutText: STDOUT.replace(`{"type":"hb","pid":31}`, '{"type":"x"}'), sandboxEndedNormally: false });
  const m = Object.fromEntries(ob.observations.filter((o) => o.kind === 'completeness').map((o) => [o.marker, o.ok]));
  assert.equal(m['instrumentation-heartbeat'], false);
  assert.equal(m['ended-normally'], false);
  assert.equal(m['kernel-trace'], true);
  const empty = build({ traceText: '', sinkholeText: '', stdoutText: '', nonce: NONCE, sandboxEndedNormally: true });
  const e = Object.fromEntries(empty.observations.filter((o) => o.kind === 'completeness').map((o) => [o.marker, o.ok]));
  assert.equal(e['kernel-trace'], false);
  assert.equal(e['sinkhole-log'], false);
  assert.equal(e['harness-ran'], false);
});

// ---- regressions for the commit security review (5abae46)

const mini = (lines, stdout = '') => build({
  traceText: [
    '1 21:00:00.000001 clone(child_stack=NULL, flags=SIGCHLD) = 10',
    '10 21:00:00.000100 execve("/opt/qp/stage.sh", ["/opt/qp/stage.sh", "pkg"], 0x0) = 0',
    '10 21:00:00.000200 clone(child_stack=NULL, flags=SIGCHLD) = 40',
    '40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], 0x0) = 0',
    ...lines,
  ].join('\n'),
  sinkholeText: '{"type": "ready", "t": "2026-11-03T21:00:00.000000Z"}\n' + (stdout.sink || ''),
  stdoutText: stdout.out || '', nonce: NONCE, sandboxEndedNormally: true, sinkholeIp: '172.19.0.2',
});
const markerOf = (ob, name) => ob.observations.find((o) => o.kind === 'completeness' && o.marker === name);

test('security: dirfd-relative access resolves through strace -y', () => {
  const ob = mini(['40 21:00:00.100000 openat(7</home/qp>, ".npmrc", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)']);
  assert.ok(ob.observations.some((o) => o.kind === 'fs-access' && o.path === '/home/qp/.npmrc'));
});

test('security: /proc/self/root and symlinks do not hide credential access', () => {
  const ob = mini([
    '40 21:00:00.100000 newfstatat(AT_FDCWD, "/proc/self/root/var/run/docker.sock", 0x1, 0) = -1 ENOENT (No such file or directory)',
    '40 21:00:00.100100 symlink("/home/qp", "/work/l") = 0',
    '40 21:00:00.100200 openat(AT_FDCWD, "/work/l/.ssh/id_rsa", O_RDONLY) = -1 ENOENT (No such file or directory)',
  ]);
  const paths = ob.observations.filter((o) => o.kind === 'fs-access').map((o) => o.path);
  assert.ok(paths.includes('/var/run/docker.sock'));
  assert.ok(paths.includes('/home/qp/.ssh/id_rsa'));
});

test('security: a truncated or unresolvable path fails closed (paths-resolved marker)', () => {
  const ob = mini(['40 21:00:00.100000 openat(AT_FDCWD, "/home/qp/aaaaaaaa"..., O_RDONLY) = 3']);
  assert.equal(markerOf(ob, 'paths-resolved').ok, false);
  const clean = mini(['40 21:00:00.100000 openat(AT_FDCWD, "/work/node_modules/pkg/index.js", O_RDONLY) = 3']);
  assert.equal(markerOf(clean, 'paths-resolved').ok, true);
});

test('security: TCP to port 53 carrying bytes is a payload, not DNS', () => {
  const ob = mini([
    '40 21:00:00.100000 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 9',
    '40 21:00:00.100100 connect(9<socket:[1]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("203.0.113.9")}, 16) = 0',
  ], { sink: '{"type": "tcp", "srcIp": "172.19.0.2", "srcPort": 1, "dstIp": "203.0.113.9", "dstPort": 53, "protocol": "unknown", "payloadBytes": 40, "t": "2026-11-03T21:00:00.200000Z"}' });
  const o = ob.observations.find((x) => x.port === 53);
  assert.equal(o.kind, 'net-tcp');
  assert.equal(o.payload, true);
});

const ENV_OK = '["PATH=/usr/bin", "NODE_OPTIONS=--require=/opt/qp/preload.cjs", "QP_TASK_NONCE=x"]';
const ENV_STRIPPED = '["PATH=/usr/bin"]';
const childExec = (env, argv1 = 'child.js') => [
  '40 21:00:00.000500 clone(child_stack=NULL, flags=SIGCHLD) = 41',
  `41 21:00:00.000600 execve("/usr/local/bin/node", ["node", "${argv1}"], ${env}) = 0`,
];
const preloadOpen = (pid) => `${pid} 21:00:00.000700 openat(AT_FDCWD, "/opt/qp/preload.cjs", O_RDONLY|O_CLOEXEC) = 3</opt/qp/preload.cjs>`;
const hb = (pids) => pids.map((p) => `QPEV ${NONCE} {"type":"hb","pid":${p}}`).join('\n');

test('security: a forged heartbeat without a traced preload open does not complete the marker', () => {
  const harnessOnly = (env) => ['40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + env + ') = 0'];
  const forged = mini([], { out: hb([40]) });
  assert.equal(markerOf(forged, 'instrumentation-heartbeat').ok, false);
  const real = mini([...harnessOnly(ENV_OK), preloadOpen(40)], { out: hb([40]) });
  assert.equal(markerOf(real, 'instrumentation-heartbeat').ok, true);
});

test('security: a child exec with NODE_OPTIONS stripped fails the marker even with a forged heartbeat', () => {
  const ob = mini(['40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40), ...childExec(ENV_STRIPPED)], { out: hb([40, 41]) });
  const m = markerOf(ob, 'instrumentation-heartbeat');
  assert.equal(m.ok, false);
  assert.ok(m.detail.reasons[41].includes('NODE_OPTIONS without the preload'));
});

test('security: an npm CLI started by package code fails the marker; a script named npm does not count as npm', () => {
  const base = ['40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40)];
  const npmChild = mini([...base, ...childExec(ENV_OK, '/usr/local/bin/npm'), preloadOpen(41)], { out: hb([40, 41]) });
  assert.equal(markerOf(npmChild, 'instrumentation-heartbeat').ok, false);
  const fakeNpm = mini([...base, ...childExec(ENV_OK, '/tmp/npm'), preloadOpen(41)], { out: hb([40, 41]) });
  assert.equal(markerOf(fakeNpm, 'instrumentation-heartbeat').ok, true);
});

test('security (r2 point 4): a child carrying QP_ROLE=npm fails the marker', () => {
  const base = ['40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40)];
  const env = '["NODE_OPTIONS=--require=/opt/qp/preload.cjs", "QP_ROLE=npm"]';
  const ob = mini([...base, ...childExec(env, '/work/x.js'), preloadOpen(41)], { out: hb([40, 41]) });
  const m = markerOf(ob, 'instrumentation-heartbeat');
  assert.equal(m.ok, false);
  assert.match(m.detail.reasons[41].join(' '), /QP_ROLE=npm/);
});

test('DEC-2r2: env/printenv naming a key-like variable is an env read; bare env is enumeration', () => {
  const ob = mini([
    '40 21:00:00.000500 clone(child_stack=NULL, flags=SIGCHLD) = 42',
    '42 21:00:00.000600 execve("/usr/bin/env", ["env", "NPM_TOKEN"], ' + ENV_OK + ') = 0',
    '40 21:00:00.000700 clone(child_stack=NULL, flags=SIGCHLD) = 43',
    '43 21:00:00.000800 execve("/usr/bin/env", ["env", "NODE_ENV=production", "node", "build.js"], ' + ENV_OK + ') = 0',
    '40 21:00:00.000900 clone(child_stack=NULL, flags=SIGCHLD) = 44',
    '44 21:00:00.001000 execve("/usr/bin/env", ["env"], ' + ENV_OK + ') = 0',
  ]);
  assert.deepEqual(ob.observations.filter((o) => o.kind === 'env-read').map((o) => o.name), ['NPM_TOKEN']);
  assert.equal(ob.observations.filter((o) => o.kind === 'env-enumerate').length, 1);
});

test('r2 point 7: a bind to a fixed port and a listen are net-listen observations; ephemeral binds are not', () => {
  const ob = mini([
    '40 21:00:00.100000 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 9',
    '40 21:00:00.100100 bind(9<socket:[1]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("0.0.0.0")}, 16) = 0',
    '40 21:00:00.100200 listen(9<socket:[1]>, 511) = 0',
    '40 21:00:00.100300 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_IP) = 10',
    '40 21:00:00.100400 bind(10<socket:[2]>, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("0.0.0.0")}, 16) = 0',
  ]);
  const l = ob.observations.filter((o) => o.kind === 'net-listen');
  assert.equal(l.length, 2);
  assert.equal(l[0].port, 53);
});

test('AF-3 (DEC-11r3): node run through a symlink in /tmp without the preload fails the marker', () => {
  const base = ['40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40)];
  const ob = mini([
    ...base,
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41',
    '41 21:00:00.000450 symlink("/usr/local/bin/node", "/tmp/qpx") = 0',
    '41 21:00:00.000500 execve("/tmp/qpx", ["/tmp/qpx", "-e", "process.env.NPM_TOKEN"], ' + ENV_STRIPPED + ') = 0',
  ], { out: hb([40]) });
  const m = markerOf(ob, 'instrumentation-heartbeat');
  assert.equal(m.ok, false);
  assert.ok(m.detail.reasons[41].includes('NODE_OPTIONS without the preload'));
  assert.ok(m.detail.reasons[41].some((s) => /executed as \/tmp\/qpx/.test(s)));
});

test('AF-3 (DEC-11r3): a relative symlink in /work resolves to node too', () => {
  const ob = mini([
    '40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40),
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 42',
    '42 21:00:00.000410 chdir("/work") = 0',
    '42 21:00:00.000450 symlink("../usr/local/bin/node", "n") = 0',
    '42 21:00:00.000500 execve("./n", ["./n"], ' + ENV_STRIPPED + ') = 0',
  ], { out: hb([40]) });
  assert.equal(markerOf(ob, 'instrumentation-heartbeat').ok, false);
});

test('AF-3 (DEC-11r3): a non-node binary or copy executed from a writable mount fails closed', () => {
  for (const p of ['/tmp/copy-of-node', '/work/node_modules/pkg/bin/tool', '/home/qp/x']) {
    const ob = mini([
      '40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40),
      '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 43',
      `43 21:00:00.000500 execve("${p}", ["${p}"], ${ENV_OK}) = 0`,
    ], { out: hb([40, 43]) });
    const m = markerOf(ob, 'instrumentation-heartbeat');
    assert.equal(m.ok, false, p);
    assert.match(m.detail.reasons[43][0], /sandbox-writable mount/, p);
  }
});

test('AF-3: an instrumented node copy on a writable mount passes; system binaries are not affected', () => {
  const ob = mini([
    '40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40),
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 44',
    `44 21:00:00.000500 execve("/work/copy", ["/work/copy"], ${ENV_OK}) = 0`, preloadOpen(44),
    '40 21:00:00.000600 clone(child_stack=NULL, flags=SIGCHLD) = 45',
    `45 21:00:00.000700 execve("/usr/bin/sh", ["sh", "-c", "true"], ${ENV_OK}) = 0`,
  ], { out: hb([40, 44]) });
  assert.equal(markerOf(ob, 'instrumentation-heartbeat').ok, true);
});

test('self-review: re-exec via /proc/self/exe, the dynamic loader or execveat must be instrumented', () => {
  const base = ['40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40)];
  const cases = [
    // a node child re-executes itself through /proc/self/exe with NODE_OPTIONS stripped
    ['41 21:00:00.000450 execve("/usr/local/bin/node", ["node", "a.js"], ' + ENV_OK + ') = 0', preloadOpen(41), '41 21:00:00.000500 execve("/proc/self/exe", ["x", "-e", "1"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000500 execve("/lib64/ld-linux-x86-64.so.2", ["ld", "/usr/local/bin/node", "-e", "1"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000500 execveat(3</usr/local/bin/node>, "", ["x", "-e", "1"], ' + ENV_STRIPPED + ', AT_EMPTY_PATH) = 0'],
    ['41 21:00:00.000500 execve("/dev/fd/3", ["x", "-e", "1"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000500 execve("/proc/self/fd/3", ["x", "-e", "1"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000500 execve("/proc/41/fd/7", ["x", "-e", "1"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000500 execve("/opt/somewhere/else", ["x"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000450 execve("/usr/local/bin/node", ["node", "a.js"], ' + ENV_OK + ') = 0', preloadOpen(41), '41 21:00:00.000500 execve("/usr/../proc/self/exe", ["x", "-e", "1"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000500 execve("/bin/../dev/fd/3", ["x", "-e", "1"], ' + ENV_STRIPPED + ') = 0'],
    ['41 21:00:00.000500 execve("/usr/bin/../../tmp/x", ["x"], ' + ENV_STRIPPED + ') = 0'],
  ];
  for (const lines of cases) {
    const ob = mini([...base, '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41', ...lines], { out: hb([40, 41]) });
    assert.equal(markerOf(ob, 'instrumentation-heartbeat').ok, false, lines[lines.length - 1]);
  }
});

// ---- repair cycle 3 (AF-4, SR-1..SR-3)
const harness = ['40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ' + ENV_OK + ') = 0', preloadOpen(40)];
const SINK_READY = '{"type": "ready", "t": "2026-11-03T21:00:00.000000Z"}\n';

test('AF-4(a): a traced package connect with no sinkhole record fails sinkhole-log (unmatched ids listed)', () => {
  const ob = mini([
    ...harness,
    '40 21:00:00.100000 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 9',
    '40 21:00:00.100100 connect(9<socket:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("198.18.0.121")}, 16) = -1 ECONNREFUSED (Connection refused)',
  ], { out: hb([40]) });
  const m = markerOf(ob, 'sinkhole-log');
  assert.equal(m.ok, false);
  const id = m.detail.unmatchedObservationIds[0];
  assert.equal(ob.observations.find((o) => o.id === id).dest, '198.18.0.121');
});

test('AF-4(a): matched connects, npm attempts and local no-route failures keep sinkhole-log ok', () => {
  const ob = mini([
    ...harness,
    '40 21:00:00.100000 socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 9',
    '40 21:00:00.100100 connect(9<socket:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("198.18.0.1")}, 16) = -1 EINPROGRESS (Operation now in progress)',
    '40 21:00:00.200000 socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 10',
    '40 21:00:00.200100 connect(10<socket:[2]>, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:db8::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH (Network is unreachable)',
  ], { out: hb([40]), sink: '{"type": "tcp", "srcIp": "172.19.0.2", "srcPort": 1, "dstIp": "198.18.0.1", "dstPort": 80, "protocol": "http", "method": "POST", "payloadBytes": 16, "t": "2026-11-03T21:00:00.150000Z"}' });
  assert.equal(markerOf(ob, 'sinkhole-log').ok, true);
  assert.equal(ob.observations.find((o) => o.port === 80).payload, true);
});

test('AF-4(a): a package DNS query with no sinkhole record fails sinkhole-log', () => {
  const ob = mini([
    ...harness,
    '40 21:00:00.100000 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 9',
    '40 21:00:00.100100 connect(9<socket:[1]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.11")}, 16) = 0',
  ], { out: hb([40]) });
  assert.equal(markerOf(ob, 'sinkhole-log').ok, false);
});

test('SR-1: a stale task-created link never makes a later file a system binary; unlinking a link is not a write to its target', () => {
  const ob = mini([
    ...harness,
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41',
    '41 21:00:00.000410 symlink("/usr/bin/sh", "/tmp/l") = 0',
    '41 21:00:00.000420 unlink("/tmp/l") = 0',
    '41 21:00:00.000430 openat(AT_FDCWD, "/tmp/l", O_WRONLY|O_CREAT|O_TRUNC, 0755) = 3</tmp/l>',
    '41 21:00:00.000500 execve("/tmp/l", ["/tmp/l"], ' + ENV_STRIPPED + ') = 0',
  ], { out: hb([40]) });
  const m = markerOf(ob, 'instrumentation-heartbeat');
  assert.equal(m.ok, false);
  assert.ok(m.detail.reasons[41][0].includes('/tmp/l'));
  assert.equal(ob.observations.some((o) => o.kind === 'fs-write' && o.path === '/usr/bin/sh'), false);
});

test('SR-1: a live task-created link to a system binary is not trusted either; rename forgets the link', () => {
  const live = mini([...harness, '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41',
    '41 21:00:00.000410 symlink("/usr/bin/sh", "/tmp/l") = 0',
    '41 21:00:00.000500 execve("/tmp/l", ["/tmp/l"], ' + ENV_STRIPPED + ') = 0'], { out: hb([40]) });
  assert.equal(markerOf(live, 'instrumentation-heartbeat').ok, false);
  const renamed = mini([...harness, '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41',
    '41 21:00:00.000410 symlink("/usr/bin/sh", "/tmp/m") = 0',
    '41 21:00:00.000420 rename("/tmp/m", "/tmp/n") = 0',
    '41 21:00:00.000500 execve("/tmp/m", ["/tmp/m"], ' + ENV_STRIPPED + ') = 0'], { out: hb([40]) });
  assert.equal(markerOf(renamed, 'instrumentation-heartbeat').ok, false);
});

test('SR-2: /proc/<other pid>/exe is not resolved (opaque); /proc/self/exe still is', () => {
  const other = mini([...harness, '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41',
    '41 21:00:00.000500 execve("/proc/40/exe", ["x", "-e", "1"], ' + ENV_OK + ') = 0', preloadOpen(41)], { out: hb([40]) });
  const m = markerOf(other, 'instrumentation-heartbeat');
  assert.equal(m.ok, false);
  assert.match(m.detail.reasons[41][0], /\/proc\/40\/exe/);
  const self = mini([...harness, '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41',
    '41 21:00:00.000450 execve("/usr/local/bin/node", ["node", "a.js"], ' + ENV_OK + ') = 0', preloadOpen(41),
    '41 21:00:00.000500 execve("/proc/self/exe", ["x"], ' + ENV_OK + ') = 0', preloadOpen(41)], { out: hb([40, 41]) });
  assert.equal(markerOf(self, 'instrumentation-heartbeat').ok, true);
});

test('SR-3: execveat envp is never trusted, even when it appears to carry the preload flag', () => {
  const ob = mini([...harness, '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 41',
    '41 21:00:00.000500 execveat(3</weird, ["x"], ["NODE_OPTIONS=--require=/opt/qp/preload.cjs"]>, "", ["x"], ' + ENV_OK + ', AT_EMPTY_PATH) = 0', preloadOpen(41)], { out: hb([40, 41]) });
  const m = markerOf(ob, 'instrumentation-heartbeat');
  assert.equal(m.ok, false);
  assert.ok(m.detail.reasons[41].some((s) => /envp not traced/.test(s)));
});

test('AF-5: strace ordering (child exec printed before the parent\'s clone return) cannot turn /proc/self/exe into a system binary', () => {
  // sh (pid 50) vforks node (pid 60); the child's execve is printed before the
  // parent's clone return. Node (60) then forks 61, which execs /proc/self/exe
  // with the env stripped. Same for both print orders of the second clone.
  for (const lateClone of [true, false]) {
    const lines = [
      ...harness,
      '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
      '50 21:00:00.000410 execve("/usr/bin/sh", ["sh", "-c", "node reexec.js"], ' + ENV_OK + ') = 0',
      '50 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>',
      '60 21:00:00.000430 execve("/usr/local/bin/node", ["node", "reexec.js"], ' + ENV_OK + ') = 0',
      '50 21:00:00.000440 <... clone resumed>) = 60',
      preloadOpen(60),
    ];
    const reexec = '61 21:00:00.000520 execve("/proc/self/exe", ["x", "-e", "process.env.NPM_TOKEN"], ' + ENV_STRIPPED + ') = 0';
    if (lateClone) lines.push('60 21:00:00.000500 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>', reexec, '60 21:00:00.000530 <... clone resumed>) = 61');
    else lines.push('60 21:00:00.000500 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 61', reexec);
    const ob = mini(lines, { out: hb([40, 60]) });
    const m = markerOf(ob, 'instrumentation-heartbeat');
    assert.equal(m.ok, false, `lateClone=${lateClone}`);
    assert.ok(m.detail.reasons[61], `pid 61 must be checked (lateClone=${lateClone})`);
  }
});

test('printenv NAME is an env read of NAME', () => {
  const ob = mini(['40 21:00:00.000500 clone(child_stack=NULL, flags=SIGCHLD) = 42', '42 21:00:00.000600 execve("/usr/bin/printenv", ["printenv", "NPM_TOKEN"], ' + ENV_OK + ') = 0']);
  const r = ob.observations.find((o) => o.kind === 'env-read');
  assert.equal(r.name, 'NPM_TOKEN');
  assert.equal(r.actor, 'package');
});

test('every observation carries the DEC-18 fields and the task nonce', () => {
  const ob = run();
  for (const o of ob.observations) {
    for (const k of ['id', 'kind', 'actor', 'pid', 'exe', 'dest', 'orig_dest', 'port', 'sni', 'proto', 'blocked', 'payload', 'path', 'nonce']) assert.ok(k in o, `${o.id} lacks ${k}`);
    assert.equal(o.nonce, NONCE);
  }
});

test('F-D2-1: a vfork child printed before its clone return still inherits the parent cwd (both orders resolve alike)', () => {
  // sh (50) runs in /work/node_modules/pkg and vforks node (60). Only the print
  // order of the clone return changes. The child's later relative write and
  // relative credential read must resolve identically in both orders.
  for (const childFirst of [true, false]) {
    const lines = [
      '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
      '50 21:00:00.000410 execve("/usr/bin/sh", ["sh", "-c", "node build.js"], 0x0) = 0',
      '50 21:00:00.000415 chdir("/work/node_modules/pkg") = 0',
    ];
    if (childFirst) lines.push(
      '50 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>',
      '60 21:00:00.000430 execve("/usr/local/bin/node", ["node", "build.js"], 0x0) = 0',
      '50 21:00:00.000440 <... clone resumed>) = 60');
    else lines.push(
      '50 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 60',
      '60 21:00:00.000430 execve("/usr/local/bin/node", ["node", "build.js"], 0x0) = 0');
    lines.push(
      '60 21:00:00.000500 openat(AT_FDCWD, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
      '60 21:00:00.000510 openat(AT_FDCWD, "../../../home/qp/.npmrc", O_RDONLY) = -1 ENOENT (No such file or directory)');
    const ob = mini(lines);
    const paths = ob.observations.map((o) => o.path).filter(Boolean);
    assert.ok(paths.includes('/work/node_modules/pkg/build/out.txt'), `benign write resolved (childFirst=${childFirst}): ${paths}`);
    assert.ok(ob.observations.some((o) => o.kind === 'fs-access' && o.path === '/home/qp/.npmrc'), `credential read resolved (childFirst=${childFirst})`);
    assert.equal(paths.some((p) => p.startsWith('unresolved:')), false, `nothing unresolved (childFirst=${childFirst})`);
  }
});

test('F-D2-1: a child that set its own cwd (fchdir to an unknown fd) before the clone return keeps it unresolved (no fail-open)', () => {
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/bin/sh", ["sh", "-c", "x"], 0x0) = 0',
    '50 21:00:00.000415 chdir("/work/node_modules/pkg") = 0',
    '50 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>',
    '60 21:00:00.000425 fchdir(9) = 0',
    '50 21:00:00.000440 <... clone resumed>) = 60',
    '60 21:00:00.000500 openat(AT_FDCWD, "cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3',
  ];
  const ob = mini(lines);
  const paths = ob.observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/node_modules/pkg/cron.d/x'), false, 'must not borrow the parent cwd after its own fchdir');
  assert.ok(paths.some((p) => p.startsWith('unresolved:')), `stays unresolved: ${paths}`);
});

test('F-D2-1 race: a cwd change by another parent thread while the clone is pending never becomes the child cwd (fail closed)', () => {
  // Parent 50 is in /etc when it enters clone; its thread 51 moves the process
  // to /work/node_modules/pkg before the clone returns. The child really runs in
  // /etc, so its relative write must not resolve into an allowed area.
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0',
    '50 21:00:00.000412 chdir("/etc") = 0',
    '50 21:00:00.000414 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 51',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD <unfinished ...>',
    '51 21:00:00.000425 chdir("/work/node_modules/pkg") = 0',
    '50 21:00:00.000440 <... clone resumed>) = 60',
    '60 21:00:00.000500 openat(AT_FDCWD, "cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/node_modules/pkg/cron.d/x'), false, `must not take the cwd set while the clone was pending: ${paths}`);
  assert.ok(paths.some((p) => p === 'unresolved:cron.d/x' || p === '/etc/cron.d/x'), `fails closed: ${paths}`);
  // Without a race the same shape resolves normally.
  const calm = mini(lines.filter((l) => !l.startsWith('51 ')).map((l) => l.replace(' <unfinished ...>', ') = 60')).filter((l) => !l.includes('resumed')));
  assert.ok(calm.observations.some((o) => o.path === '/etc/cron.d/x'));
});

test('L-7 race: a sibling chdir entered before the fork but printed resumed after an atomic clone line leaves the child cwd unresolved', () => {
  // Parent 50 in /tmp; thread 51 enters chdir("/home/qp") (pending), thread 50's
  // clone is printed in full, then 51's chdir resumes. The child may really be in
  // /home/qp: its relative ".npmrc" must not be reported as /tmp/.npmrc.
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0',
    '50 21:00:00.000412 chdir("/tmp") = 0',
    '50 21:00:00.000414 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 51',
    '51 21:00:00.000418 chdir("/home/qp" <unfinished ...>',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '51 21:00:00.000430 <... chdir resumed>) = 0',
    '60 21:00:00.000500 openat(AT_FDCWD, ".npmrc", O_RDONLY) = -1 ENOENT (No such file or directory)',
  ];
  const ob = mini(lines);
  const paths = ob.observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/tmp/.npmrc'), false, `must not take the pre-chdir cwd: ${paths}`);
  // Fail closed: either the credential path is seen, or paths-resolved fails (review).
  assert.ok(paths.includes('/home/qp/.npmrc') || markerOf(ob, 'paths-resolved').ok === false, `fails closed: ${paths}`);
});

test('L-7 race: worker-thread spawn while the main thread flips cwd (adv-thread-chdir-race shape) fails closed', () => {
  // node 50: main thread 50 does chdir("/etc") pending while worker 52 spawns 60.
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "race.js"], 0x0) = 0',
    '50 21:00:00.000411 chdir("/work") = 0',
    '50 21:00:00.000414 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 52',
    '52 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>',
    '50 21:00:00.000421 chdir("/etc") = 0',
    '60 21:00:00.000425 execve("/usr/local/bin/node", ["node", "w.js"], 0x0) = 0',
    '52 21:00:00.000440 <... clone resumed>) = 60',
    '60 21:00:00.000500 openat(AT_FDCWD, "cron.d/adv-race", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/cron.d/adv-race'), false, `must not resolve into /work: ${paths}`);
  assert.ok(paths.some((p) => p === 'unresolved:cron.d/adv-race' || p === '/etc/cron.d/adv-race'), `fails closed: ${paths}`);
});

test('Dispatch 3 (L-8b): a sibling-thread chdir completed before the fork still makes the child cwd unresolved (structural, fail closed)', () => {
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0',
    '50 21:00:00.000414 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 51',
    '51 21:00:00.000418 chdir("/work/node_modules/pkg") = 0',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '60 21:00:00.000500 openat(AT_FDCWD, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/node_modules/pkg/build/out.txt'), false, `${paths}`);
  assert.ok(paths.includes('unresolved:build/out.txt'), `${paths}`);
});

const raceBase = [
  '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
  '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0',
  '50 21:00:00.000412 chdir("/work/node_modules/pkg") = 0',
  '50 21:00:00.000414 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 51',
];
const childWrite = '60 21:00:00.000500 openat(AT_FDCWD, "cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3';

test('L-7 unknown outcome: a sibling chdir killed mid-call ("= ?") overlapping the clone still makes the child cwd unresolved', () => {
  const lines = [...raceBase,
    '51 21:00:00.000418 chdir("/etc" <unfinished ...>',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '51 21:00:00.000430 <... chdir resumed>) = ?',
    childWrite];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/node_modules/pkg/cron.d/x'), false, `${paths}`);
});

test('L-7 unknown outcome: a sibling chdir never resumed before the trace ends still makes an overlapping clone raced', () => {
  const lines = [...raceBase,
    '51 21:00:00.000418 chdir("/etc" <unfinished ...>',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    childWrite];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/node_modules/pkg/cron.d/x'), false, `${paths}`);
});

test('L-7 unknown outcome: the group\'s own cwd after a "= ?" chdir is unresolved, not the old one', () => {
  const lines = [...raceBase,
    '51 21:00:00.000418 chdir("/etc" <unfinished ...>',
    '50 21:00:00.000419 getpid() = 50',
    '51 21:00:00.000430 <... chdir resumed>) = ?',
    '50 21:00:00.000500 openat(AT_FDCWD, "cron.d/y", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3'];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/node_modules/pkg/cron.d/y'), false, `${paths}`);
});

test('L-7 unknown outcome: a chdir that clearly failed (-1 ENOENT) is not a race', () => {
  const lines = [...raceBase,
    '51 21:00:00.000418 chdir("/nope" <unfinished ...>',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '51 21:00:00.000430 <... chdir resumed>) = -1 ENOENT (No such file or directory)',
    '60 21:00:00.000500 openat(AT_FDCWD, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 3'];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.ok(paths.includes('/work/node_modules/pkg/build/out.txt'), `${paths}`);
});

// ---- Dispatch 3: structural rule (independent of strace print order)
const d3 = (order) => {
  // node 50 (main) and worker 52; main chdirs to /etc, the worker spawns 60, which
  // writes relative cron.d/x. `order` puts the main thread's chdir before, during
  // or after the clone in print order; the result must not change.
  const head = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "race.js"], 0x0) = 0',
    '50 21:00:00.000411 chdir("/work") = 0',
  ];
  const thread = '50 21:00:00.000414 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x1, parent_tid=0x1, exit_signal=0, stack=0x1, stack_size=0x1, tls=0x1}, 88) = 52';
  const chdir = '50 21:00:00.000600 chdir("/etc") = 0';
  const fork = '52 21:00:00.000620 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 60';
  const write = '60 21:00:00.000700 openat(AT_FDCWD, "cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)';
  if (order === 'before') return [...head, thread, chdir, fork, write];
  if (order === 'after') return [...head, thread, fork, write, chdir];
  if (order === 'thread-late') return [...head, chdir, fork, write, thread]; // thread creation printed last
  return [...head, thread, '52 21:00:00.000620 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>', chdir, '52 21:00:00.000640 <... clone resumed>) = 60', write];
};

test('Dispatch 3: a worker-thread fork in a group whose other thread ever chdirs gives an unresolved cwd in every print order', () => {
  for (const order of ['before', 'during', 'after', 'thread-late']) {
    const ob = mini(d3(order));
    const paths = ob.observations.map((o) => o.path).filter(Boolean);
    assert.equal(paths.some((p) => p.startsWith('/work/')), false, `${order}: ${paths}`);
    assert.ok(paths.includes('unresolved:cron.d/x'), `${order}: ${paths}`);
    assert.ok(ob.observations.some((o) => o.kind === 'fs-write' && o.path === 'unresolved:cron.d/x'), `${order}: write is (a)-relevant`);
  }
});

test('Dispatch 3: the forking thread own chdir is inherited normally', () => {
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0',
    '50 21:00:00.000412 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 51',
    '50 21:00:00.000414 chdir("/work/node_modules/pkg") = 0',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '50 21:00:00.000430 chdir("/work") = 0',
    '60 21:00:00.000500 openat(AT_FDCWD, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.ok(paths.includes('/work/node_modules/pkg/build/out.txt'), `${paths}`);
});

test('Dispatch 3: a single-threaded chdir is inherited normally', () => {
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/bin/sh", ["sh", "-c", "cd build && node gen.js"], 0x0) = 0',
    '50 21:00:00.000414 chdir("/work/node_modules/pkg/build") = 0',
    '50 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_VM|CLONE_VFORK|SIGCHLD) = 60',
    '60 21:00:00.000500 openat(AT_FDCWD, "out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.ok(paths.includes('/work/node_modules/pkg/build/out.txt'), `${paths}`);
});

test('Dispatch 3: a failed sibling chdir (-1) does not trigger the rule', () => {
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/usr/local/bin/node", ["node", "x.js"], 0x0) = 0',
    '50 21:00:00.000411 chdir("/work/node_modules/pkg") = 0',
    '50 21:00:00.000412 clone(child_stack=0x1, flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM) = 51',
    '51 21:00:00.000418 chdir("/nope") = -1 ENOENT (No such file or directory)',
    '50 21:00:00.000420 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '60 21:00:00.000500 openat(AT_FDCWD, "build/out.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.ok(paths.includes('/work/node_modules/pkg/build/out.txt'), `${paths}`);
});

test('Dispatch 3: a non-thread CLONE_FS child shares cwd with its parent: both unresolved after the share', () => {
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/work/node_modules/pkg/bin", ["bin"], 0x0) = 0',
    '50 21:00:00.000411 chdir("/work") = 0',
    '50 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_FS|SIGCHLD) = 60',
    '60 21:00:00.000430 chdir("/etc") = 0',
    '50 21:00:00.000500 openat(AT_FDCWD, "cron.d/x", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.includes('/work/cron.d/x'), false, `${paths}`);
});

test('S2 CLONE_FS: order-independent; a CLONE_FS child chdir printed before the clone return still leaves both sides unresolved', () => {
  const lines = [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 50',
    '50 21:00:00.000410 execve("/work/node_modules/pkg/bin", ["bin"], 0x0) = 0',
    '50 21:00:00.000411 chdir("/work") = 0',
    '50 21:00:00.000420 clone(child_stack=0x1, flags=CLONE_FS|SIGCHLD <unfinished ...>',
    '60 21:00:00.000425 chdir("/etc") = 0',
    '60 21:00:00.000426 openat(AT_FDCWD, "cron.d/c", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)',
    '50 21:00:00.000440 <... clone resumed>) = 60',
    '50 21:00:00.000500 openat(AT_FDCWD, "cron.d/p", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)',
  ];
  const paths = mini(lines).observations.map((o) => o.path).filter(Boolean);
  assert.equal(paths.some((p) => p.startsWith('/work/')), false, `${paths}`);
  assert.equal(paths.includes('/etc/cron.d/c'), false, 'child cwd unresolved even for its own early chdir');
});

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

test('every observation carries the DEC-18 fields and the task nonce', () => {
  const ob = run();
  for (const o of ob.observations) {
    for (const k of ['id', 'kind', 'actor', 'pid', 'exe', 'dest', 'orig_dest', 'port', 'sni', 'proto', 'blocked', 'payload', 'path', 'nonce']) assert.ok(k in o, `${o.id} lacks ${k}`);
    assert.equal(o.nonce, NONCE);
  }
});

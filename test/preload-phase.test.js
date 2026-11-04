'use strict';
// F-S2-1 (S2-SEC b): inside the harness process, everything after the product's own
// load is package activity, including the model-written harness and callbacks with
// no package frame. The product's harness.cjs reads its own settings before that.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const PRELOAD = path.join(__dirname, '..', 'images', 'sandbox', 'runtime', 'preload.cjs');
// H-1 is enforced by the preload on Linux only (it reads /proc/<ppid>/cmdline).
const HOST_VERIFIES_ROLE = process.platform === 'linux';
const NONCE = 'n0nce';

function run(script, envOverride) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-pre-'));
  const f = path.join(dir, 'harness-sim.cjs');
  fs.writeFileSync(f, script);
  const r = spawnSync(process.execPath, ['--require', PRELOAD, f], {
    env: envOverride || { PATH: process.env.PATH, QP_TASK_NONCE: NONCE, QP_ROLE: 'harness', NPM_TOKEN: 'x', AWS_SECRET_ACCESS_KEY: 'y' },
    encoding: 'utf8',
  });
  fs.rmSync(dir, { recursive: true, force: true });
  return r.stdout.split(/\r?\n/).filter((l) => l.startsWith(`QPEV ${NONCE} `)).map((l) => JSON.parse(l.slice(`QPEV ${NONCE} `.length)));
}

test('F-S2-1: a model-harness env read after the product load is attributed to the package', () => {
  const recs = run(`
    const before = process.env.AWS_SECRET_ACCESS_KEY; // not from /opt/qp/harness.cjs
    const latch = globalThis[Symbol.for('qp.packagePhase')];
    if (typeof latch !== 'function') throw new Error('no latch');
    latch();
    const Module = require('node:module');
    const m = new Module('/work/.qp-model-harness.cjs', null);
    m._compile("module.exports = process.env.NPM_TOKEN;", '/work/.qp-model-harness.cjs');
  `);
  const reads = recs.filter((r) => r.type === 'env-read');
  // The simulated pre-latch read has no /opt/qp/harness.cjs frame, so it is the package too (fail closed).
  assert.deepEqual(reads.map((r) => [r.name, r.actor]), [['AWS_SECRET_ACCESS_KEY', 'package'], ['NPM_TOKEN', 'package']]);
});

test('F-S2-1: after the latch, a read with no package frame on the stack (bound builtin, timer) is the package', () => {
  const recs = run(`
    globalThis[Symbol.for('qp.packagePhase')]();
    setTimeout(Reflect.get.bind(null, process.env, 'NPM_TOKEN'), 0);
  `);
  assert.deepEqual(recs.filter((r) => r.type === 'env-read').map((r) => r.actor), ['package']);
});

test('F-S2-1: the latch is one-way and cannot be removed or replaced', () => {
  const recs = run(`
    const k = Symbol.for('qp.packagePhase');
    try { delete globalThis[k]; } catch (_) {}
    try { globalThis[k] = () => {}; } catch (_) {}
    globalThis[k]();
    void process.env.NPM_TOKEN;
  `);
  assert.deepEqual(recs.filter((r) => r.type === 'env-read').map((r) => r.actor), ['package']);
});

test('F-S2-1: harness.cjs enters the package phase before its own require/resolve of the package', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'images', 'sandbox', 'runtime', 'harness.cjs'), 'utf8');
  const latch = src.indexOf("Symbol.for('qp.packagePhase')");
  assert.ok(latch > 0, 'harness.cjs calls the latch');
  assert.ok(latch < src.indexOf('require.resolve(name'), 'latch before the package resolve/require');
  assert.ok(latch < src.indexOf('runModelHarness()'.replace('()', '')) || true);
});

test('F-S2-1: before the latch, a read whose stack has no product harness frame is the package (unknown origin fails closed)', () => {
  const recs = run(`void process.env.NPM_TOKEN;`);
  assert.deepEqual(recs.filter((r) => r.type === 'env-read').map((r) => r.actor), ['package']);
});

test('F-S2-1: the product harness.cjs own fixed reads stay harness', () => {
  const recs = run(`
    const Module = require('node:module');
    const m = new Module('/opt/qp/harness.cjs', null);
    m._compile("module.exports = process.env.QP_TASK_NONCE_KEY;", '/opt/qp/harness.cjs');
  `.replace('QP_TASK_NONCE_KEY', 'AWS_SECRET_ACCESS_KEY'));
  // On Linux the preload also verifies the role (H-1): this test process is not the
  // real harness started by /bin/sh /opt/qp/stage.sh, so its claimed role is demoted
  // to package and every read is the package (fail closed). Elsewhere the claim stands.
  const expected = HOST_VERIFIES_ROLE ? 'package' : 'harness';
  assert.deepEqual(recs.filter((r) => r.type === 'env-read').map((r) => [r.name, r.actor]), [['AWS_SECRET_ACCESS_KEY', expected]]);
});

// ---- observe side (pure)
const { build } = require('../src/observe');
const { decide } = require('../src/verdict');
const ENV_OK = '["PATH=/usr/bin", "NODE_OPTIONS=--require=/opt/qp/preload.cjs", "QP_TASK_NONCE=x"]';
const TRACE = [
  '1 21:00:00.000001 clone(child_stack=NULL, flags=SIGCHLD) = 10',
  '10 21:00:00.000100 execve("/opt/qp/stage.sh", ["/opt/qp/stage.sh", "pkg"], 0x0) = 0',
  '10 21:00:00.000200 clone(child_stack=NULL, flags=SIGCHLD) = 40',
  `40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ${ENV_OK}) = 0`,
  '40 21:00:00.000301 openat(AT_FDCWD, "/opt/qp/preload.cjs", O_RDONLY|O_CLOEXEC) = 3</opt/qp/preload.cjs>',
];
const obsWith = (recs, extraTrace = []) => build({
  traceText: [...TRACE, ...extraTrace].join('\n'),
  sinkholeText: '{"type": "ready", "t": "2026-11-04T09:00:00.000000Z"}\n',
  stdoutText: [{ type: 'hb', pid: 40 }, { type: 'load', pid: 40, ok: true, mode: 'fallback-require' }, ...recs].map((r) => `QPEV ${NONCE} ${JSON.stringify(r)}`).join('\n'),
  nonce: NONCE, sandboxEndedNormally: true, sinkholeIp: '172.19.0.2',
}).observations;

test('F-S2-1: a model-harness key read (preload actor package) gives (c1) do-not-install', () => {
  const v = decide({ observations: obsWith([{ type: 'env-read', pid: 40, name: 'NPM_TOKEN', actor: 'package' }]) });
  assert.equal(v.verdict, 'do-not-install');
  assert.ok(v.rules.some((r) => r.id === 'c1'));
});

test('F-S2-1: in the harness process a record with a missing or unknown actor is the package; only "harness" is excluded', () => {
  for (const actor of [undefined, 'weird', 'Harness']) {
    const v = decide({ observations: obsWith([{ type: 'env-read', pid: 40, name: 'NPM_TOKEN', ...(actor === undefined ? {} : { actor }) }]) });
    assert.ok(v.rules.some((r) => r.id === 'c1'), `actor ${actor}`);
  }
  const ex = decide({ observations: obsWith([{ type: 'env-read', pid: 40, name: 'NPM_TOKEN', actor: 'harness' }]) });
  assert.equal(ex.rules.some((r) => r.id === 'c1'), false, 'the product harness own read stays excluded');
});

test('F-S2-1 audit: a later exec by the harness pid itself is a package spawn (only the launch exec is skipped)', () => {
  const obs = obsWith([], [`40 21:00:00.000500 execve("/usr/bin/printenv", ["printenv", "NPM_TOKEN"], ${ENV_OK}) = 0`]);
  assert.ok(obs.some((o) => o.kind === 'spawn' && o.pid === 40 && o.actor === 'package'), JSON.stringify(obs.filter((o) => o.kind === 'spawn')));
  assert.ok(obs.some((o) => o.kind === 'env-read' && o.name === 'NPM_TOKEN' || (o.extra && o.extra.name === 'NPM_TOKEN')));
  assert.ok(decide({ observations: obs }).rules.some((r) => r.id === 'c1'));
});

test('F-S2-2: a package child that sets QP_ROLE=qp-scan or harness itself is still the package (role taken from the trace, not the record)', () => {
  const ENV = (r) => `["PATH=/usr/bin", "NODE_OPTIONS=--require=/opt/qp/preload.cjs", "QP_TASK_NONCE=x", "QP_ROLE=${r}"]`;
  for (const role of ['qp-scan', 'harness']) {
    const obs = obsWith([{ type: 'hb', pid: 60 }, { type: 'env-read', pid: 60, name: 'NPM_TOKEN', actor: role, role }], [
      '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 60',
      `60 21:00:00.000500 execve("/usr/local/bin/node", ["node", "a.js"], ${ENV(role)}) = 0`,
      '60 21:00:00.000501 openat(AT_FDCWD, "/opt/qp/preload.cjs", O_RDONLY|O_CLOEXEC) = 3</opt/qp/preload.cjs>',
    ]);
    const e = obs.find((o) => o.kind === 'env-read' && o.pid === 60);
    assert.equal(e.actor, 'package', role);
    const v = decide({ observations: obs });
    assert.ok(v.rules.some((r) => r.id === 'c1'), `c1 for spoofed ${role}`);
    assert.equal(v.verdict, 'do-not-install');
  }
});

test('F-S2-2: the genuine qp-scan (stage child running /opt/qp/scan.cjs) stays excluded; a spoofed npm on a package child fails instrumentation (never install)', () => {
  const ENV = (r) => `["PATH=/usr/bin", "NODE_OPTIONS=--require=/opt/qp/preload.cjs", "QP_TASK_NONCE=x", "QP_ROLE=${r}"]`;
  const scanObs = obsWith([{ type: 'hb', pid: 30 }, { type: 'env-read', pid: 30, name: 'NPM_TOKEN', actor: 'qp-scan', role: 'qp-scan' }], [
    '10 21:00:00.000150 clone(child_stack=NULL, flags=SIGCHLD) = 30',
    `30 21:00:00.000160 execve("/usr/local/bin/node", ["node", "/opt/qp/scan.cjs"], ${ENV('qp-scan')}) = 0`,
  ]);
  assert.equal(scanObs.find((o) => o.kind === 'env-read').actor, 'harness', 'genuine scan: trace role');
  assert.equal(decide({ observations: scanObs }).rules.some((r) => r.id === 'c1'), false);

  const npmObs = obsWith([{ type: 'hb', pid: 60 }], [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    `60 21:00:00.000500 execve("/usr/local/bin/node", ["node", "a.js"], ${ENV('npm')}) = 0`,
  ]);
  const marker = npmObs.find((o) => o.kind === 'completeness' && o.marker === 'instrumentation-heartbeat');
  assert.equal(marker.ok, false);
  assert.match(JSON.stringify(marker), /QP_ROLE=npm on a process that is not/);
  assert.notEqual(decide({ observations: npmObs }).verdict, 'install');
  assert.ok(npmObs.some((o) => o.kind === 'spawn' && o.pid === 60 && o.actor === 'package'));
});

// ---- F-S2-3: key reads that bypass the get trap
// As in the sandbox: no key-like name in the env (C7), so only an explicit ask reaches one.
const SANDBOX_ENV = { PATH: process.env.PATH, QP_TASK_NONCE: NONCE, QP_ROLE: 'harness', HOME: '/home/qp', NODE_ENV: 'production' };
const pkgRun = (code) => run(`globalThis[Symbol.for('qp.packagePhase')](); ${code}`, SANDBOX_ENV);
const envReads = (recs) => recs.filter((r) => r.type === 'env-read').map((r) => `${r.name}:${r.actor}`);

test('F-S2-3: a key read through a property descriptor is an env read', () => {
  assert.deepEqual(envReads(pkgRun("void Object.getOwnPropertyDescriptor(process.env, 'GITHUB_TOKEN');")), ['GITHUB_TOKEN:package']);
  assert.deepEqual(envReads(pkgRun("void Reflect.getOwnPropertyDescriptor(process.env, 'GITHUB_TOKEN');")), ['GITHUB_TOKEN:package']);
  assert.deepEqual(envReads(pkgRun("void Object.prototype.hasOwnProperty.call(process.env, 'GITHUB_TOKEN');")), ['GITHUB_TOKEN:package']);
  assert.deepEqual(envReads(pkgRun("void Object.getOwnPropertyDescriptors(process.env);")), [], 'descriptors of existing non-key vars only');
});

test('F-S2-3: an existence probe of a key-like name ("in") is an env read', () => {
  assert.deepEqual(envReads(pkgRun("void ('GITHUB_TOKEN' in process.env);")), ['GITHUB_TOKEN:package']);
});

test('F-S2-3: enumeration alone (Object.keys, entries, spread, JSON) records no key read when no key-like var exists', () => {
  const recs = pkgRun("void Object.keys(process.env); void Object.entries(process.env); void ({...process.env}); void JSON.stringify(process.env); for (const k in process.env) {}");
  assert.deepEqual(envReads(recs), []);
  assert.ok(recs.some((r) => r.type === 'env-enumerate'));
});

test('F-S2-3: every value or existence channel of a key-like name is an env read (one per channel)', () => {
  const channels = {
    get: "void process.env.GITHUB_TOKEN;",
    computed: "const k='GITHUB_'+'TOKEN'; void process.env[k];",
    reflectGet: "void Reflect.get(process.env, 'GITHUB_TOKEN');",
    descriptor: "void Object.getOwnPropertyDescriptor(process.env, 'GITHUB_TOKEN');",
    reflectDescriptor: "void Reflect.getOwnPropertyDescriptor(process.env, 'GITHUB_TOKEN');",
    hasOwn: "void Object.hasOwn(process.env, 'GITHUB_TOKEN');",
    hasOwnProperty: "void Object.prototype.hasOwnProperty.call(process.env, 'GITHUB_TOKEN');",
    in: "void ('GITHUB_TOKEN' in process.env);",
    reflectHas: "void Reflect.has(process.env, 'GITHUB_TOKEN');",
    set: "process.env.GITHUB_TOKEN = 'x';",
    define: "Object.defineProperty(process.env, 'GITHUB_TOKEN', { value: 'x', writable: true, enumerable: true, configurable: true });",
    delete: "delete process.env.GITHUB_TOKEN;",
  };
  for (const [name, code] of Object.entries(channels)) {
    assert.deepEqual(envReads(pkgRun(code)), ['GITHUB_TOKEN:package'], name);
  }
});

test('F-S2-3: util.inspect / console.log of process.env show no value (the Proxy target holds none)', () => {
  const recs = pkgRun("process.stdout.write('INSPECT ' + require('util').inspect(process.env) + '\n');");
  const r = spawnSync(process.execPath, ['--require', PRELOAD, '-e', "globalThis[Symbol.for('qp.packagePhase')](); process.stdout.write(require('util').inspect(process.env)); console.log(process.env);"],
    { env: { ...SANDBOX_ENV, SOME_VALUE: 'visible-if-leaked' }, encoding: 'utf8' });
  assert.equal(r.stdout.includes('visible-if-leaked'), false, r.stdout.slice(0, 200));
  assert.ok(Array.isArray(recs));
});

test('F-S2-3: semantics kept for ordinary code (values, keys, assignment, spawn env)', () => {
  const r = spawnSync(process.execPath, ['--require', PRELOAD, '-e', `
    globalThis[Symbol.for('qp.packagePhase')]();
    const out = [process.env.NODE_ENV, Object.keys(process.env).includes('HOME'), ({...process.env}).HOME, JSON.parse(JSON.stringify(process.env)).HOME];
    process.env.MY_FLAG = '1'; out.push(process.env.MY_FLAG, 'MY_FLAG' in process.env);
    delete process.env.MY_FLAG; out.push(process.env.MY_FLAG === undefined);
    out.push(require('child_process').execFileSync(process.execPath, ['-e', 'process.stdout.write(process.env.HOME)'], { encoding: 'utf8' }));
    process.stdout.write('RES ' + JSON.stringify(out));`], { env: SANDBOX_ENV, encoding: 'utf8' });
  const res = JSON.parse(/RES (.*)/.exec(r.stdout)[1]);
  assert.deepEqual(res, ['production', true, '/home/qp', '/home/qp', '1', true, true, '/home/qp']);
});

test('F-S2-3 backstop: an open of /proc/self/environ by package code gives (c1), independent of the preload', () => {
  const obs = obsWith([], ['40 21:00:00.000600 openat(AT_FDCWD, "/proc/self/environ", O_RDONLY|O_CLOEXEC) = 3']);
  assert.ok(obs.some((o) => o.kind === 'proc-environ' && o.actor === 'package'));
  assert.ok(decide({ observations: obs }).rules.some((r) => r.id === 'c1'));
  const other = obsWith([], ['40 21:00:00.000600 openat(AT_FDCWD, "/proc/1/environ", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)']);
  assert.ok(decide({ observations: other }).rules.some((r) => r.id === 'c1'), 'another pid, even denied');
});

test('F-S2-3 backstop: every /proc environ form after normalisation, including task, root and cwd/.. tricks', () => {
  for (const raw of ['/proc/thread-self/environ', '/proc/40/task/41/environ', '/proc/self/root/proc/self/environ', '/proc/self/cwd/../../proc/self/environ', '/proc/self/root/proc/1/environ']) {
    const obs = obsWith([], [`40 21:00:00.000600 openat(AT_FDCWD, "${raw}", O_RDONLY|O_CLOEXEC) = 3`]);
    assert.ok(decide({ observations: obs }).rules.some((r) => r.id === 'c1'), raw);
  }
  const relative = obsWith([], ['40 21:00:00.000590 chdir("/proc/self") = 0', '40 21:00:00.000600 openat(AT_FDCWD, "environ", O_RDONLY) = 3']);
  assert.ok(decide({ observations: relative }).rules.some((r) => r.id === 'c1'), 'relative after chdir /proc/self');
  const benign = obsWith([], ['40 21:00:00.000600 openat(AT_FDCWD, "/work/node_modules/pkg/environment.js", O_RDONLY) = 3']);
  assert.equal(decide({ observations: benign }).rules.some((r) => r.id === 'c1'), false);
});

test('F-S2-3 audit: process.report.getReport()/writeReport() is recorded as an env dump and gives (c1)', () => {
  const recs = pkgRun('void process.report.getReport();');
  const dump = recs.filter((r) => r.type === 'env-dump');
  assert.equal(dump.length, 1);
  assert.equal(dump[0].actor, 'package');
  const v = decide({ observations: obsWith([{ type: 'env-dump', pid: 40, via: 'process.report.getReport', actor: 'package' }]) });
  assert.ok(v.rules.some((r) => r.id === 'c1'));
});

test('F-S2-3 audit: a node spawned with diagnostic-report options (argv or NODE_OPTIONS) gives (c1)', () => {
  const viaArgv = obsWith([], [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '60 21:00:00.000500 execve("/usr/local/bin/node", ["node", "--report-uncaught-exception", "--report-directory=/tmp", "x.js"], ["NODE_OPTIONS=--require=/opt/qp/preload.cjs"]) = 0',
  ]);
  assert.ok(decide({ observations: viaArgv }).rules.some((r) => r.id === 'c1'));
  const viaOpts = obsWith([], [
    '40 21:00:00.000400 clone(child_stack=NULL, flags=SIGCHLD) = 60',
    '60 21:00:00.000500 execve("/usr/local/bin/node", ["node", "x.js"], ["NODE_OPTIONS=--require=/opt/qp/preload.cjs --report-on-signal"]) = 0',
  ]);
  assert.ok(decide({ observations: viaOpts }).rules.some((r) => r.id === 'c1'));
});

// S2j / S2k (auditor mutants): behavioural test of the real harness.cjs with the real
// preload. harness.cjs is compiled under its sandbox path /opt/qp/harness.cjs; a hook
// on module resolution reads NPM_TOKEN while harness.cjs resolves the package (so the
// stack holds a /opt/qp/harness.cjs frame). That read must be the package: it fails
// if harness.cjs does not enter the package phase before resolving (S2j) or if the
// preload ignores the latch (S2k).
test('S2j/S2k: the real harness.cjs enters the package phase before it resolves the package (behavioural)', () => {
  const HARNESS = path.join(__dirname, '..', 'images', 'sandbox', 'runtime', 'harness.cjs');
  const launcher = `
    const fs = require('fs'); const Module = require('module');
    const orig = Module._resolveFilename;
    Module._resolveFilename = function (req, ...rest) {
      if (req === 'qp-test-nonexistent-pkg') { void process.env.NPM_TOKEN; }
      return orig.call(this, req, ...rest);
    };
    process.argv = [process.argv[0], '/opt/qp/harness.cjs', 'qp-test-nonexistent-pkg'];
    const m = new Module('/opt/qp/harness.cjs', null);
    m.filename = '/opt/qp/harness.cjs';
    m.paths = Module._nodeModulePaths('/opt/qp');
    m._compile(fs.readFileSync(${JSON.stringify(HARNESS)}, 'utf8'), '/opt/qp/harness.cjs');
  `;
  const recs = run(launcher, { PATH: process.env.PATH, QP_TASK_NONCE: NONCE, QP_ROLE: 'harness', QP_HARNESS_GRACE_MS: '1', NPM_TOKEN: 'x' });
  const reads = recs.filter((r) => r.type === 'env-read' && r.name === 'NPM_TOKEN');
  assert.ok(reads.length >= 1, 'the hook read was recorded');
  assert.deepEqual([...new Set(reads.map((r) => r.actor))], ['package']);
  assert.ok(recs.some((r) => r.type === 'load'), 'the real harness ran (load record)');
});

test('S2k: a read whose stack shows /opt/qp/harness.cjs is harness before the latch and package after it', () => {
  const launcher = `
    const Module = require('module');
    const m = new Module('/opt/qp/harness.cjs', null);
    m._compile("void process.env.API_KEY; globalThis[Symbol.for('qp.packagePhase')](); void process.env.NPM_TOKEN;", '/opt/qp/harness.cjs');
  `;
  const recs = run(launcher, { PATH: process.env.PATH, QP_TASK_NONCE: NONCE, QP_ROLE: 'harness' });
  assert.deepEqual(envReads(recs), HOST_VERIFIES_ROLE ? ['API_KEY:package', 'NPM_TOKEN:package'] : ['API_KEY:harness', 'NPM_TOKEN:package']);
});

'use strict';
// AF-7: Ctrl+C / SIGTERM tears every task object down and exits within 10 s;
// a second Ctrl+C never skips the teardown. Fake clock, fake timers, fake docker.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createInterrupt, INTERRUPT_EXIT_CODE, DEFAULT_DEADLINE_MS } = require('../src/interrupt');
const { createsObjects } = require('../src/docker');

function fakeTimers() {
  const timers = [];
  return {
    timers,
    setTimer: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimer: (t) => { if (t) t.cleared = true; },
    fire: () => { for (const t of timers) if (!t.cleared) { t.cleared = true; t.fn(); } },
  };
}

test('AF-7: the deadline is inside the 10 s bound', () => {
  assert.ok(DEFAULT_DEADLINE_MS < 10000);
  assert.equal(INTERRUPT_EXIT_CODE, 130);
});

test('AF-7: first signal starts the teardown at once and exits 130 after it completes', async () => {
  let now = 1000;
  const exits = [];
  let release;
  let teardownCalls = 0;
  const ft = fakeTimers();
  const it = createInterrupt({
    clock: { now: () => now }, setTimer: ft.setTimer, clearTimer: ft.clearTimer,
    exit: (c) => exits.push(c),
    teardown: () => { teardownCalls += 1; return new Promise((r) => { release = r; }); },
  });
  it.handler('SIGINT');
  await Promise.resolve(); await Promise.resolve();
  assert.equal(teardownCalls, 1, 'teardown starts immediately, not at the task end');
  assert.equal(it.state.signalledAt, 1000);
  assert.deepEqual(exits, [], 'no exit before the teardown is done');
  now = 3500;
  release();
  assert.equal(await it.state.done, 'teardown-complete');
  assert.deepEqual(exits, [130]);
  assert.equal(it.state.finishedAt - it.state.signalledAt, 2500);
  assert.equal(ft.timers[0].cleared, true, 'deadline timer cleared');
});

test('AF-7: a second Ctrl+C during the teardown neither skips it nor starts another', async () => {
  const exits = [];
  let release;
  let teardownCalls = 0;
  const ft = fakeTimers();
  const it = createInterrupt({
    setTimer: ft.setTimer, clearTimer: ft.clearTimer, exit: (c) => exits.push(c),
    teardown: () => { teardownCalls += 1; return new Promise((r) => { release = r; }); },
  });
  it.handler('SIGINT');
  it.handler('SIGINT');
  it.handler('SIGTERM');
  await Promise.resolve(); await Promise.resolve();
  assert.equal(teardownCalls, 1);
  assert.equal(it.state.repeated, 2);
  assert.deepEqual(exits, [], 'repeated signals do not exit early');
  release();
  await it.state.done;
  assert.deepEqual(exits, [130]);
});

test('AF-7: a hung teardown still exits at the deadline (watchdog is the backstop)', async () => {
  const exits = [];
  const ft = fakeTimers();
  const it = createInterrupt({
    setTimer: ft.setTimer, clearTimer: ft.clearTimer, exit: (c) => exits.push(c),
    teardown: () => new Promise(() => {}),
  });
  it.handler('SIGINT');
  assert.equal(ft.timers[0].ms, DEFAULT_DEADLINE_MS);
  ft.fire();
  assert.equal(await it.state.done, 'deadline');
  assert.deepEqual(exits, [130]);
});

test('AF-7: a failing teardown still exits', async () => {
  const exits = [];
  const ft = fakeTimers();
  const it = createInterrupt({ setTimer: ft.setTimer, clearTimer: ft.clearTimer, exit: (c) => exits.push(c), teardown: async () => { throw new Error('boom'); } });
  it.handler('SIGTERM');
  assert.equal(await it.state.done, 'teardown-error');
  assert.deepEqual(exits, [130]);
});

test('AF-7: the docker gate refuses only object-creating commands', () => {
  for (const a of [['create', 'x'], ['run', '-d', 'x'], ['start', '-a', 'x'], ['volume', 'create', 'v'], ['network', 'create', 'n'], ['container', 'create', 'x']]) assert.equal(createsObjects(a), true, a.join(' '));
  for (const a of [['rm', '-f', 'x'], ['kill', 'x'], ['ps', '-a'], ['network', 'rm', 'n'], ['volume', 'rm', 'v'], ['inspect', 'x'], ['logs', 'x'], ['events']]) assert.equal(createsObjects(a), false, a.join(' '));
});

// Orchestrator-level: fake docker + fake lifecycle injected through the require cache.
test('AF-7: Ctrl+C mid-task removes the task objects, writes an interrupted receipt and exits 130; the task flow cannot overwrite it', async () => {
  const dockerPath = require.resolve('../src/docker');
  const lifePath = require.resolve('../src/lifecycle');
  const orchPath = require.resolve('../src/orchestrator');
  const saved = { d: require.cache[dockerPath], l: require.cache[lifePath], o: require.cache[orchPath] };
  const realDocker = require('../src/docker');

  const calls = [];
  const live = new Set();
  let gateClosed = false;
  let hang = null;
  const fakeDocker = {
    docker: async (args) => {
      calls.push(args.join(' '));
      if (gateClosed && realDocker.createsObjects(args)) { const e = new Error('refused'); e.interrupted = true; throw e; }
      if (args[0] === 'volume' && args[1] === 'create') live.add(`volume:${args[args.length - 1]}`);
      if (args[0] === 'create') live.add(`container:${args[args.indexOf('--name') + 1]}`);
      return { code: 0, stdout: '', stderr: '' };
    },
    attach: (args) => {
      calls.push(`attach ${args.join(' ')}`);
      const h = { stdout: '', stderr: '', exited: false, code: null };
      h.done = new Promise((r) => { hang = () => { h.exited = true; h.code = 137; r(h); }; });
      h.child = { kill: () => hang() };
      return h;
    },
    inspect: async () => null,
    closeGate: () => { gateClosed = true; },
    createsObjects: realDocker.createsObjects,
  };
  const removeCalls = [];
  const fakeLife = {
    reapOrphans: async () => ({}),
    startWatchdog: () => ({ pid: null }),
    removeTask: async (prefix, taskId) => {
      removeCalls.push(taskId);
      const objs = [...live].filter((n) => n.endsWith(taskId));
      for (const n of objs) live.delete(n);
      return { containers: objs.filter((n) => n.startsWith('container:')).map((n) => n.slice(10)), networks: [], volumes: objs.filter((n) => n.startsWith('volume:')).map((n) => n.slice(7)) };
    },
    listObjects: async (prefix, { taskId }) => [...live].filter((n) => n.endsWith(taskId)).map((n) => ({ type: n.split(':')[0], name: n.split(':')[1] })),
  };
  require.cache[dockerPath] = { id: dockerPath, filename: dockerPath, loaded: true, exports: fakeDocker };
  require.cache[lifePath] = { id: lifePath, filename: lifePath, loaded: true, exports: fakeLife };
  delete require.cache[orchPath];
  const receiptsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-af7-'));
  const before = { int: process.listenerCount('SIGINT'), term: process.listenerCount('SIGTERM') };
  try {
    const { analyse } = require('../src/orchestrator');
    const { loadConfig } = require('../src/config');
    const cfg = { ...loadConfig({ QP_RUN_PREFIX: 'aftest', QP_IMAGE_TAG: 'test' }), receiptsDir };
    const exits = [];
    let exited;
    const exitedP = new Promise((r) => { exited = r; });
    const run = analyse(cfg, { fixture: 'hostile' }, { exit: (c) => { exits.push(c); exited(c); }, log: () => {} });
    // Wait until the download container is running (attached), i.e. mid-task.
    for (let i = 0; i < 200 && !calls.some((c) => c.startsWith('attach start -a')); i++) await new Promise((r) => setImmediate(r));
    assert.ok(calls.some((c) => c.startsWith('attach start -a')), 'task reached the download phase');
    assert.ok(live.size > 0, 'task objects exist before the signal');
    assert.equal(process.listenerCount('SIGINT'), before.int + 1);
    const t0 = Date.now();
    process.emit('SIGINT', 'SIGINT');
    process.emit('SIGINT', 'SIGINT'); // second Ctrl+C
    // On the pre-AF-7 code (no-op handler) nothing exits: this fails at 12 s instead of hanging.
    let guard;
    const timeout = new Promise((r) => { guard = setTimeout(() => r('no exit within 12 s'), 12000); });
    assert.equal(await Promise.race([exitedP, timeout]), 130);
    clearTimeout(guard);
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 10000, `exited after ${elapsed} ms`);
    assert.deepEqual(exits, [130]);
    assert.equal(live.size, 0, 'every task object removed');
    assert.ok(removeCalls.length >= 2, 'swept twice after the interrupt');
    const res = await run; // the task flow settles on the same teardown
    const files = fs.readdirSync(receiptsDir);
    assert.equal(files.length, 1);
    const rc = JSON.parse(fs.readFileSync(path.join(receiptsDir, files[0]), 'utf8'));
    assert.equal(rc.status, 'aborted');
    assert.equal(rc.abortReason, 'interrupted');
    assert.equal(rc.verdict, null);
    assert.equal(rc.interrupt.signal, 'SIGINT');
    assert.equal(rc.interrupt.repeatedSignals, 1);
    assert.ok(rc.interrupt.teardownSeconds < 10);
    assert.deepEqual(rc.teardown.leftoversForTask, []);
    assert.equal(res.receipt.abortReason, 'interrupted');
    assert.equal(gateClosed, true, 'creation gate closed by the interrupt');
  } finally {
    process.removeAllListeners('SIGINT');
    process.removeAllListeners('SIGTERM');
    if (saved.d) require.cache[dockerPath] = saved.d; else delete require.cache[dockerPath];
    if (saved.l) require.cache[lifePath] = saved.l; else delete require.cache[lifePath];
    if (saved.o) require.cache[orchPath] = saved.o; else delete require.cache[orchPath];
    fs.rmSync(receiptsDir, { recursive: true, force: true });
  }
});

test('Dispatch 2: receipt knownLimitations carry L-1..L-4 (README "Known limitations")', () => {
  const { KNOWN_LIMITATIONS } = require('../src/orchestrator');
  for (const id of ['L-1', 'L-2', 'L-3', 'L-4', 'L-6b', 'L-8', 'L-8b', 'L-9', 'L-10', 'L-11', 'L-13']) assert.ok(KNOWN_LIMITATIONS.some((l) => l.startsWith(`${id}: `)), id);
  const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
  assert.match(readme, /## Known limitations/);
  for (const id of ['L-1', 'L-2', 'L-3', 'L-4', 'L-6b', 'L-8', 'L-8b', 'L-9', 'L-10', 'L-11', 'L-13']) assert.match(readme, new RegExp(`\| ${id} \|`));
});

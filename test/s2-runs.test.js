'use strict';
// S2 option (B), REQ: a runtime harness failure in the traced sandbox is fed back to
// the model once and triggers a SECOND fresh traced run; the verdict uses the UNION
// of the observations of every run, and a completeness marker failing in any run
// fails. Fake docker + fake lifecycle injected through the require cache; fake model.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ENV_OK = '["PATH=/usr/bin", "NODE_OPTIONS=--require=/opt/qp/preload.cjs", "QP_TASK_NONCE=x"]';
const traceFor = (round) => [
  '1 21:00:00.000001 clone(child_stack=NULL, flags=SIGCHLD) = 10',
  '10 21:00:00.000100 execve("/opt/qp/stage.sh", ["/opt/qp/stage.sh", "pkg"], 0x0) = 0',
  '10 21:00:00.000200 clone(child_stack=NULL, flags=SIGCHLD) = 40',
  `40 21:00:00.000300 execve("/usr/local/bin/node", ["node", "/opt/qp/harness.cjs", "pkg"], ${ENV_OK}) = 0`,
  '40 21:00:00.000301 openat(AT_FDCWD, "/opt/qp/preload.cjs", O_RDONLY|O_CLOEXEC) = 3</opt/qp/preload.cjs>',
  // run 1 only: a forbidden write by the package (in the harness process)
  ...(round === 1 ? ['40 21:00:00.000400 openat(AT_FDCWD, "/etc/marker", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)'] : []),
  '10 21:00:00.000900 exit_group(0) = ?',
].join('\n');

// hbRun: the only run whose harness heartbeats; the other run fails instrumentation.
async function twoRunCase(hbRun) {
  const dockerPath = require.resolve('../src/docker');
  const lifePath = require.resolve('../src/lifecycle');
  const orchPath = require.resolve('../src/orchestrator');
  const saved = { d: require.cache[dockerPath], l: require.cache[lifePath], o: require.cache[orchPath] };
  const real = require('../src/docker');

  let nonce = null;
  let sandboxRound = 0;
  let tracerRound = 0;
  const staged = [];
  const calls = [];
  const resolved = (h) => { h.exited = true; h.done = Promise.resolve(h); return h; };
  const fakeDocker = {
    createsObjects: real.createsObjects,
    closeGate: () => {},
    inspect: async () => ({ Id: 'id', Name: '/x', State: { Pid: 1 }, Config: {}, HostConfig: {}, Mounts: [], NetworkSettings: { Networks: new Proxy({}, { get: () => ({ IPAddress: '172.19.0.2' }) }) } }),
    docker: async (args, o = {}) => {
      calls.push(args.join(' '));
      if (args[0] === 'create' && args.includes('/opt/qp/run.sh')) {
        const e = args.find((a) => a.startsWith('QP_TASK_NONCE='));
        nonce = e.split('=')[1];
      }
      if (args[0] === 'run' && args.some((a) => /-meta-/.test(a))) {
        return { code: 0, stdout: `QP-META ${JSON.stringify({ manifest: { name: 'qp-fixture-hostile', version: '1.0.0' }, readme: '# x', entry: 'module.exports=1', entryPath: 'index.js' })}\n`, stderr: '' };
      }
      if (args[0] === 'run' && args.some((a) => /-stage-/.test(a))) { staged.push(o.input); return { code: 0, stdout: '', stderr: '' }; }
      if (args[0] === 'network' && args[1] === 'inspect') return { code: 0, stdout: JSON.stringify([{ IPAM: { Config: [{ Subnet: '172.19.0.0/16' }] }, Internal: true }]), stderr: '' };
      if (args[0] === 'logs') return { code: 0, stdout: '{"type": "ready", "t": "2026-11-04T09:00:00.000000Z"}\n{"type": "flushed", "closed": 0, "t": "2026-11-04T09:00:01.000000Z"}\n', stderr: '' };
      return { code: 0, stdout: '', stderr: '' };
    },
    attach: (args) => {
      calls.push(`attach ${args.join(' ')}`);
      const h = { child: { kill() {} }, stdout: '', stderr: '', truncated: false, exited: false, code: 0 };
      if (args[0] === 'events') { h.done = new Promise(() => {}); return h; }
      const name = args[args.length - 1];
      if (/-download-/.test(name)) { h.stdout = 'QP-INVENTORY {"version":"1.0.0","nonRegistry":[],"packageCount":1,"unpackedBytes":10}\n'; return resolved(h); }
      if (/-sandbox-/.test(name)) {
        sandboxRound += 1;
        const recs = [
          { type: 'load', pid: 40, ok: true, mode: 'fallback-require' },
          { type: 'sandbox-scan', keyLikeEnvNames: [], ignoredImageVars: [], dockerSockPresent: [], mounts: [], envNamesScanned: 5 },
          { type: 'model-harness', pid: 40, ok: false, error: `TypeError: boom in run ${sandboxRound}` },
          // run 2 has NO heartbeat for pid 40: instrumentation fails in run 2 only
          ...(sandboxRound === hbRun ? [{ type: 'hb', pid: 40 }] : []),
        ];
        h.stdout = `QP-TRACER-ATTACHED\n${recs.map((r) => `QPEV ${nonce} ${JSON.stringify(r)}`).join('\n')}\n`;
        return resolved(h);
      }
      if (/-tracer-/.test(name)) { tracerRound += 1; h.stdout = traceFor(tracerRound); return resolved(h); }
      return resolved(h);
    },
  };
  const fakeLife = {
    reapOrphans: async () => ({}), startWatchdog: () => ({ pid: null }),
    removeTask: async () => ({ containers: [], networks: [], volumes: [] }), listObjects: async () => [],
  };
  require.cache[dockerPath] = { id: dockerPath, filename: dockerPath, loaded: true, exports: fakeDocker };
  require.cache[lifePath] = { id: lifePath, filename: lifePath, loaded: true, exports: fakeLife };
  delete require.cache[orchPath];
  const receiptsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-s2b-'));
  try {
    const { analyse } = require('../src/orchestrator');
    const { loadConfig } = require('../src/config');
    const cfg = { ...loadConfig({ QP_RUN_PREFIX: 's2test', QP_IMAGE_TAG: 'test', QP_SANDBOX_TIMEOUT_S: '5' }), receiptsDir };
    const H1 = "module.exports = async () => { require('qp-fixture-hostile').nope(); };";
    const H2 = "module.exports = async () => { require('qp-fixture-hostile'); };";
    const reply = (h) => ({ status: 'ok', latencyMs: 1, usage: { total_tokens: 3 }, content: JSON.stringify({ prediction: { network: { expected: false }, filesOutsidePackage: { expected: false }, childProcesses: { expected: false } }, harness: h, explanation: 'fine' }) });
    const sent = [];
    // S7 E2e: the outcome call (its own system prompt) comes after the receipt with the
    // verdict is written; it sees that receipt on disk with outcomeExplanation pending.
    const { SYSTEM_PROMPT: OUTCOME_PROMPT } = require('../src/outcome');
    const outcomeCalls = [];
    let pendingBody = null;
    const modelSend = async (req) => {
      if (req.messages[0].content === OUTCOME_PROMPT) {
        outcomeCalls.push(req);
        const f = fs.readdirSync(receiptsDir).filter((x) => x.endsWith('.json'));
        pendingBody = f.length === 1 ? fs.readFileSync(path.join(receiptsDir, f[0]), 'utf8') : null;
        return { status: 'ok', latencyMs: 1, model: 'm', content: 'The install script tried to write to a system path, which was refused.' };
      }
      sent.push(req);
      return sent.length === 1 ? reply(H1) : reply(H2);
    };
    const modelCfg = { baseUrl: 'http://fake', model: 'm', fallbackModel: '', maxTokens: 10, timeoutMs: 100, enabled: true };
    const { receipt, receiptPath } = await analyse(cfg, { fixture: 'hostile' }, { modelSend, modelCfg, exit: () => {}, log: () => {} });

    assert.equal(receipt.status, 'completed', JSON.stringify(receipt.abortDetail));
    assert.equal(sent.length, 2, 'exactly one feedback to the model');
    assert.equal(outcomeCalls.length, 1, 'one outcome call, after the verdict');
    const pend = JSON.parse(pendingBody);
    assert.equal(pend.outcomeExplanation.status, 'pending', 'the verdict was written before the outcome call');
    assert.equal(pend.verdict, 'do-not-install');
    const fin = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
    assert.equal(fin.outcomeExplanation.status, 'done');
    assert.equal(fin.outcomeExplanation.source, 'model m');
    assert.equal(fin.outcomeExplanation.guard.accepted, true);
    assert.deepEqual(Object.keys(fin), Object.keys(pend), 'same fields, same order');
    for (const k of Object.keys(pend)) if (k !== 'outcomeExplanation') assert.equal(JSON.stringify(fin[k]), JSON.stringify(pend[k]), `field ${k} unchanged by the rewrite`);
    assert.deepEqual(fs.readdirSync(receiptsDir).filter((x) => x.endsWith('.tmp')), [], 'no temp file left');
    assert.match(sent[1].messages.at(-1).content, /runtime error in the sandbox: TypeError: boom in run 1/);
    assert.deepEqual(staged, [H1, H2], 'the retried harness is staged for run 2');
    assert.equal(receipt.runs.length, 2);
    assert.deepEqual(receipt.runs.map((r) => r.harness), ['model', 'model-retry']);
    assert.equal(sandboxRound, 2, 'no third run');
    assert.ok(calls.some((c) => /^rm -f -v .*-sandbox-/.test(c)), 'run 1 objects removed before run 2');
    // union: run 1's forbidden write decides, although run 2 was clean
    assert.equal(receipt.verdict, 'do-not-install');
    const a = receipt.rulesFired.find((r) => r.id === 'a');
    assert.ok(a && a.observationIds.every((id) => !id.startsWith('r2-')), 'rule a fired from run 1');
    // a marker failing in run 2 only fails the union
    assert.equal(receipt.completeness['instrumentation-heartbeat'].ok, false);
    assert.deepEqual(receipt.completeness['instrumentation-heartbeat'].runs.map((r) => r.ok), hbRun === 1 ? [true, false] : [false, true]);
    assert.equal(receipt.harness.model.staged, true);
    assert.match(receipt.harness.model.fallback, /plain require\(\) only/);
    assert.equal(receipt.model.harness.retries, 1);
    // Enforced (analyst c42cee7a): every sandbox mounts the task volume read-only; the
    // only writable mount of the volume after the download is the stage container,
    // which runs node -e with our fixed script only (no package code, no network).
    const vol = calls.find((c) => c.startsWith('volume create')).split(' ').pop();
    const sandboxCreates = calls.filter((c) => c.startsWith('create ') && c.includes('/opt/qp/run.sh'));
    assert.equal(sandboxCreates.length, 2);
    for (const c of sandboxCreates) {
      assert.ok(c.includes(`-v ${vol}:/in:ro`), c);
      assert.equal(new RegExp(`${vol}:[^ ]*(?<!:ro)( |$)`).test(c.replace(`${vol}:/in:ro`, '')), false, `no other mount of the volume: ${c}`);
    }
    const writers = calls.filter((c) => c.includes(`${vol}:`) && !c.includes(`${vol}:/in:ro`) && !c.startsWith('create ') );
    assert.equal(writers.length, 2, 'two stage writes (run 1 and run 2)');
    for (const c of writers) {
      assert.match(c, /-stage-/, `only the stage container mounts the volume writable: ${c}`);
      assert.match(c, /--network none/);
      assert.match(c, /--entrypoint node .* -e const fs=require\('fs'\);const c=fs\.readFileSync\(0\)/, 'stage runs our fixed script');
    }
  } finally {
    if (saved.d) require.cache[dockerPath] = saved.d; else delete require.cache[dockerPath];
    if (saved.l) require.cache[lifePath] = saved.l; else delete require.cache[lifePath];
    if (saved.o) require.cache[orchPath] = saved.o; else delete require.cache[orchPath];
    process.removeAllListeners('SIGINT');
    process.removeAllListeners('SIGTERM');
    fs.rmSync(receiptsDir, { recursive: true, force: true });
  }
}

test('S2 (B): runtime harness failure -> one retry -> second traced run; verdict on the union; a marker failing only in run 2 fails', () => twoRunCase(1));

// S2b (auditor mutant): the union of markers must not take the last run only.
test('S2 (B): a marker failing only in run 1 still fails the union (not last-run-only)', () => twoRunCase(2));

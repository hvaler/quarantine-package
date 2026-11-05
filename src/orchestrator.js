// Orchestrator: download outside the sandbox, run inside a fresh hardened
// sandbox traced by a separate tracer, observe, decide, write a receipt,
// tear everything down.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { docker, attach, inspect, closeGate } = require('./docker');
const { objName, labels } = require('./config');
const { parseRegistrySpec, resolveFixture } = require('./spec');
const observe = require('./observe');
const { decide } = require('./verdict');
const lifecycle = require('./lifecycle');
const probe = require('./probe');
const { redact, scanText } = require('./secrets');
const { createInterrupt } = require('./interrupt');
const model = require('./model');

const KNOWN_LIMITATIONS = Object.freeze([
  'L-4: ICMP is out of scope: the sandbox has no capability to open raw sockets, and unprivileged ICMP is not logged.',
  'L-4: TLS bodies are not inspected: the sinkhole records the SNI from the ClientHello and refuses the handshake.',
  'UDP other than DNS is logged as an attempt; its original destination comes from the kernel trace when the socket names it.',
  'DNS over TCP is logged as a TCP attempt to port 53 (query name not parsed).',
  'Env-var reads are seen by the in-process preload only; a package can bypass or forge it in its own process. Forged preload records can only add observations; trace-derived completeness markers come from the tracer stream.',
  'Inside the harness process every rule-relevant syscall is attributed to the package (the harness itself performs none).',
  'Paths written through fchdir-relative or unknown directory fds are reported as unresolved and treated as outside the allowed areas.',
  'Side channels inside the kernel (timing, /proc enumeration) are not observed.',
  'L-4: Evasion: in the shared pid namespace a package can see that it is traced (TracerPid, the strace process) and behave benignly; S1 does not hide the tracer.',
  'npm CLI processes do not get the env-read preload (npm fails with a wrapped process.env); an npm started by package code is therefore reported as incomplete instrumentation (review).',
  'L-1: Shell expansion of env variables (e.g. $NPM_TOKEN inside a lifecycle sh) and env reads by sh itself (perl and awk are removed from the image since S2, X10) are invisible to both the kernel trace and the preload (DEC-11r5; their file, network and process activity is still traced and judged).',
  'L-2: DEC-11r4: a package lifecycle that executes a script directly from /work, /tmp or HOME (e.g. "./install.sh" rather than "sh ./install.sh" or "node x.js") fails the instrumentation marker and gets review (i): the trace cannot tell a script from an ELF binary there (fail closed; narrowed in S2, X8).',
  'L-3: Download phase: a non-registry spec in the root manifest aborts before any network request; one deeper in the tree is rejected before it is fetched, but registry metadata of the dependencies visited before it has been fetched. Download-container egress is not limited to the registry host in S1.',
  'L-4: execveat is handled (envp never trusted, SR-3) but is covered by unit tests only, not by a runtime fixture.',
  'L-4: image builds are not byte-reproducible: the bases are pinned by digest, but distribution packages (strace, iptables, tcpdump) are installed at build time.',
  'L-6b: relative file operations of a child process printed before the clone return of its parent have no inherited cwd: they are unresolved, so a write gives (a) and a read gives review (fail closed).',
  'L-8: a chdir by a thread not yet attributed to any process that overlaps an unrelated fork marks that fork raced: relative paths of the child are unresolved (over-condemnation, never install).',
  'L-8b: a benign multi-threaded package whose non-forking thread ever changes directory (e.g. main thread process.chdir while a worker spawns) gets the relative paths of its children unresolved: relative writes give do-not-install (a), relative reads give review. Fail closed by design (dispatch 3).',
  'L-9: a chdir whose outcome is unknown (killed mid-call, "= ?", or never resumed before the trace ends) is treated as applied: the cwd of the thread group and of overlapping or later children become unresolved (fail closed).',
  'L-10: a process cloned with CLONE_FS but not CLONE_THREAD shares its working directory with its parent; both sides get an unresolved cwd for the whole trace (fail closed). Only native code issues such a clone; node, dash and perl do not.',
  'L-11: io_uring is not traced. Node 22 / libuv in the sandbox never issues io_uring_setup (checked with UV_USE_IO_URING=1), and native io_uring is denied by the default Docker seccomp profile the sandbox runs under; native code from a writable mount gives review anyway (L-2).',
  'L-13: a native addon (.node) that the package loads can read env in-process with getenv(); there is no exec and no preload record, so only the intent signal (c1) is lost. Same class as L-1: the sandbox env holds no secret value (C7) and any exfiltration still fires (d)/(f). Extension (S6): native addon + syscalls strace 6.1 cannot name: the tracer cannot trace syscalls above 450, so a native addon calling fchmodat2, the *xattrat calls, open_tree_attr or file_getattr/file_setattr is not observed (glibc 2.36 has no wrappers and the image no binary that uses them).',
  'Sinkhole memory bound: when more than 128 MB is buffered across open connections, the connection holding the most is recorded early with what it sent so far; later bytes on it are not counted.',
  'UDP payloads are logged but, per DEC-2r1, UDP attempts are rated review (f), never do-not-install by payload.',
]);

const HARNESS_MODE = 'require, then the model harness when one is staged (S2)';

function hardeningSnapshot(info) {
  if (!info) return null;
  const hc = info.HostConfig || {};
  return {
    container: info.Name ? info.Name.replace(/^\//, '') : null,
    id: info.Id,
    image: info.Config && info.Config.Image,
    imageId: info.Image,
    User: info.Config && info.Config.User,
    ReadonlyRootfs: hc.ReadonlyRootfs,
    Privileged: hc.Privileged,
    CapDrop: hc.CapDrop,
    CapAdd: hc.CapAdd,
    SecurityOpt: hc.SecurityOpt,
    PidsLimit: hc.PidsLimit,
    Memory: hc.Memory,
    MemorySwap: hc.MemorySwap,
    NanoCpus: hc.NanoCpus,
    Tmpfs: hc.Tmpfs,
    Binds: hc.Binds,
    Mounts: (info.Mounts || []).map((m) => ({ Type: m.Type, Name: m.Name, Destination: m.Destination, RW: m.RW })),
    NetworkMode: hc.NetworkMode,
    PidMode: hc.PidMode,
    IpcMode: hc.IpcMode,
    UsernsMode: hc.UsernsMode,
    AutoRemove: hc.AutoRemove,
  };
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function waitFor(fn, timeoutMs, stepMs = 100) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await sleep(stepMs);
  }
  return null;
}

function hardenedArgs(cfg, { tmpfs }) {
  const L = cfg.limits;
  const args = [
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
    '--user', `${cfg.sandboxUid}:${cfg.sandboxUid}`,
    '--pids-limit', String(L.pids), '--memory', String(L.memoryBytes), '--memory-swap', String(L.memoryBytes),
    '--cpus', String(L.cpus),
  ];
  for (const [p, size] of tmpfs) args.push('--tmpfs', `${p}:rw,exec,nosuid,nodev,size=${size},uid=${cfg.sandboxUid},gid=${cfg.sandboxUid},mode=0700`);
  return args;
}

// Analyse one package. Returns { receipt, receiptPath, exitCode }.
async function analyse(cfg, target, opts = {}) {
  const clock = opts.clock || { now: () => new Date() };
  const taskId = crypto.randomBytes(5).toString('hex');
  const nonce = crypto.randomBytes(12).toString('hex');
  const started = clock.now();
  const N = (role) => objName(cfg, role, taskId);
  const L = labels(cfg, taskId);
  const receipt = {
    schema: 'qp-receipt/1',
    taskId,
    runPrefix: cfg.prefix,
    nonce,
    startedAt: started.toISOString(),
    finishedAt: null,
    status: null,
    verdict: null,
    rulesFired: [],
    package: null,
    limits: { ...cfg.limits },
    images: { tag: cfg.imageTag, ...cfg.images },
    download: null,
    sandbox: null,
    harness: { mode: HARNESS_MODE, loaded: null },
    explanation: { label: 'explanation', source: null, text: null, note: 'The verdict is computed by deterministic rules from the observations; this explanation never changes it.' },
    model: null,
    predictionVsObserved: null,
    completeness: null,
    observations: [],
    network: { sinkholeLog: [] },
    secretScan: null,
    hostProbe: null,
    teardown: null,
    knownLimitations: KNOWN_LIMITATIONS,
    logs: {},
  };

  let watchdog = null;
  const handles = [];
  // AF-7: the first SIGINT/SIGTERM tears this task down at once and exits
  // (130) within the deadline; later signals never skip that teardown.
  let finishing = null;
  const interrupt = createInterrupt({
    exit: opts.exit || ((code) => process.exit(code)),
    log: opts.log || ((m) => process.stderr.write(`qp: ${m}
`)),
    teardown: async (st) => {
      closeGate();
      // Snapshot: the task flow may still be running and must not change what is written.
      const snap = JSON.parse(JSON.stringify(receipt));
      snap.interrupt = { signal: st.signal, signalledAt: new Date(st.signalledAt).toISOString(), repeatedSignals: 0, teardownSeconds: null };
      const r = await finish(abort(snap, 'interrupted', `${st.signal} received; the task was stopped and its objects removed`, 130), { interrupted: st });
      (opts.log || ((m) => process.stderr.write(`qp: ${m}
`)))(r.receipt.interrupt ? `interrupted; teardown took ${r.receipt.interrupt.teardownSeconds} s; receipt ${r.receiptPath}` : `interrupted during the normal teardown; receipt ${r.receiptPath}`);
      return r;
    },
  });
  const onSignal = interrupt.handler;
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  try {
    // ---- input
    let src;
    if (target.fixture) {
      const f = resolveFixture(cfg.fixturesDir, target.fixture);
      if (!f.ok) return abort(receipt, 'invalid-input', f.error, 2);
      src = { kind: 'fixture', name: f.name, version: f.version, dir: f.dir, spec: '/src', label: `fixture:${f.fixture}` };
    } else {
      const s = parseRegistrySpec(target.spec);
      if (!s.ok) return abort(receipt, 'invalid-input', s.error, 2);
      src = { kind: 'registry', name: s.name, spec: s.spec, label: s.spec };
    }
    receipt.package = { requested: src.label, source: src.kind, name: src.name, version: src.version || null };

    // Stale = older than the longest possible task (download + sandbox + probe and teardown slack).
    await lifecycle.reapOrphans(cfg.prefix, { staleMs: (cfg.limits.downloadSeconds + cfg.limits.sandboxSeconds + 300) * 1000 });
    watchdog = lifecycle.startWatchdog(process.pid, cfg.prefix, taskId);

    // ---- download (network on, scripts off)
    const vol = N('vol');
    await docker(['volume', 'create', ...L, vol], { allowFail: false });
    const dlName = N('download');
    const dlArgs = ['create', '--rm', '--name', dlName, ...L,
      ...hardenedArgs(cfg, { tmpfs: [['/tmp', 256 * 1024 * 1024], ['/home/qp', 256 * 1024 * 1024]] }),
      '-v', `${vol}:/out`, '-e', 'HOME=/home/qp'];
    if (src.kind === 'fixture') dlArgs.push('-v', `${src.dir}:/src:ro`);
    dlArgs.push(cfg.images.sandbox, 'timeout', '-s', 'KILL', String(cfg.limits.downloadSeconds + 5), '/opt/qp/download.sh', src.spec, String(cfg.limits.downloadMaxPackages), src.kind === 'fixture' ? src.name : '-');
    await docker(dlArgs, { allowFail: false });
    const dlInfo = await inspect(dlName);
    const dlStart = Date.now();
    const dl = attach(['start', '-a', dlName]);
    handles.push(dl);
    let dlKilled = false;
    const dlTimer = setTimeout(() => { dlKilled = true; docker(['kill', dlName]); }, cfg.limits.downloadSeconds * 1000);
    await dl.done;
    clearTimeout(dlTimer);
    const inv = /QP-INVENTORY (\{.*\})/.exec(dl.stdout);
    const preMatch = /QP-PRECHECK (\{.*\})/.exec(dl.stdout);
    const precheck = preMatch ? JSON.parse(preMatch[1]) : null;
    const lockMatch = /QP-LOCKCHECK (\{.*\})/.exec(dl.stdout);
    const lockcheck = lockMatch ? JSON.parse(lockMatch[1]) : null;
    receipt.download = {
      container: dlName, hardening: hardeningSnapshot(dlInfo), seconds: (Date.now() - dlStart) / 1000,
      exitCode: dl.code, precheck, lockcheck, inventory: inv ? JSON.parse(inv[1]) : null,
      output: redact(tail(dl.stdout.replace(/QP-(INVENTORY|PRECHECK|LOCKCHECK) .*/g, ''), 4000) + tail(dl.stderr, 2000)).text,
    };
    if (dlKilled || dl.code === 137) return await finish(abort(receipt, 'download-time', `download exceeded ${cfg.limits.downloadSeconds}s`, 3));
    // DEC-16 pre-fetch check: non-registry specs anywhere in the tree are rejected before anything is fetched.
    if (precheck && precheck.reason === 'download-non-registry') return await finish(abort(receipt, 'download-non-registry', `non-registry dependency specs: ${precheck.nonRegistry.map((d) => `${d.dependency} (${d.specType}, in ${d.from})`).join('; ').slice(0, 300)}`, 3));
    // Verified lock (before npm ci extracts anything): shrinkwrap pins and any other non-registry resolution.
    if (lockcheck && lockcheck.ok === false) return await finish(abort(receipt, 'download-non-registry', `resolved lock has non-registry entries: ${lockcheck.nonRegistry.map((d) => `${d.path} (${d.reason})`).join('; ').slice(0, 300)}`, 3));
    if (precheck && precheck.reason === 'download-deps') return await finish(abort(receipt, 'download-deps', `more than ${cfg.limits.downloadMaxPackages} packages in the tree`, 3));
    if (!inv || dl.code !== 0) return await finish(abort(receipt, 'download-failed', 'package could not be downloaded (not found, registry error or install failure)', 3));
    const inventory = receipt.download.inventory;
    receipt.package.version = inventory.version;
    // A local fixture is itself installed from a packed tarball; only its dependencies must come from the registry.
    // The exemption covers only where the fixture itself resolved from, never its declared dependency specs.
    inventory.nonRegistry = inventory.nonRegistry.filter((d) => !(src.kind === 'fixture' && d.path === `node_modules/${src.name}` && d.reason === 'resolved outside the registry'));
    if (inventory.nonRegistry.length) return await finish(abort(receipt, 'download-non-registry', 'resolved tree contains non-registry dependencies (git, tarball URL, file or link)', 3));
    if (inventory.packageCount > cfg.limits.downloadMaxPackages) return await finish(abort(receipt, 'download-deps', `${inventory.packageCount} packages exceeds ${cfg.limits.downloadMaxPackages}`, 3));
    if (inventory.unpackedBytes > cfg.limits.downloadMaxBytes) return await finish(abort(receipt, 'download-size', `${inventory.unpackedBytes} bytes exceeds ${cfg.limits.downloadMaxBytes}`, 3));

    // ---- S2 model loop (C8): metadata out of the volume (no network, read-only), then the model.
    const meta = await extractMeta(cfg, vol, N('meta'), L, src.name);
    const consulted = await model.consult({ meta, send: opts.modelSend || model.vultrTransport(), cfg: opts.modelCfg || model.modelConfig() });
    receipt.model = consulted.section;
    receipt.explanation.source = consulted.section.explanation ? `model ${consulted.section.model}` : null;
    receipt.explanation.text = consulted.section.explanation;
    if (consulted.harness) await stageHarness(cfg, vol, N('stage'), L, consulted.harness);

    // ---- traced sandbox run(s). Run 1 always; run 2 only when the staged model
    // harness failed at runtime in run 1 and the single C8 feedback produced a new
    // harness (option B: no package code ever runs outside a traced sandbox).
    const run1 = await sandboxRun(1, consulted.harness ? 'model' : 'none', { vol, src });
    if (run1.abort) return await finish(run1.abort);
    const runs = [run1];
    if (run1.modelHarness && run1.modelHarness.ok === false && consulted.retry) {
      const h2 = await consulted.retry(run1.modelHarness.error || 'harness failed');
      if (h2) {
        await endRun(run1);
        await stageHarness(cfg, vol, N('stage'), L, h2);
        const run2 = await sandboxRun(2, 'model-retry', { vol, src });
        if (run2.abort) return await finish(run2.abort);
        runs.push(run2);
      }
    }

    // ---- decide on the UNION of every traced run (a forbidden act in any run counts;
    // a completeness marker failing in any run fails).
    const observations = [];
    for (const r of runs) {
      for (const o of r.ob.observations) observations.push(r.round === 1 ? o : { ...o, id: `r${r.round}-${o.id}`, run: r.round });
    }
    const decision = decide({ observations });
    const markers = {};
    for (const r of runs) {
      for (const [k, v] of Object.entries(r.ob.markers)) {
        if (!markers[k]) markers[k] = { ok: true, runs: [] };
        markers[k].ok = markers[k].ok && v.ok;
        markers[k].runs.push({ round: r.round, ok: v.ok, detail: v.detail });
      }
    }

    receipt.status = 'completed';
    receipt.verdict = decision.verdict;
    receipt.rulesFired = decision.rules;
    receipt.observations = observations;
    receipt.network.sinkholeLog = runs.flatMap((r) => r.ob.sinkholeLog.map((x) => (r.round === 1 ? x : { ...x, run: r.round })));
    receipt.completeness = markers;
    receipt.predictionVsObserved = model.compare(receipt.model && receipt.model.prediction, observations, { packageName: src.name });
    const last = runs[runs.length - 1];
    receipt.harness.loaded = runs.every((r) => r.load && r.load.ok);
    receipt.harness.detail = last.load ? { mode: last.load.mode, error: last.load.error, resolved: last.load.resolved } : null;
    const staged = runs.some((r) => r.harnessKind !== 'none');
    receipt.harness.model = staged
      ? { staged: true, ran: !!last.modelHarness, ok: last.modelHarness ? last.modelHarness.ok === true : null, error: last.modelHarness && last.modelHarness.error ? redact(String(last.modelHarness.error)).text : null, fallback: last.modelHarness && last.modelHarness.ok === true ? null : 'plain require() only (the product load always runs first; the model harness failed)' }
      : { staged: false, fallback: 'plain require() only: no usable model harness', reason: receipt.model ? receipt.model.status : null };
    receipt.runs = runs.map((r) => ({
      round: r.round, harness: r.harnessKind, mode: r.load ? r.load.mode : null,
      modelHarness: r.modelHarness ? { ok: r.modelHarness.ok === true, error: r.modelHarness.error ? redact(String(r.modelHarness.error)).text : null } : null,
      container: r.sandbox.container, seconds: r.sandbox.seconds, exitCode: r.sandbox.exitCode, endedBy: r.sandbox.endedBy, limitsHit: r.sandbox.limitsHit,
      observations: r.ob.observations.length, traceFile: r.traceFile || null,
    }));
    receipt.sandbox = run1.sandbox;
    if (runs.length > 1) receipt.sandboxRetry = runs[1].sandbox;
    if (run1.traceFile) receipt.traceFile = run1.traceFile;
    receipt.logs.sandboxOutput = run1.output;
    if (runs.length > 1) receipt.logs.sandboxOutputRetry = runs[1].output;
    const scans = runs.map((r) => r.scan);
    receipt.secretScan = {
      sandbox: scans[0],
      ...(runs.length > 1 ? { sandboxRetry: scans[1] } : {}),
    };
    if (scans.some((x) => !x.pass)) receipt.secretScan.sandbox = { ...scans[0], pass: scans.every((x) => x.pass) };
    return await finish({ receipt, exitCode: 0 });
  } catch (err) {
    receipt.status = 'aborted';
    receipt.abortReason = 'infrastructure';
    receipt.abortDetail = String(err && err.message || err).slice(0, 400);
    return await finish({ receipt, exitCode: 4 });
  } finally {
    // While an interrupt teardown runs the handlers stay, so a second Ctrl+C cannot fall through to the default exit.
    if (interrupt.state.signalledAt === null) {
      process.removeListener('SIGINT', onSignal);
      process.removeListener('SIGTERM', onSignal);
    }
  }

  // One traced sandbox run. Returns { abort } (an aborted result for finish) or the
  // run's observations and sandbox section. Object names are the task's; a second
  // run reuses them after endRun() removed the first run's containers and network.
  async function sandboxRun(round, harnessKind, { vol, src }) {
    const net = N('net');
    await docker(['network', 'create', '--internal', ...L, net], { allowFail: false });
    const netInfo = JSON.parse((await docker(['network', 'inspect', net], { allowFail: false })).stdout)[0];
    const subnet = netInfo.IPAM && netInfo.IPAM.Config && netInfo.IPAM.Config[0] && netInfo.IPAM.Config[0].Subnet;
    const sinkName = N('sinkhole');
    await docker(['run', '-d', '--rm', '--name', sinkName, ...L, '--network', net,
      '--read-only', '--tmpfs', '/run:size=1m', '--tmpfs', '/tmp:size=8m',
      '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN', '--security-opt', 'no-new-privileges',
      '--sysctl', 'net.ipv6.conf.all.disable_ipv6=1', '--sysctl', 'net.ipv6.conf.default.disable_ipv6=1',
      '--sysctl', 'net.ipv4.conf.all.route_localnet=1',
      // AF-4: the sinkhole is event-driven (no thread per connection); its own
      // ceilings sit far above anything the sandbox (pids 64) can open.
      '--pids-limit', '256', '--memory', '512m', '--memory-swap', '512m', '--cpus', '0.5', '--ulimit', 'nofile=65536:65536',
      // AF-6: connections are attributed for their whole lifetime, up to the task wall clock.
      '-e', `QP_CONN_DEADLINE_S=${cfg.limits.sandboxSeconds + 10}`,
      '-e', `QP_SANDBOX_UID=${cfg.sandboxUid}`, cfg.images.sinkhole], { allowFail: false });
    const ready = await waitFor(async () => /"type": "ready"/.test((await docker(['logs', sinkName])).stdout), 15000, 200);
    if (!ready) return { abort: abort(receipt, 'infrastructure', `sinkhole did not become ready (run ${round})`, 4) };
    const sinkInfo = await inspect(sinkName);
    const sinkholeIp = sinkInfo && sinkInfo.NetworkSettings.Networks[net] && sinkInfo.NetworkSettings.Networks[net].IPAddress;

    // ---- optional host probe (C2 / DEC-5r1), first run only
    let probeRun = null;
    if (opts.hostProbe && round === 1) probeRun = await probe.start(cfg, { taskId, labels: L, subnet, sinkholeIp, nonceName: `qp-${nonce}.probe.invalid` });

    // ---- sandbox (created, snapshotted, started) + tracer
    const sbName = N('sandbox');
    // Docker-side evidence for the end reason: OOM, and kill/stop/destroy issued
    // through the Docker API (never emitted for a signal sent inside the container).
    const events = attach(['events', '--filter', `container=${sbName}`, '--filter', `container=${sinkName}`,
      '--filter', 'event=oom', '--filter', 'event=kill', '--filter', 'event=stop', '--filter', 'event=destroy',
      '--format', '{{.Action}} {{.Actor.Attributes.name}}']);
    handles.push(events);
    const sbArgs = ['create', '--rm', '--name', sbName, ...L, '--network', `container:${sinkName}`,
      ...hardenedArgs(cfg, { tmpfs: [['/work', cfg.limits.tmpfsWorkBytes], ['/tmp', cfg.limits.tmpfsTmpBytes], ['/home/qp', cfg.limits.tmpfsHomeBytes]] }),
      '-v', `${vol}:/in:ro`,
      '-e', 'NODE_OPTIONS=--require=/opt/qp/preload.cjs', '-e', `QP_TASK_NONCE=${nonce}`, '-e', 'HOME=/home/qp',
    ];
    if (opts.hostProbe && round === 1) sbArgs.push('-e', `QP_PROBE_NAME=qp-${nonce}.probe.invalid`);
    sbArgs.push(cfg.images.sandbox, '/opt/qp/run.sh', String(cfg.limits.sandboxSeconds), src.name);
    await docker(sbArgs, { allowFail: false });
    const sbInfo = await inspect(sbName);
    const sbStart = Date.now();
    const sb = attach(['start', '-a', sbName]);
    handles.push(sb);
    const running = await waitFor(async () => { const i = await inspect(sbName); return i && i.State && i.State.Pid > 0; }, 15000, 50);
    const trName = N('tracer');
    let tr = null;
    let trInfo = null;
    if (running) {
      await docker(['create', '--rm', '--name', trName, ...L, '--pid', `container:${sbName}`, '--network', 'none',
        '--read-only', '--cap-drop', 'ALL', '--cap-add', 'SYS_PTRACE', '--security-opt', 'no-new-privileges',
        '--user', '0:0', '--pids-limit', '16', '--memory', '256m', '--memory-swap', '256m', '--cpus', '0.5',
        '--entrypoint', '/opt/qp/trace.sh', cfg.images.sandbox], { allowFail: false });
      trInfo = await inspect(trName);
      tr = attach(['start', '-a', trName]);
      handles.push(tr);
    }
    let killed = false;
    let trEndedAt = null;
    if (tr) tr.done.then(() => { trEndedAt = Date.now(); });
    const sbTimer = setTimeout(() => { killed = true; docker(['kill', sbName]); }, cfg.limits.sandboxSeconds * 1000);
    await sb.done;
    const sbEndedAt = Date.now();
    clearTimeout(sbTimer);
    const sbSeconds = (sbEndedAt - sbStart) / 1000;
    if (tr) await Promise.race([tr.done, sleep(10000)]);
    if (tr && !tr.exited) await docker(['kill', trName]);
    // DEC-12r1 (a): the tracer never attached, so the package never ran: infrastructure abort, no verdict.
    // Only the first marker line counts: package code runs after it and cannot precede it.
    const firstMarker = (/^QP-TRACER-(ATTACHED|MISSING)\s*$/m.exec(sb.stdout) || [])[1];
    if (!tr || firstMarker !== 'ATTACHED') {
      events.child.kill();
      receipt.sandbox = { container: sbName, round, containerId: sbInfo && sbInfo.Id, exitCode: sb.code, hardening: hardeningSnapshot(sbInfo), tracer: { container: trName, hardening: hardeningSnapshot(trInfo), attached: false } };
      return { abort: abort(receipt, 'tracer-unavailable', `the tracer did not attach within 10 s (run ${round}); the package was not run`, 4) };
    }
    // DEC-12r1 (b): the tracer stream ended before the sandbox did: kernel trace incomplete.
    const traceComplete = !(trEndedAt !== null && trEndedAt < sbEndedAt - 1000);
    events.child.kill();
    // AF-6: the sandbox has ended; the sinkhole drains and records every connection
    // still open, with all bytes received (SIGUSR1 -> "flushed"). If the flush is not
    // confirmed, any traced connect left without a record fails the sinkhole-log
    // marker (AF-4(a) backstop), so a missed record can never read as "no payload".
    await docker(['kill', '-s', 'USR1', sinkName]);
    const flushed = await waitFor(async () => /"type": "flushed"/.test((await docker(['logs', sinkName])).stdout), 5000, 200);
    const evLines = events.stdout.split(/\r?\n/).filter(Boolean);
    const oom = evLines.some((l) => l.startsWith('oom '));

    // ---- end reason from evidence only (ruling on S1-D2)
    const backstopFired = sb.code === 137 && !killed && !oom && sbSeconds >= cfg.limits.sandboxSeconds + 4;
    const sinkholeAlive = !!(await inspect(sinkName));
    const foreignSandboxKill = evLines.some((l) => /^(kill|stop) /.test(l) && l.endsWith(` ${sbName}`)) && !killed;
    const sinkholeStopped = evLines.some((l) => /^(kill|stop|destroy) /.test(l) && l.endsWith(` ${sinkName}`));
    if (!killed && !oom && !backstopFired && (foreignSandboxKill || sinkholeStopped || !sinkholeAlive)) {
      receipt.sandbox = { container: sbName, round, containerId: sbInfo && sbInfo.Id, exitCode: sb.code, seconds: sbSeconds, sinkholeAlive, dockerEvents: evLines.slice(0, 20), hardening: hardeningSnapshot(sbInfo) };
      return { abort: abort(receipt, 'killed-externally', `the sandbox ended with exit ${sb.code} after ${sbSeconds.toFixed(1)} s (run ${round}); Docker reported a kill/stop/removal not issued by this task (sandbox kill: ${foreignSandboxKill}, sinkhole stopped or gone: ${sinkholeStopped || !sinkholeAlive})`, 4) };
    }

    // ---- probe controls and stop
    if (probeRun) receipt.hostProbe = await probe.finish(cfg, probeRun, { taskId, labels: L, net, sinkholeIp });

    // ---- observe this run
    // From the container exit status only (stdout is package-writable).
    const ended = sb.code === 0 && !killed;
    const limits = [];
    if (killed) limits.push({ reason: 'wall-clock', detail: `killed by the orchestrator after ${cfg.limits.sandboxSeconds}s` });
    else if (backstopFired) limits.push({ reason: 'wall-clock', detail: `killed by the in-container hard timeout (wall + 5 s) after ${sbSeconds.toFixed(1)} s` });
    if (oom) limits.push({ reason: 'memory', detail: 'OOM kill reported by Docker' });
    // Dispatch 3: optional raw trace beside the receipt, never inside it. The trace is
    // of the sandbox only, which holds no secret (C7); it is still pattern-scanned and
    // any matching line redacted before it is written, and `scan-secrets` covers it.
    const traceFile = cfg.keepTrace && tr ? keepTrace(cfg, round === 1 ? taskId : `${taskId}.r${round}`, tr.stdout, tr.truncated) : null;
    const ob = observe.build({
      traceText: tr ? tr.stdout : '', sinkholeText: (await docker(['logs', sinkName])).stdout,
      stdoutText: sb.stdout, nonce, limits, sandboxEndedNormally: ended, sinkholeIp, traceComplete,
    });
    const pidsObs = ob.observations.find((o) => o.kind === 'pids-exhaustion');
    // DEC-17: pids exhaustion is a limit even when the shell gives up and the task then exits.
    if (pidsObs && !limits.some((l) => l.reason === 'pids')) {
      ob.observations.push({ id: `o${ob.observations.length + 1}`, kind: 'limit', actor: null, nonce, reason: 'pids', detail: `${pidsObs.failedForks} fork/clone calls failed with EAGAIN at pids-limit ${cfg.limits.pids}` });
      limits.push({ reason: 'pids', detail: 'process limit exhausted' });
    }
    const recs = observe.parsePreload(sb.stdout, nonce).recs;
    const load = ob.observations.find((o) => o.kind === 'load');
    // Model harness outcome (reported by the harness process; package-writable, so it
    // only decides whether the single retry runs, never the verdict).
    const modelHarness = harnessKind === 'none' ? null : (recs.find((r) => r.type === 'model-harness' && (!load || r.pid === load.pid)) || null);
    const scanRec = recs.find((r) => r.type === 'sandbox-scan');
    const shown = sb.stdout.split(/\r?\n/).filter((l) => !l.startsWith('QPEV ')).join('\n');
    return {
      round, harnessKind, ob, load, modelHarness, traceFile, net, sinkName, sbName, trName,
      output: redact(tail(shown, 8000)).text,
      scan: scanRec ? { keyLikeEnvNames: scanRec.keyLikeEnvNames, ignoredImageVars: scanRec.ignoredImageVars, dockerSockPresent: scanRec.dockerSockPresent, mounts: scanRec.mounts, envNamesScanned: scanRec.envNamesScanned, pass: scanRec.keyLikeEnvNames.length === 0 && scanRec.dockerSockPresent.length === 0 } : { pass: false, error: 'no in-sandbox scan record' },
      sandbox: {
        container: sbName, round, fresh: true, containerId: sbInfo && sbInfo.Id, seconds: sbSeconds, exitCode: sb.code,
        endedBy: killed ? 'orchestrator-kill' : sb.code === 137 ? 'kill' : 'exit',
        limitsHit: limits,
        hardening: hardeningSnapshot(sbInfo),
        tracer: { container: trName, hardening: hardeningSnapshot(trInfo), traceBytes: tr ? tr.stdout.length : 0, truncated: tr ? tr.truncated : null },
        sinkhole: { container: sinkName, ip: sinkholeIp, hardening: hardeningSnapshot(sinkInfo), records: ob.sinkhole.records, controlRecords: ob.sinkhole.control, flushed: !!flushed },
        network: { name: net, internal: netInfo.Internal === true, subnet, enableIPv6: netInfo.EnableIPv6 === true },
        roles: ob.roles,
        allowedAreaWrites: ob.allowedAreaWrites,
        preloadForeignRecords: ob.preloadForeignRecords,
      },
    };
  }

  // Removes a finished run's containers and network (the volume stays) so the next
  // run starts fresh under the same task-scoped names.
  async function endRun(r) {
    await docker(['rm', '-f', '-v', r.sbName, r.trName, r.sinkName], { timeoutMs: 60000 });
    await docker(['network', 'rm', r.net], { timeoutMs: 60000 });
  }

  // Idempotent: the first caller (task flow or interrupt) runs the teardown; later callers share it.
  function finish(result, how = {}) {
    if (!finishing) finishing = doFinish(result, how);
    return finishing;
  }

  async function doFinish(result, { interrupted = null } = {}) {
    for (const h of handles) if (!h.exited) { try { h.child.kill(); } catch (_) { /* gone */ } }
    let removed = await lifecycle.removeTask(cfg.prefix, taskId);
    if (interrupted) {
      // An object whose create was in flight at the signal can appear just after the first sweep.
      await sleep(1000);
      const again = await lifecycle.removeTask(cfg.prefix, taskId);
      removed = {
        containers: [...new Set([...removed.containers, ...again.containers])],
        networks: [...new Set([...removed.networks, ...again.networks])],
        volumes: [...new Set([...removed.volumes, ...again.volumes])],
      };
    }
    const left = await lifecycle.listObjects(cfg.prefix, { taskId, nameSweep: true });
    result.receipt.teardown = { removed, leftoversForTask: left.map((o) => `${o.type}:${o.name}`), hostTempDirs: [] };
    // After an interrupt the watchdog stays: it sweeps the task once more when this process has exited.
    if (watchdog && !interrupted) { try { process.kill(watchdog.pid); } catch (_) { /* already gone */ } }
    if (interrupted) {
      result.receipt.interrupt.teardownSeconds = (Date.now() - interrupted.signalledAt) / 1000;
      result.receipt.interrupt.repeatedSignals = interrupted.repeated;
    }
    result.receipt.finishedAt = clock.now().toISOString();
    // C7: the receipt itself is pattern-scanned before it is written.
    let body = JSON.stringify(result.receipt, null, 2);
    const hits = scanText(body, 'receipt');
    result.receipt.secretScan = { ...(result.receipt.secretScan || {}), receipt: { pass: hits.length === 0, hits: hits.map((h) => ({ line: h.line, pattern: h.pattern })) } };
    if (hits.length) body = redact(JSON.stringify(result.receipt, null, 2)).text;
    else body = JSON.stringify(result.receipt, null, 2);
    fs.mkdirSync(cfg.receiptsDir, { recursive: true });
    const receiptPath = path.join(cfg.receiptsDir, `${result.receipt.taskId}.json`);
    fs.writeFileSync(receiptPath, body + '\n');
    return { ...result, receiptPath };
  }
}

// Package metadata for the model (S2-SEC a): manifest, README and entry excerpts,
// read inside a hardened, network-less container from the read-only volume.
const META_SCRIPT = `
const fs=require('fs'),path=require('path');const name=process.argv[1];
const root=path.join('/in/node_modules',name);const rd=(f,n)=>{try{const b=fs.readFileSync(f);return b.subarray(0,n).toString('utf8')}catch(_){return null}};
let manifest=null;try{manifest=JSON.parse(rd(path.join(root,'package.json'),200000))}catch(_){}
let readme=null;try{const f=fs.readdirSync(root).find(x=>/^readme(\\.|$)/i.test(x));if(f)readme=rd(path.join(root,f),8000)}catch(_){}
let entryPath=null,entry=null;try{entryPath=require.resolve(root);if(!entryPath.startsWith(root+path.sep))entryPath=null;else entry=rd(entryPath,6000)}catch(_){}
process.stdout.write('QP-META '+JSON.stringify({manifest,readme,entry,entryPath:entryPath&&path.relative(root,entryPath)})+'\\n');`;

async function extractMeta(cfg, vol, name, L, pkgName) {
  const r = await docker(['run', '--rm', '--name', name, ...L, '--network', 'none',
    ...hardenedArgs(cfg, { tmpfs: [['/tmp', 16 * 1024 * 1024]] }),
    '-v', `${vol}:/in:ro`, '--entrypoint', 'node', cfg.images.sandbox, '-e', META_SCRIPT, pkgName], { timeoutMs: 60000 });
  const m = /QP-META (\{.*\})/.exec(r.stdout || '');
  try { return m ? JSON.parse(m[1]) : {}; } catch (_) { return {}; }
}

// The model harness is written into the volume (read-only inside the sandbox) by a
// separate network-less container; it is never placed in an env var or argv.
async function stageHarness(cfg, vol, name, L, code) {
  await docker(['run', '--rm', '-i', '--name', name, ...L, '--network', 'none',
    ...hardenedArgs(cfg, { tmpfs: [['/tmp', 16 * 1024 * 1024]] }),
    '-v', `${vol}:/out`, '--entrypoint', 'node', cfg.images.sandbox, '-e',
    "const fs=require('fs');const c=fs.readFileSync(0);fs.mkdirSync('/out/.qp',{recursive:true});fs.rmSync('/out/.qp/model-harness.cjs',{force:true});fs.writeFileSync('/out/.qp/model-harness.cjs',c,{mode:0o444})"],
  { timeoutMs: 60000, allowFail: false, input: code });
}

function keepTrace(cfg, taskId, text, truncated) {
  const hits = scanText(text, 'trace');
  const body = hits.length ? redact(text).text : text;
  fs.mkdirSync(cfg.receiptsDir, { recursive: true });
  const file = `${taskId}.trace`;
  fs.writeFileSync(path.join(cfg.receiptsDir, file), body);
  return { file, bytes: Buffer.byteLength(body), truncated: !!truncated, secretScan: { pass: hits.length === 0, redactedLines: hits.length } };
}

function abort(receipt, reason, detail, exitCode) {
  receipt.status = 'aborted';
  receipt.verdict = null;
  receipt.abortReason = reason;
  receipt.abortDetail = detail;
  return { receipt, exitCode };
}

function tail(s, n) { s = String(s || ''); return s.length > n ? `…${s.slice(-n)}` : s; }

module.exports = { analyse, hardeningSnapshot, keepTrace, KNOWN_LIMITATIONS };

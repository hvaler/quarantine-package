// Orchestrator: download outside the sandbox, run inside a fresh hardened
// sandbox traced by a separate tracer, observe, decide, write a receipt,
// tear everything down.
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { docker, attach, inspect } = require('./docker');
const { objName, labels } = require('./config');
const { parseRegistrySpec, resolveFixture } = require('./spec');
const observe = require('./observe');
const { decide } = require('./verdict');
const lifecycle = require('./lifecycle');
const probe = require('./probe');
const { redact, scanText } = require('./secrets');

const KNOWN_LIMITATIONS = Object.freeze([
  'ICMP is out of scope: the sandbox has no capability to open raw sockets, and unprivileged ICMP is not logged.',
  'TLS bodies are not inspected: the sinkhole records the SNI from the ClientHello and refuses the handshake.',
  'UDP other than DNS is logged as an attempt; its original destination comes from the kernel trace when the socket names it.',
  'DNS over TCP is logged as a TCP attempt to port 53 (query name not parsed).',
  'Env-var reads are seen by the in-process preload only; a package can bypass or forge it in its own process. Forged preload records can only add observations; trace-derived completeness markers come from the tracer stream.',
  'Inside the harness process every rule-relevant syscall is attributed to the package (the harness itself performs none).',
  'Paths written through fchdir-relative or unknown directory fds are reported as unresolved and treated as outside the allowed areas.',
  'Side channels inside the kernel (timing, /proc enumeration) are not observed.',
  'Evasion: in the shared pid namespace a package can see that it is traced (TracerPid, the strace process) and behave benignly; S1 does not hide the tracer.',
  'npm CLI processes do not get the env-read preload (npm fails with a wrapped process.env); an npm started by package code is therefore reported as incomplete instrumentation (review).',
  'Shell expansion of env variables (e.g. $NPM_TOKEN inside a lifecycle sh) is invisible to both the kernel trace and the preload.',
  'UDP payloads are logged but, per DEC-2r1, UDP attempts are rated review (f), never do-not-install by payload.',
]);

const HARNESS_MODE = 'fallback-require (no model in S1)';

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
    explanation: { source: 'none (no model in S1)', text: null, note: 'The verdict is computed by deterministic rules; an explanation never changes it.' },
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
  const onSignal = () => { /* teardown runs in finally; keep process alive until done */ };
  try {
    // ---- input
    let src;
    if (target.fixture) {
      const f = resolveFixture(cfg.fixturesDir, target.fixture);
      if (!f.ok) return abort(receipt, 'invalid-input', f.error, 2);
      src = { kind: 'fixture', name: f.name, dir: f.dir, spec: '/src', label: `fixture:${f.fixture}` };
    } else {
      const s = parseRegistrySpec(target.spec);
      if (!s.ok) return abort(receipt, 'invalid-input', s.error, 2);
      src = { kind: 'registry', name: s.name, spec: s.spec, label: s.spec };
    }
    receipt.package = { requested: src.label, source: src.kind, name: src.name, version: null };

    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    await lifecycle.reapOrphans(cfg.prefix);
    watchdog = lifecycle.startWatchdog(process.pid, cfg.prefix, taskId);

    // ---- download (network on, scripts off)
    const vol = N('vol');
    await docker(['volume', 'create', ...L, vol], { allowFail: false });
    const dlName = N('download');
    const dlArgs = ['create', '--rm', '--name', dlName, ...L,
      ...hardenedArgs(cfg, { tmpfs: [['/tmp', 256 * 1024 * 1024], ['/home/qp', 256 * 1024 * 1024]] }),
      '-v', `${vol}:/out`, '-e', 'HOME=/home/qp'];
    if (src.kind === 'fixture') dlArgs.push('-v', `${src.dir}:/src:ro`);
    dlArgs.push(cfg.images.sandbox, 'timeout', '-s', 'KILL', String(cfg.limits.downloadSeconds + 5), '/opt/qp/download.sh', src.spec);
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
    receipt.download = {
      container: dlName, hardening: hardeningSnapshot(dlInfo), seconds: (Date.now() - dlStart) / 1000,
      exitCode: dl.code, inventory: inv ? JSON.parse(inv[1]) : null,
      output: redact(tail(dl.stdout.replace(/QP-INVENTORY .*/, ''), 4000) + tail(dl.stderr, 2000)).text,
    };
    if (dlKilled || dl.code === 137) return await finish(abort(receipt, 'download-time', `download exceeded ${cfg.limits.downloadSeconds}s`, 3));
    if (!inv || dl.code !== 0) return await finish(abort(receipt, 'download-failed', 'package could not be downloaded (not found, registry error or install failure)', 3));
    const inventory = receipt.download.inventory;
    receipt.package.version = inventory.version;
    // A local fixture is itself installed from a packed tarball; only its dependencies must come from the registry.
    inventory.nonRegistry = inventory.nonRegistry.filter((d) => !(src.kind === 'fixture' && d.path === `node_modules/${src.name}`));
    if (inventory.nonRegistry.length) return await finish(abort(receipt, 'download-non-registry', 'resolved tree contains non-registry dependencies (git, tarball URL, file or link)', 3));
    if (inventory.packageCount > cfg.limits.downloadMaxPackages) return await finish(abort(receipt, 'download-deps', `${inventory.packageCount} packages exceeds ${cfg.limits.downloadMaxPackages}`, 3));
    if (inventory.unpackedBytes > cfg.limits.downloadMaxBytes) return await finish(abort(receipt, 'download-size', `${inventory.unpackedBytes} bytes exceeds ${cfg.limits.downloadMaxBytes}`, 3));

    // ---- internal network + sinkhole
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
      '--pids-limit', '64', '--memory', '128m', '--cpus', '0.5',
      '-e', `QP_SANDBOX_UID=${cfg.sandboxUid}`, cfg.images.sinkhole], { allowFail: false });
    const ready = await waitFor(async () => /"type": "ready"/.test((await docker(['logs', sinkName])).stdout), 15000, 200);
    if (!ready) return await finish(abort(receipt, 'infrastructure', 'sinkhole did not become ready', 4));
    const sinkInfo = await inspect(sinkName);
    const sinkholeIp = sinkInfo && sinkInfo.NetworkSettings.Networks[net] && sinkInfo.NetworkSettings.Networks[net].IPAddress;

    // ---- optional host probe (C2 / DEC-5r1)
    let probeRun = null;
    if (opts.hostProbe) probeRun = await probe.start(cfg, { taskId, labels: L, subnet, sinkholeIp, nonceName: `qp-${nonce}.probe.invalid` });

    // ---- sandbox (created, snapshotted, started) + tracer
    const sbName = N('sandbox');
    const events = attach(['events', '--filter', `container=${sbName}`, '--filter', 'event=oom', '--format', '{{.Action}}']);
    handles.push(events);
    const sbArgs = ['create', '--rm', '--name', sbName, ...L, '--network', `container:${sinkName}`,
      ...hardenedArgs(cfg, { tmpfs: [['/work', cfg.limits.tmpfsWorkBytes], ['/tmp', cfg.limits.tmpfsTmpBytes], ['/home/qp', cfg.limits.tmpfsHomeBytes]] }),
      '-v', `${vol}:/in:ro`,
      '-e', 'NODE_OPTIONS=--require=/opt/qp/preload.cjs', '-e', `QP_TASK_NONCE=${nonce}`, '-e', 'HOME=/home/qp',
    ];
    if (opts.hostProbe) sbArgs.push('-e', `QP_PROBE_NAME=qp-${nonce}.probe.invalid`);
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
      receipt.sandbox = { container: sbName, containerId: sbInfo && sbInfo.Id, exitCode: sb.code, hardening: hardeningSnapshot(sbInfo), tracer: { container: trName, hardening: hardeningSnapshot(trInfo), attached: false } };
      return await finish(abort(receipt, 'tracer-unavailable', 'the tracer did not attach within 10 s; the package was not run', 4));
    }
    // DEC-12r1 (b): the tracer stream ended before the sandbox did: kernel trace incomplete.
    const traceComplete = !(trEndedAt !== null && trEndedAt < sbEndedAt - 1000);
    events.child.kill();
    await sleep(200);
    const oom = /oom/.test(events.stdout);

    // ---- probe controls and stop
    if (probeRun) receipt.hostProbe = await probe.finish(cfg, probeRun, { taskId, labels: L, net, sinkholeIp });

    // ---- observe and decide
    // From the container exit status only (stdout is package-writable).
    const ended = sb.code === 0 && !killed;
    const limits = [];
    if (killed) limits.push({ reason: 'wall-clock', detail: `killed by the orchestrator after ${cfg.limits.sandboxSeconds}s` });
    else if (sb.code === 137 && !oom) limits.push({ reason: 'wall-clock', detail: 'killed by the in-container hard timeout' });
    if (oom) limits.push({ reason: 'memory', detail: 'OOM kill reported by Docker' });
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
    const decision = decide({ observations: ob.observations });

    const scanRec = observe.parsePreload(sb.stdout, nonce).recs.find((r) => r.type === 'sandbox-scan');
    receipt.status = 'completed';
    receipt.verdict = decision.verdict;
    receipt.rulesFired = decision.rules;
    receipt.observations = ob.observations;
    receipt.network.sinkholeLog = ob.sinkholeLog;
    receipt.completeness = ob.markers;
    const load = ob.observations.find((o) => o.kind === 'load');
    receipt.harness.loaded = !!(load && load.ok);
    receipt.harness.detail = load ? { mode: load.mode, error: load.error, resolved: load.resolved } : null;
    receipt.sandbox = {
      container: sbName, fresh: true, containerId: sbInfo && sbInfo.Id, seconds: sbSeconds, exitCode: sb.code,
      endedBy: killed ? 'orchestrator-kill' : sb.code === 137 ? 'kill' : 'exit',
      limitsHit: limits,
      hardening: hardeningSnapshot(sbInfo),
      tracer: { container: trName, hardening: hardeningSnapshot(trInfo), traceBytes: tr ? tr.stdout.length : 0, truncated: tr ? tr.truncated : null },
      sinkhole: { container: sinkName, ip: sinkholeIp, hardening: hardeningSnapshot(sinkInfo), records: ob.sinkhole.records, controlRecords: ob.sinkhole.control },
      network: { name: net, internal: netInfo.Internal === true, subnet, enableIPv6: netInfo.EnableIPv6 === true },
      roles: ob.roles,
      allowedAreaWrites: ob.allowedAreaWrites,
      preloadForeignRecords: ob.preloadForeignRecords,
    };
    const shown = sb.stdout.split(/\r?\n/).filter((l) => !l.startsWith('QPEV ')).join('\n');
    receipt.logs.sandboxOutput = redact(tail(shown, 8000)).text;
    receipt.secretScan = {
      sandbox: scanRec ? { keyLikeEnvNames: scanRec.keyLikeEnvNames, ignoredImageVars: scanRec.ignoredImageVars, dockerSockPresent: scanRec.dockerSockPresent, mounts: scanRec.mounts, envNamesScanned: scanRec.envNamesScanned, pass: scanRec.keyLikeEnvNames.length === 0 && scanRec.dockerSockPresent.length === 0 } : { pass: false, error: 'no in-sandbox scan record' },
    };
    return await finish({ receipt, exitCode: 0 });
  } catch (err) {
    receipt.status = 'aborted';
    receipt.abortReason = 'infrastructure';
    receipt.abortDetail = String(err && err.message || err).slice(0, 400);
    return await finish({ receipt, exitCode: 4 });
  } finally {
    process.removeListener('SIGINT', onSignal);
    process.removeListener('SIGTERM', onSignal);
  }

  async function finish(result) {
    for (const h of handles) if (!h.exited) { try { h.child.kill(); } catch (_) { /* gone */ } }
    const removed = await lifecycle.removeTask(cfg.prefix, taskId);
    const left = (await lifecycle.listObjects(cfg.prefix, ['--filter', `label=qp.task-id=${taskId}`]));
    result.receipt.teardown = { removed, leftoversForTask: left.map((o) => `${o.type}:${o.name}`), hostTempDirs: [] };
    if (watchdog) { try { process.kill(watchdog.pid); } catch (_) { /* already gone */ } }
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

function abort(receipt, reason, detail, exitCode) {
  receipt.status = 'aborted';
  receipt.verdict = null;
  receipt.abortReason = reason;
  receipt.abortDetail = detail;
  return { receipt, exitCode };
}

function tail(s, n) { s = String(s || ''); return s.length > n ? `…${s.slice(-n)}` : s; }

module.exports = { analyse, hardeningSnapshot, KNOWN_LIMITATIONS };

// Observation builder: joins the kernel trace (authoritative), the sinkhole log
// and the preload records into receipt observations. Pure: no I/O.
'use strict';

const { analyse } = require('./trace');
const { DOCKER_SOCKETS, CREDENTIAL_PATHS, KEY_LIKE } = require('./verdict');

const NPM_CLI_PATHS = ['/usr/local/bin/npm', '/usr/local/lib/node_modules/npm/bin/npm-cli.js'];
const DEVICE_SINKS =['/dev/null', '/dev/tty', '/dev/stdout', '/dev/stderr', '/dev/fd', '/proc/self/fd', '/proc/thread-self/fd'];
const MAX_ALLOWED_AREA_WRITES = 200;
const MAX_SPAWNS = 50;

const under = (p, root) => typeof p === 'string' && (p === root || p.startsWith(`${root}/`));

function secondsOfDayIso(iso) {
  const m = /T(\d\d):(\d\d):(\d\d(?:\.\d+)?)Z$/.exec(String(iso || ''));
  return m ? Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3]) : null;
}

function parseJsonLines(text, prefix) {
  const out = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    let body = line;
    if (prefix) {
      if (!line.startsWith(prefix)) continue;
      body = line.slice(prefix.length);
    }
    try { out.push(JSON.parse(body)); } catch (_) { /* not a record */ }
  }
  return out;
}

// Preload/harness records on stdout: "QPEV <nonce> <json>". Records with another nonce are dropped.
function parsePreload(stdout, nonce) {
  const recs = [];
  let foreign = 0;
  for (const line of String(stdout || '').split(/\r?\n/)) {
    const m = /^QPEV (\S+) (\{.*\})\s*$/.exec(line);
    if (!m) continue;
    if (m[1] !== nonce) { foreign += 1; continue; }
    try { recs.push(JSON.parse(m[2])); } catch (_) { foreign += 1; }
  }
  return { recs, foreign };
}

function processRoles(tr) {
  const execs = tr.events.filter((e) => e.type === 'exec');
  const firstExec = (pred) => execs.find(pred);
  const stage = firstExec((e) => e.path === '/opt/qp/stage.sh');
  const stagePid = stage ? stage.pid : null;
  const childOfStage = (pid) => stagePid !== null && tr.parent.get(pid) === stagePid;
  const npm = firstExec((e) => childOfStage(e.pid) && (/\/npm$/.test(e.path) || e.argv[0] === 'npm'));
  const harness = firstExec((e) => childOfStage(e.pid) && e.argv.includes('/opt/qp/harness.cjs'));
  const scan = firstExec((e) => childOfStage(e.pid) && e.argv.includes('/opt/qp/scan.cjs'));
  return { stagePid, npmPid: npm ? npm.pid : null, harnessPid: harness ? harness.pid : null, scanPid: scan ? scan.pid : null };
}

function makeActorOf(tr, roles) {
  const isDescendant = (pid, anc) => {
    let cur = pid;
    for (let i = 0; i < 4096 && cur !== undefined && cur !== null; i++) {
      const p = tr.parent.get(cur);
      if (p === anc) return true;
      cur = p;
    }
    return false;
  };
  return (pid) => {
    if (pid === roles.npmPid) return 'npm';
    if (roles.npmPid !== null && isDescendant(pid, roles.npmPid)) return 'package';
    if (roles.harnessPid !== null && isDescendant(pid, roles.harnessPid)) return 'package';
    if (pid === roles.harnessPid) return 'harness-process';
    if (pid === roles.scanPid || pid === roles.stagePid || pid === 1) return 'harness';
    if (tr.parent.get(pid) === 1 && roles.stagePid !== pid) return 'harness'; // run.sh helpers (cp, sed) before the stage
    return 'unattributed';
  };
}

// Inside the harness process, every rule-relevant syscall is package code:
// the harness itself only resolves and require()s the package (no writes,
// no network, no credential access). Env reads there use the preload's stack.
const forRules = (actor) => (actor === 'harness-process' ? 'package' : actor);
const COUNTED = new Set(['package', 'unattributed']);

function build({ traceText, sinkholeText, stdoutText, nonce, limits = [], sandboxEndedNormally, initialCwd, sinkholeIp, traceComplete = true }) {
  const tr = analyse(traceText || '', { initialCwd });
  const roles = processRoles(tr);
  const actorOf = makeActorOf(tr, roles);
  const sink = parseJsonLines(sinkholeText);
  const sinkReady = sink.some((r) => r.type === 'ready');
  const sinkRecords = sink.filter((r) => (r.type === 'dns' || r.type === 'tcp' || r.type === 'udp'));
  // The sandbox shares the sinkhole's network namespace: its redirected traffic
  // arrives from loopback or from the namespace's own address. Anything else
  // (e.g. the probe's in-subnet control) is kept apart.
  const ownIps = new Set(['127.0.0.1', ...(sinkholeIp ? [sinkholeIp] : [])]);
  const sandboxSink = sinkRecords.filter((r) => !r.srcIp || ownIps.has(r.srcIp));
  const controlSink = sinkRecords.filter((r) => r.srcIp && !ownIps.has(r.srcIp));
  const { recs: pre, foreign } = parsePreload(stdoutText, nonce);

  const obs = [];
  const add = (o) => {
    obs.push({
      id: `o${obs.length + 1}`, kind: o.kind, actor: o.actor ?? null, pid: o.pid ?? null, exe: o.exe ?? null,
      dest: o.dest ?? null, orig_dest: o.orig_dest ?? null, port: o.port ?? null, sni: o.sni ?? null,
      proto: o.proto ?? null, blocked: o.blocked ?? null, payload: o.payload ?? null, path: o.path ?? null,
      nonce, ...o.extra,
    });
  };
  const exeOf = (pid) => tr.exe.get(pid) || null;

  // ---- file writes
  const seenWrites = new Set();
  let allowedAreaWrites = 0;
  let allowedAreaWritesOmitted = 0;
  for (const e of tr.events.filter((x) => x.type === 'fs-write')) {
    const actor = forRules(actorOf(e.pid));
    if (!COUNTED.has(actor)) continue;
    if (e.path && DEVICE_SINKS.some((d) => under(e.path, d))) continue;
    const key = `${e.pid}|${e.path || e.rawPath}|${e.blocked}`;
    if (seenWrites.has(key)) continue;
    seenWrites.add(key);
    const allowedArea = under(e.path, '/work') || under(e.path, '/tmp');
    if (allowedArea) {
      allowedAreaWrites += 1;
      if (allowedAreaWrites > MAX_ALLOWED_AREA_WRITES) { allowedAreaWritesOmitted += 1; continue; }
    }
    add({ kind: 'fs-write', actor, pid: e.pid, exe: exeOf(e.pid), path: e.path || `unresolved:${e.rawPath}`, blocked: e.blocked, extra: { syscall: e.syscall, errno: e.errno } });
  }

  // ---- credential / docker.sock access and /proc/<pid>/environ
  const sensitive = (p) => DOCKER_SOCKETS.includes(p) || CREDENTIAL_PATHS.some((c) => under(p, c));
  const seenAccess = new Set();
  const unresolvedAccess = [];
  for (const e of tr.events.filter((x) => x.type === 'fs-read' || x.type === 'fs-stat' || x.type === 'fs-write' || x.type === 'net-unix' || x.type === 'fs-link-target')) {
    const actor = forRules(actorOf(e.pid));
    if (!COUNTED.has(actor)) continue;
    // A path the tracer could not resolve (truncated, unknown dirfd/cwd) cannot be
    // cleared: it makes the observation incomplete (DEC-11 -> review), fail-closed.
    if (e.unresolved && e.type !== 'fs-write') {
      if (unresolvedAccess.length < 20) unresolvedAccess.push({ pid: e.pid, syscall: e.syscall, rawPath: e.rawPath === null ? '(truncated)' : String(e.rawPath).slice(0, 200) });
      continue;
    }
    if (e.path && /^\/proc\/(\d+|self|thread-self)\/environ$/.test(e.path)) {
      add({ kind: 'proc-environ', actor, pid: e.pid, exe: exeOf(e.pid), path: e.path, blocked: e.blocked });
      continue;
    }
    if (!sensitive(e.path)) continue;
    const key = `${e.pid}|${e.path}|${e.syscall}`;
    if (seenAccess.has(key)) continue;
    seenAccess.add(key);
    add({ kind: 'fs-access', actor, pid: e.pid, exe: exeOf(e.pid), path: e.path, blocked: e.blocked, extra: { syscall: e.syscall, errno: e.errno } });
  }

  // ---- network: kernel trace attempts joined with sinkhole records
  const netEvents = tr.events.filter((x) => x.type === 'net');
  const dnsAttempts = netEvents.filter((x) => x.port === 53 && x.proto === 'udp');
  const usedDns = new Set();
  const usedTcp = new Set();
  const sinkByTrace = new Map();
  for (const r of sandboxSink) {
    const t = secondsOfDayIso(r.t);
    if (r.type === 'dns') {
      let best = null;
      for (const a of dnsAttempts) {
        if (t !== null && a.t > t + 0.05) continue;
        if (!best || a.t > best.t) best = a;
      }
      if (best) { usedDns.add(best); const l = sinkByTrace.get(best) || []; l.push(r); sinkByTrace.set(best, l); }
      else r.unmatched = true;
    } else if (r.type === 'tcp') {
      const cands = netEvents.filter((a) => a.proto !== 'udp' && a.ip === r.dstIp && a.port === r.dstPort && !usedTcp.has(a) && (t === null || a.t <= t + 0.05));
      cands.sort((x, y) => x.t - y.t);
      if (cands.length) { usedTcp.add(cands[0]); sinkByTrace.set(cands[0], [r]); }
      else r.unmatched = true;
    } else {
      r.unmatched = true;
    }
  }
  const dnsNames = new Map();
  for (const r of sandboxSink) if (r.type === 'dns' && r.answer) dnsNames.set(r.answer, r.name);

  for (const e of netEvents) {
    const actor = forRules(actorOf(e.pid));
    const recs = sinkByTrace.get(e) || [];
    // Only UDP 53 is DNS. TCP to port 53 is an ordinary TCP attempt whose
    // payload is judged from the sinkhole record like any other port.
    const isDns = e.port === 53 && e.proto === 'udp';
    if (isDns) {
      const names = [...new Set(recs.map((r) => r.name).filter(Boolean))];
      add({ kind: 'net-dns', actor, pid: e.pid, exe: exeOf(e.pid), dest: names.join(',') || null, orig_dest: `${e.ip}:${e.port}`, port: 53, proto: e.proto, blocked: e.blocked, payload: false,
        extra: { sinkholeLogged: recs.length > 0, queries: recs.map((r) => ({ name: r.name, qtype: r.qtype })) } });
      continue;
    }
    const r = recs[0];
    const name = (r && r.dstName) || dnsNames.get(e.ip) || null;
    let payload = false;
    if (r) payload = (r.protocol === 'http' && (/^(POST|PUT|PATCH)$/.test(r.method || '') || r.payloadBytes > 0 || r.chunked === true)) || (r.protocol === 'unknown' && r.payloadBytes > 0);
    add({
      kind: e.proto === 'udp' ? 'net-udp' : 'net-tcp', actor, pid: e.pid, exe: exeOf(e.pid),
      dest: name || e.ip, orig_dest: e.ip ? `${e.ip}:${e.port}` : null, port: e.port, sni: r ? r.sni || null : null,
      proto: r ? r.protocol : e.proto, blocked: e.blocked, payload: r ? payload : null,
      extra: { family: e.family, sinkholeLogged: !!r, http: r && r.protocol === 'http' ? { method: r.method, host: r.host, path: r.path, payloadBytes: r.payloadBytes } : undefined },
    });
  }
  for (const r of sandboxSink.filter((x) => x.unmatched)) {
    const kind = r.type === 'dns' ? 'net-dns' : r.type === 'tcp' ? 'net-tcp' : 'net-udp';
    const payload = r.type === 'tcp' ? ((r.protocol === 'http' && (/^(POST|PUT|PATCH)$/.test(r.method || '') || r.payloadBytes > 0 || r.chunked === true)) || (r.protocol === 'unknown' && r.payloadBytes > 0)) : r.type === 'udp' ? r.payloadBytes > 0 : false;
    add({ kind, actor: 'unattributed', dest: r.name || r.dstName || r.dstIp || null, orig_dest: r.dstIp ? `${r.dstIp}:${r.dstPort}` : null, port: r.dstPort || (r.type === 'dns' ? 53 : null), sni: r.sni || null, proto: r.protocol || r.type, blocked: false, payload,
      extra: { sinkholeLogged: true, note: 'seen by the sinkhole with no matching kernel-trace record' } });
  }

  // ---- binds and listens in the shared namespace (r2 point 7): a listen attempt, rule (f)
  for (const e of tr.events.filter((x) => x.type === 'net-bind' || x.type === 'net-listen')) {
    const actor = forRules(actorOf(e.pid));
    if (!COUNTED.has(actor)) continue;
    add({ kind: 'net-listen', actor, pid: e.pid, exe: exeOf(e.pid), dest: e.ip, port: e.port, proto: e.proto, path: e.path || null, blocked: e.blocked, payload: false, extra: { syscall: e.syscall } });
  }

  // ---- env access (preload) and env enumeration via env/printenv
  for (const p of pre.filter((x) => x.type === 'env-read' || x.type === 'env-enumerate')) {
    const procActor = actorOf(p.pid);
    let actor = procActor === 'harness-process' ? (p.actor === 'package' ? 'package' : 'harness') : procActor;
    if (procActor === 'unattributed' && p.pid !== undefined && !tr.parent.has(p.pid)) actor = 'unattributed';
    if (p.type === 'env-read') add({ kind: 'env-read', actor, pid: p.pid, exe: exeOf(p.pid), extra: { name: p.name } });
    else add({ kind: 'env-enumerate', actor, pid: p.pid, exe: exeOf(p.pid), extra: { rule: 'c2 (observation only)' } });
  }

  // ---- spawned processes (package side), env/printenv as enumeration
  let spawns = 0;
  const rolePids = new Set([roles.npmPid, roles.harnessPid, roles.scanPid, roles.stagePid].filter((p) => p !== null));
  for (const e of tr.events.filter((x) => x.type === 'exec')) {
    if (rolePids.has(e.pid)) continue; // the orchestrator's own npm, harness, scan and stage execs
    const actor = forRules(actorOf(e.pid));
    if (!COUNTED.has(actor)) continue;
    if (/\/(env|printenv)$/.test(e.path) && e.argv.length <= 1) {
      add({ kind: 'env-enumerate', actor, pid: e.pid, exe: e.path, extra: { rule: 'c2 (observation only)', via: 'exec' } });
    }
    // DEC-2r2: an exec of printenv or env whose argv names a variable is an env
    // read of that name (c1 when key-like). `env A=b cmd` assignments are not reads.
    if (/\/(printenv|env)$/.test(e.path)) {
      for (const name of e.argv.slice(1).filter((a) => typeof a === 'string' && a && !a.startsWith('-') && !a.includes('=') && /^[A-Za-z_][A-Za-z0-9_-]*$/.test(a))) {
        if (/\/env$/.test(e.path) && !KEY_LIKE.test(name)) continue; // env's other args are a command, not a variable
        add({ kind: 'env-read', actor, pid: e.pid, exe: e.path, extra: { name, via: `exec ${e.path.split('/').pop()}` } });
      }
    }
    spawns += 1;
    if (spawns <= MAX_SPAWNS) add({ kind: 'spawn', actor, pid: e.pid, exe: e.path, extra: { argv: e.argv.slice(0, 6).map((a) => a.slice(0, 120)) } });
  }

  // ---- pids exhaustion
  const forkFails = tr.events.filter((x) => x.type === 'fork-failed' && x.errno === 'EAGAIN');
  if (forkFails.length) {
    const actor = forRules(actorOf(forkFails[0].pid));
    add({ kind: 'pids-exhaustion', actor, pid: forkFails[0].pid, exe: exeOf(forkFails[0].pid), blocked: true, extra: { failedForks: forkFails.length } });
  }

  // ---- limits
  for (const l of limits) add({ kind: 'limit', actor: null, extra: { reason: l.reason, detail: l.detail } });

  // ---- load
  const loads = pre.filter((x) => x.type === 'load' && (roles.harnessPid === null || x.pid === roles.harnessPid || x.pid === undefined));
  const load = loads[0];
  add({ kind: 'load', actor: 'harness', pid: load ? load.pid : roles.harnessPid, extra: { ok: !!(load && load.ok), mode: load ? load.mode : null, error: load ? load.error || null : 'no load record from the harness', resolved: load ? load.resolved : null } });

  // ---- completeness markers (DEC-11)
  // A heartbeat counts only if the kernel trace shows that same process opening
  // the preload: a forged QPEV heartbeat alone cannot complete this marker.
  // A node process counts as instrumented only when the kernel trace shows
  // (1) its exec envp carries NODE_OPTIONS with the preload, (2) the same pid
  // opening the preload, and (3) it is not an npm CLI other than the
  // orchestrator's own npm (npm runs with env unwrapped). The QPEV heartbeat
  // is required too, but alone it can be forged and never suffices.
  const heartbeats = new Set(pre.filter((x) => x.type === 'hb').map((x) => x.pid));
  const preloadOpened = new Set(tr.events.filter((x) => x.type === 'fs-read' && x.path === '/opt/qp/preload.cjs' && !x.blocked).map((x) => x.pid));
  const lastNodeExec = new Map();
  for (const x of tr.events) if (x.type === 'exec' && /\/node$/.test(x.path)) lastNodeExec.set(x.pid, x);
  const nodePids = [...lastNodeExec.keys()];
  const reasons = {};
  for (const [pid, x] of lastNodeExec) {
    const r = [];
    const envOpts = (x.envp || []).filter((v) => typeof v === 'string' && v.startsWith('NODE_OPTIONS='));
    if (x.envp === null) r.push('envp not traced');
    else if (!envOpts.some((v) => /(^|\s|=)--require[= ]\/opt\/qp\/preload\.cjs(\s|$)/.test(v))) r.push('NODE_OPTIONS without the preload');
    if (!preloadOpened.has(pid)) r.push('preload not opened');
    if (!heartbeats.has(pid)) r.push('no heartbeat');
    const roleVar = (x.envp || []).find((v) => typeof v === 'string' && v.startsWith('QP_ROLE='));
    if (roleVar === 'QP_ROLE=npm' && pid !== roles.npmPid) r.push('QP_ROLE=npm on a process that is not the orchestrator\'s npm (env would be unwrapped)');
    if (NPM_CLI_PATHS.includes(x.argv[1]) && pid !== roles.npmPid) r.push('npm CLI started by package code');
    if (r.length) reasons[pid] = r;
  }
  const missingHb = Object.keys(reasons).map(Number);
  const markers = {
    'instrumentation-heartbeat': { ok: nodePids.length > 0 && missingHb.length === 0, detail: { nodeProcesses: nodePids.length, missing: missingHb, reasons } },
    'paths-resolved': { ok: unresolvedAccess.length === 0, detail: { unresolved: unresolvedAccess } },
    'kernel-trace': {
      ok: tr.calls > 0 && roles.stagePid !== null && traceComplete,
      detail: { syscalls: tr.calls, state: tr.calls === 0 || roles.stagePid === null ? 'missing' : traceComplete ? 'complete' : 'incomplete' },
    },
    'sinkhole-log': { ok: sinkReady, detail: {} },
    'ended-normally': { ok: !!sandboxEndedNormally, detail: {} },
    'harness-ran': { ok: !!load, detail: {} },
  };
  for (const [name, m] of Object.entries(markers)) add({ kind: 'completeness', actor: null, extra: { marker: name, ok: m.ok, detail: m.detail } });

  // Load and completeness observations carry `ok` at top level for the rules.
  for (const o of obs) if (o.kind === 'load' || o.kind === 'completeness') o.ok = o.ok === true;

  return {
    observations: obs,
    roles,
    processes: tr.parent.size + 1,
    allowedAreaWrites: { total: allowedAreaWrites, omitted: allowedAreaWritesOmitted },
    spawnsOmitted: Math.max(0, spawns - MAX_SPAWNS),
    preloadForeignRecords: foreign,
    sinkhole: { ready: sinkReady, records: sandboxSink.length, control: controlSink.length },
    sinkholeLog: sandboxSink,
    markers,
  };
}

module.exports = { build, parsePreload, parseJsonLines, secondsOfDayIso };

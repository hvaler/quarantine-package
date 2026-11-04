// Thin wrapper over the docker CLI (argument arrays only, never a shell).
'use strict';

const { spawn } = require('node:child_process');

const MAX_CAPTURE = 8 * 1024 * 1024;

// AF-7: once a task is interrupted, nothing new may be created or started (the
// teardown is already listing and removing), and in-flight docker clients are
// killed so their awaits settle at once. Removal and listing stay allowed.
const gate = { closed: false, inflight: new Set() };
function createsObjects(args) {
  const a = args.map(String);
  if (a[0] === 'create' || a[0] === 'run' || a[0] === 'start') return true;
  if ((a[0] === 'volume' || a[0] === 'network' || a[0] === 'container') && (a[1] === 'create' || a[1] === 'run' || a[1] === 'start')) return true;
  return false;
}
function closeGate() {
  gate.closed = true;
  for (const c of gate.inflight) { try { c.kill(); } catch (_) { /* gone */ } }
}
function track(child) {
  gate.inflight.add(child);
  child.on('close', () => gate.inflight.delete(child));
  child.on('error', () => gate.inflight.delete(child));
}
function refused(args) {
  const e = new Error(`docker ${args[0]} refused: task interrupted`);
  e.interrupted = true;
  return e;
}

function docker(args, { timeoutMs = 120000, allowFail = true, input = null } = {}) {
  if (gate.closed && createsObjects(args)) return Promise.reject(refused(args));
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { windowsHide: true });
    if (createsObjects(args)) track(child);
    let out = '';
    let err = '';
    const timer = setTimeout(() => { child.kill(); }, timeoutMs);
    if (input !== null) { child.stdin.on('error', () => {}); child.stdin.end(input); }
    child.stdout.on('data', (d) => { if (out.length < MAX_CAPTURE) out += d; });
    child.stderr.on('data', (d) => { if (err.length < MAX_CAPTURE) err += d; });
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      const res = { code, stdout: out, stderr: err };
      if (code !== 0 && !allowFail) {
        const e = new Error(`docker ${args[0]} failed (${code}): ${err.trim().slice(0, 300)}`);
        e.result = res;
        reject(e);
      } else resolve(res);
    });
  });
}

// Attached long-running docker process; returns handle with collected streams.
function attach(args, { maxBytes = MAX_CAPTURE } = {}) {
  if (gate.closed && createsObjects(args)) {
    const h = { child: { kill() {} }, stdout: '', stderr: String(refused(args).message), truncated: false, exited: true, code: null, interrupted: true };
    h.done = Promise.resolve(h);
    return h;
  }
  const child = spawn('docker', args, { windowsHide: true });
  track(child);
  const h = { child, stdout: '', stderr: '', truncated: false, exited: false, code: null };
  child.stdout.on('data', (d) => {
    if (h.stdout.length < maxBytes) h.stdout += d; else h.truncated = true;
  });
  child.stderr.on('data', (d) => {
    if (h.stderr.length < maxBytes) h.stderr += d; else h.truncated = true;
  });
  h.done = new Promise((resolve) => {
    child.on('error', () => { h.exited = true; resolve(h); });
    child.on('close', (code) => { h.exited = true; h.code = code; resolve(h); });
  });
  return h;
}

async function inspect(name) {
  const r = await docker(['inspect', name], { timeoutMs: 30000 });
  if (r.code !== 0) return null;
  try { return JSON.parse(r.stdout)[0]; } catch (_) { return null; }
}

module.exports = { docker, attach, inspect, closeGate, createsObjects, _gate: gate };

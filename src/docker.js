// Thin wrapper over the docker CLI (argument arrays only, never a shell).
'use strict';

const { spawn } = require('node:child_process');

const MAX_CAPTURE = 8 * 1024 * 1024;

function docker(args, { timeoutMs = 120000, allowFail = true } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { windowsHide: true });
    let out = '';
    let err = '';
    const timer = setTimeout(() => { child.kill(); }, timeoutMs);
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
  const child = spawn('docker', args, { windowsHide: true });
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

module.exports = { docker, attach, inspect };

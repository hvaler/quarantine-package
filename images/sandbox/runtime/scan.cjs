'use strict';
// In-sandbox secret scan (C7). Pattern scan only: values are never printed,
// measured or stored. It reports env var NAMES that look key-like, mounts
// (mount point and fs type only) and the presence of docker.sock.
const fs = require('node:fs');

const nonce = process.env.QP_TASK_NONCE || 'none';
const KEY_LIKE = /(^|[_-])(API_?KEY|KEY|TOKEN|SECRET|PASS(WORD)?|PASSWD|CREDENTIALS?)([_-]|$)/i;
const IGNORED_IMAGE_VARS = new Set(['GPG_KEY']); // known image metadata, not secrets
const SOCKETS = ['/var/run/docker.sock', '/run/docker.sock'];

const env = process.env;
const flaggedNames = Object.keys(env).filter((k) => KEY_LIKE.test(k) && !IGNORED_IMAGE_VARS.has(k));

let mounts = [];
try {
  mounts = fs.readFileSync('/proc/self/mounts', 'utf8').trim().split('\n').map((l) => {
    const p = l.split(' ');
    return { mountPoint: p[1], fsType: p[2], readOnly: /(^|,)ro(,|$)/.test(p[3]) };
  });
} catch (_) { /* reported as empty */ }

const dockerSock = SOCKETS.filter((s) => { try { fs.lstatSync(s); return true; } catch (_) { return false; } });

// Host-probe runs resolve a unique nonce name from inside the sandbox so the
// probe can prove that no DNS query for it leaves the host (DEC-5r1).
if (process.env.QP_PROBE_NAME) {
  require('node:dns').lookup(process.env.QP_PROBE_NAME, () => {});
  setTimeout(() => {}, 1500);
}

fs.writeSync(1, `QPEV ${nonce} ${JSON.stringify({
  type: 'sandbox-scan',
  envNamesScanned: Object.keys(env).length,
  keyLikeEnvNames: flaggedNames,
  ignoredImageVars: [...IGNORED_IMAGE_VARS],
  mounts,
  dockerSockPresent: dockerSock,
})}\n`);

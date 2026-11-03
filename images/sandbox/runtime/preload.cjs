'use strict';
// Loaded into every node process in the sandbox via NODE_OPTIONS=--require.
// It adds detail the kernel trace cannot see: env-var reads and enumeration,
// with stack attribution inside the harness process. It also emits one
// heartbeat per process (a completeness marker). Records go to stdout as
//   QPEV <task-nonce> <json>
// The kernel trace (strace) is the authoritative record of file, network
// and process activity; this preload is supplementary and, running inside
// the package's own process, can be bypassed by it (a stated limitation).

const fs = require('node:fs');

const writeSync = fs.writeSync;
const nonce = process.env.QP_TASK_NONCE || 'none';
const role = process.env.QP_ROLE || 'package';
delete process.env.QP_ROLE; // descendants never inherit a role: they are package code
const PKG_ROOTS = ['/work/node_modules/'];
const KEY_LIKE = /(^|[_-])(API_?KEY|KEY|TOKEN|SECRET|PASS(WORD)?|PASSWD|CREDENTIALS?)([_-]|$)/i;

let busy = false;
function emit(rec) {
  if (busy) return;
  busy = true;
  try {
    rec.pid = process.pid;
    rec.role = role;
    writeSync(1, `QPEV ${nonce} ${JSON.stringify(rec)}\n`);
  } catch (_) {
    // stdout closed by the package: the missing records are themselves a signal
  } finally {
    busy = false;
  }
}

function stackActor() {
  if (role === 'package') return 'package';
  if (role === 'npm' || role === 'qp-scan') return role;
  const holder = {};
  const saved = Error.stackTraceLimit;
  Error.stackTraceLimit = 64;
  Error.captureStackTrace(holder, stackActor);
  Error.stackTraceLimit = saved;
  const stack = String(holder.stack || '');
  return PKG_ROOTS.some((r) => stack.includes(r)) ? 'package' : 'harness';
}

emit({ type: 'hb', argv: process.argv.slice(0, 2), execPath: process.execPath });

const realEnv = process.env;
const reported = new Set();
const proxy = new Proxy(realEnv, {
  get(target, key, receiver) {
    if (typeof key === 'string' && KEY_LIKE.test(key)) {
      const actor = stackActor();
      const tag = `${actor}:${key}`;
      if (!reported.has(tag)) {
        reported.add(tag);
        emit({ type: 'env-read', name: key, actor });
      }
    }
    return Reflect.get(target, key, receiver);
  },
  ownKeys(target) {
    const actor = stackActor();
    if (actor === 'package' && !reported.has('enum')) {
      reported.add('enum');
      emit({ type: 'env-enumerate', actor });
    }
    return Reflect.ownKeys(target);
  },
});
// The npm CLI does not run correctly with a wrapped process.env, so npm
// processes are not wrapped. For the orchestrator's own npm this loses
// nothing (npm's env reads never count). For an npm started by package code,
// its env reads are not observed: a stated limitation.
// Only the image's real npm CLI, by exact path (a script merely named "npm" is wrapped).
// The orchestrator decides from the kernel trace whether an unwrapped process is its own npm.
const NPM_CLI_PATHS = ['/usr/local/bin/npm', '/usr/local/lib/node_modules/npm/bin/npm-cli.js'];
const isNpmCli = NPM_CLI_PATHS.includes(String(process.argv[1] || ''));
if (isNpmCli) {
  emit({ type: 'preload-note', detail: 'npm CLI process: env not wrapped' });
} else {
  try {
    Object.defineProperty(process, 'env', { value: proxy, writable: true, configurable: true, enumerable: true });
  } catch (_) {
    emit({ type: 'preload-warning', detail: 'process.env could not be wrapped' });
  }
}

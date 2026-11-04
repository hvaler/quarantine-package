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
const HARNESS_FILE = '/opt/qp/harness.cjs';
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

// F-S2-1 (S2-SEC b): one-way latch. The product's harness.cjs enters the package
// phase right before it loads the package; from then on everything in this process
// is package activity (the package, the model-written harness, callbacks with no
// package frame). Non-configurable and non-writable; calling it again, by anyone,
// can only keep it set.
let packagePhase = false;
Object.defineProperty(globalThis, Symbol.for('qp.packagePhase'), {
  value: () => { packagePhase = true; }, writable: false, configurable: false, enumerable: false,
});

function stackActor() {
  if (role === 'package') return 'package';
  if (role === 'npm' || role === 'qp-scan') return role;
  if (packagePhase) return 'package';
  const holder = {};
  const saved = Error.stackTraceLimit;
  Error.stackTraceLimit = 64;
  Error.captureStackTrace(holder, stackActor);
  Error.stackTraceLimit = saved;
  const stack = String(holder.stack || '');
  // Fail closed (F-S2-1): only a read whose stack shows the product's own
  // /opt/qp/harness.cjs, and no package frame, is the harness; an unknown origin
  // is the package.
  if (PKG_ROOTS.some((r) => stack.includes(r))) return 'package';
  return stack.includes(HARNESS_FILE) ? 'harness' : 'package';
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
// Only the process the stage script started with QP_ROLE=npm is left unwrapped
// (never decided by path, name or title). QP_ROLE is deleted above, so npm's
// children never inherit it. A package that sets QP_ROLE itself gains nothing:
// the orchestrator checks every node exec's envp in the kernel trace, and any
// exec carrying QP_ROLE=npm other than its own npm pid fails instrumentation.
if (role === 'npm') {
  emit({ type: 'preload-note', detail: 'npm CLI process: env not wrapped' });
} else {
  try {
    Object.defineProperty(process, 'env', { value: proxy, writable: true, configurable: true, enumerable: true });
  } catch (_) {
    emit({ type: 'preload-warning', detail: 'process.env could not be wrapped' });
  }
}

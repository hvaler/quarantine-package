// Limits, names and labels. Defaults follow DEC-6; every value can be
// overridden by env for tests, and the receipt records the applied values.
'use strict';

const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');

// Images are tagged with the commit they were built from, so seats building
// different commits on one host never run each other's images.
function imageTag() {
  try {
    const sha = require('node:child_process').execFileSync('git', ['-C', REPO_ROOT, 'rev-parse', '--short=8', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (/^[0-9a-f]{8}$/.test(sha)) return `s1-${sha}`;
  } catch (_) { /* not a git checkout */ }
  return 's1-nogit';
}

function num(env, key, def) {
  const v = env[key];
  if (v === undefined || v === '') return def;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`invalid ${key}`);
  return n;
}

function loadConfig(env = process.env) {
  const prefix = env.QP_RUN_PREFIX || 'qp';
  if (!/^[a-z0-9]{1,16}$/.test(prefix)) throw new Error('QP_RUN_PREFIX must match ^[a-z0-9]{1,16}$');
  const tag = env.QP_IMAGE_TAG || imageTag();
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(tag)) throw new Error('invalid QP_IMAGE_TAG');
  return {
    prefix,
    imageTag: tag,
    images: {
      sandbox: env.QP_SANDBOX_IMAGE || `qp-sandbox:${tag}`,
      sinkhole: env.QP_SINKHOLE_IMAGE || `qp-sinkhole:${tag}`,
    },
    limits: {
      downloadSeconds: num(env, 'QP_DOWNLOAD_TIMEOUT_S', 120),
      downloadMaxBytes: num(env, 'QP_DOWNLOAD_MAX_BYTES', 50 * 1024 * 1024),
      downloadMaxPackages: num(env, 'QP_DOWNLOAD_MAX_PACKAGES', 300),
      sandboxSeconds: num(env, 'QP_SANDBOX_TIMEOUT_S', 60),
      pids: 64,
      memoryBytes: 268435456,
      cpus: 0.5,
      tmpfsWorkBytes: 128 * 1024 * 1024,
      tmpfsTmpBytes: 64 * 1024 * 1024,
      tmpfsHomeBytes: 16 * 1024 * 1024,
    },
    sandboxUid: 10001,
    fixturesDir: path.join(REPO_ROOT, 'fixtures'),
    receiptsDir: env.QP_RECEIPTS_DIR ? path.resolve(env.QP_RECEIPTS_DIR) : path.join(process.cwd(), 'receipts'),
  };
}

const objName = (cfg, role, taskId) => `ar-${cfg.prefix}-${role}-${taskId}`;

function labels(cfg, taskId) {
  return [
    '--label', 'qp.managed=true',
    '--label', `qp.run-prefix=${cfg.prefix}`,
    '--label', `qp.task-id=${taskId}`,
    '--label', `qp.owner-pid=${process.pid}`,
  ];
}

module.exports = { loadConfig, objName, labels, REPO_ROOT, imageTag };

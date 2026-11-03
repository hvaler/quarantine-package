// Limits, names and labels. Defaults follow DEC-6; every value can be
// overridden by env for tests, and the receipt records the applied values.
'use strict';

const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..');

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
  return {
    prefix,
    images: {
      sandbox: env.QP_SANDBOX_IMAGE || 'qp-sandbox:s1',
      sinkhole: env.QP_SINKHOLE_IMAGE || 'qp-sinkhole:s1',
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

module.exports = { loadConfig, objName, labels, REPO_ROOT };

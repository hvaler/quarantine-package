#!/usr/bin/env node
// qp — Quarantine Package CLI (S1).
'use strict';

const path = require('node:path');
const { loadConfig, REPO_ROOT } = require('./config');
const lifecycle = require('./lifecycle');

const USAGE = `usage:
  qp analyse <name>[@<version|tag>] [--host-probe]   analyse a registry package
  qp analyse --fixture <name> [--host-probe]         analyse a local fixture from ./fixtures/<name>
  qp cleanup                                         remove every object of this QP_RUN_PREFIX
  qp leftovers                                       list objects of this QP_RUN_PREFIX (exit 1 if any)
  qp scan-secrets [<path>...]                        pattern scan (default: the repo and ./receipts)

env: QP_RUN_PREFIX (default qp), QP_RECEIPTS_DIR (default ./receipts),
     QP_SANDBOX_TIMEOUT_S, QP_DOWNLOAD_TIMEOUT_S, QP_DOWNLOAD_MAX_BYTES, QP_DOWNLOAD_MAX_PACKAGES
exit: 0 completed (any verdict) / clean, 1 leftovers or secret hits, 2 usage or invalid input,
      3 aborted in the download phase, 4 infrastructure failure`;

async function main(argv) {
  const [cmd, ...rest] = argv;
  let cfg;
  try { cfg = loadConfig(); } catch (e) { console.error(e.message); return 2; }
  switch (cmd) {
    case 'analyse': case 'analyze': {
      const hostProbe = rest.includes('--host-probe');
      const args = rest.filter((a) => a !== '--host-probe');
      let target;
      if (args[0] === '--fixture') {
        if (args.length !== 2) { console.error(USAGE); return 2; }
        target = { fixture: args[1] };
      } else {
        if (args.length !== 1) { console.error(USAGE); return 2; }
        target = { spec: args[0] };
      }
      const { analyse } = require('./orchestrator');
      const { receipt, receiptPath, exitCode } = await analyse(cfg, target, { hostProbe });
      const summary = {
        taskId: receipt.taskId, status: receipt.status, verdict: receipt.verdict,
        package: receipt.package, rulesFired: (receipt.rulesFired || []).map((r) => `${r.id}:${r.observationIds.length}`),
        abortReason: receipt.abortReason || null, hostProbePass: receipt.hostProbe ? receipt.hostProbe.pass : undefined,
        receipt: receiptPath,
      };
      console.log(JSON.stringify(summary));
      return exitCode;
    }
    case 'cleanup': {
      const r = await lifecycle.cleanupAll(cfg.prefix);
      console.log(JSON.stringify({ prefix: cfg.prefix, removed: r }));
      return 0;
    }
    case 'leftovers': {
      const objs = await lifecycle.leftovers(cfg.prefix);
      console.log(JSON.stringify({ prefix: cfg.prefix, count: objs.length, objects: objs.map((o) => `${o.type}:${o.name}`), hostTempDirs: [] }));
      return objs.length ? 1 : 0;
    }
    case 'scan-secrets': {
      const { scanPaths } = require('./secrets');
      const paths = rest.length ? rest.map((p) => path.resolve(p)) : [REPO_ROOT, cfg.receiptsDir];
      const r = scanPaths(paths);
      console.log(JSON.stringify({ scannedFiles: r.files, hits: r.hits.map((h) => ({ file: path.relative(process.cwd(), h.source), line: h.line, pattern: h.pattern })) }));
      return r.hits.length ? 1 : 0;
    }
    default:
      console.error(USAGE);
      return 2;
  }
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (err) => {
  console.error(String(err && err.stack || err));
  process.exitCode = 4;
});

#!/usr/bin/env node
// qp — Quarantine Package CLI.
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
  qp smoke-model [--out <file>]                      C11: REAL model calls (Vultr) on 3 public packages + the hostile fixture

env: QP_RUN_PREFIX (default qp), QP_RECEIPTS_DIR (default ./receipts), QP_KEEP_TRACE=1 (raw trace beside the receipt),
     QP_SANDBOX_TIMEOUT_S, QP_DOWNLOAD_TIMEOUT_S, QP_DOWNLOAD_MAX_BYTES, QP_DOWNLOAD_MAX_PACKAGES,
     VULTR_INFERENCE_KEY (model key, read by this process only), QP_MODEL, QP_MODEL_FALLBACK, QP_MODEL_OFF=1,
     QP_MODEL_BASE_URL and QP_MODEL_TIMEOUT_MS (tests only)
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
    case 'smoke-model': {
      // C11, explicitly marked: the only command that is meant to call the real endpoint.
      const outIdx = rest.indexOf('--out');
      const out = path.resolve(outIdx >= 0 && rest[outIdx + 1] ? rest[outIdx + 1] : path.join(cfg.receiptsDir, `c11-smoke-${Date.now()}.json`));
      if (!process.env.VULTR_INFERENCE_KEY) { console.error('VULTR_INFERENCE_KEY is not set in this environment'); return 2; }
      const { analyse } = require('./orchestrator');
      const fs = require('node:fs');
      const targets = [{ spec: 'express@4.21.2' }, { spec: 'lodash@4.17.21' }, { spec: 'chalk@4.1.2' }, { fixture: 'hostile' }];
      const rows = [];
      for (const t of targets) {
        const { receipt, receiptPath } = await analyse(cfg, t, {});
        const m = receipt.model || {};
        const att = m.attempts || [];
        rows.push({
          package: t.spec || `fixture:${t.fixture}`, taskId: receipt.taskId, verdict: receipt.verdict, status: receipt.status,
          modelStatus: m.status || null, modelUsed: m.model || null, missing: m.missing || null,
          attempts: att.map((a) => ({ purpose: a.purpose, model: a.model, status: a.status, latencyMs: a.latencyMs, httpStatus: a.httpStatus, tokens: a.usage })),
          latencyMsTotal: att.reduce((n, a) => n + (a.latencyMs || 0), 0),
          tokensTotal: att.reduce((n, a) => n + ((a.usage && a.usage.total_tokens) || 0), 0),
          harness: receipt.harness && receipt.harness.model ? receipt.harness.model : null,
          harnessRetries: m.harness ? m.harness.retries : null,
          predictionVsObserved: (receipt.predictionVsObserved || []).map((c) => ({ dimension: c.dimension, status: c.status })),
          receipt: receiptPath,
        });
        console.error(`smoke: ${rows.at(-1).package} -> ${rows.at(-1).verdict} model=${rows.at(-1).modelStatus}/${rows.at(-1).modelUsed}`);
      }
      const evidence = { schema: 'qp-c11-smoke/1', at: new Date().toISOString(), endpoint: require('./model').modelConfig().baseUrl, defaultModel: require('./model').modelConfig().model, fallbackModel: require('./model').modelConfig().fallbackModel, rows };
      const { scanText } = require('./secrets');
      const body = JSON.stringify(evidence, null, 2);
      if (scanText(body, 'smoke').length || body.includes(process.env.VULTR_INFERENCE_KEY)) { console.error('smoke evidence failed the secret scan; not written'); return 1; }
      fs.mkdirSync(path.dirname(out), { recursive: true });
      fs.writeFileSync(out, body + '\n');
      console.log(JSON.stringify({ evidence: out, packages: rows.length, harnessOk: rows.filter((r) => r.harness && r.harness.ok).length, modelOk: rows.filter((r) => r.modelStatus === 'ok').length }));
      return 0;
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

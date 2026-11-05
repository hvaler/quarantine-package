#!/usr/bin/env node
// qp — Quarantine Package CLI.
'use strict';

const path = require('node:path');
const { loadConfig, REPO_ROOT } = require('./config');
const lifecycle = require('./lifecycle');
const formats = require('./formats');

const { FORMATS, EXIT, exitFor } = formats;

const USAGE = `usage:
  qp analyse <name>[@<version|tag>] [--host-probe] [--format json|md|sarif]   analyse a registry package
  qp analyse --fixture <name> [--host-probe] [--format json|md|sarif]         analyse a local fixture from ./fixtures/<name>
      --format writes the receipt (json), a PR-comment Markdown (md) or SARIF 2.1.0 (sarif) to stdout;
      without it, stdout is one JSON summary line. The receipt file is written either way.
  qp export <receipt.json> --format json|md|sarif    convert a stored receipt (no re-run); exits like analyse
  qp cleanup                                         remove every object of this QP_RUN_PREFIX
  qp leftovers                                       list objects of this QP_RUN_PREFIX (exit 1 if any)
  qp scan-secrets [<path>...]                        pattern scan (default: the repo and ./receipts)
  qp smoke-model [--out <file>]                      C11: REAL model calls (Vultr) on 3 public packages + the hostile fixture

env: QP_RUN_PREFIX (default qp), QP_RECEIPTS_DIR (default ./receipts), QP_KEEP_TRACE=1 (raw trace beside the receipt),
     QP_SANDBOX_TIMEOUT_S, QP_DOWNLOAD_TIMEOUT_S, QP_DOWNLOAD_MAX_BYTES, QP_DOWNLOAD_MAX_PACKAGES,
     VULTR_INFERENCE_KEY (model key, read by this process only), QP_MODEL, QP_MODEL_FALLBACK, QP_MODEL_OFF=1,
     QP_MODEL_BASE_URL and QP_MODEL_TIMEOUT_MS (tests only)
     QP_PUBLIC_URL (origin for absolute links in md/sarif), QP_OUTCOME_TIMEOUT_MS (outcome explanation, default 20000)
exit (analyse): 0 install, 10 review, 20 do-not-install, 2 usage or invalid input, 3 aborted in the download phase,
      4 infrastructure failure or tracer unavailable, 130 interrupted
exit (other commands): 0 clean, 1 leftovers or secret hits, 2 usage`;

async function main(argv) {
  const [cmd, ...rest] = argv;
  let cfg;
  try { cfg = loadConfig(); } catch (e) { console.error(e.message); return 2; }
  switch (cmd) {
    case 'analyse': case 'analyze': {
      const hostProbe = rest.includes('--host-probe');
      let args = rest.filter((a) => a !== '--host-probe');
      // S7 F1c: --format json|md|sarif writes that format of the receipt to stdout.
      let format = null;
      const fi = args.indexOf('--format');
      if (fi >= 0) {
        format = args[fi + 1];
        if (!FORMATS.includes(format)) { console.error(USAGE); return EXIT.usage; }
        args = args.filter((_, i) => i !== fi && i !== fi + 1);
      }
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
      if (format) {
        // F1d + C7: every format comes from the STORED receipt (secret-scanned and, if
        // needed, redacted when it was written), never from the in-memory object.
        let stored;
        try { stored = JSON.parse(require('node:fs').readFileSync(receiptPath, 'utf8')); } catch (_) { stored = null; }
        if (!stored) { console.error('the stored receipt could not be read back'); return EXIT.infrastructure; }
        const base = { baseUrl: process.env.QP_PUBLIC_URL || '' };
        if (format === 'json') process.stdout.write(`${JSON.stringify(stored, null, 2)}\n`);
        else if (format === 'md') process.stdout.write(formats.toMarkdown(stored, base));
        else process.stdout.write(`${JSON.stringify(formats.toSarif(stored, base), null, 2)}\n`);
        return exitFor(stored, exitCode);
      }
      console.log(JSON.stringify(summary));
      return exitFor(receipt, exitCode);
    }
    case 'export': {
      // S7 F1d: a stored receipt in any format, with no re-run; exits like analyse.
      const fi = rest.indexOf('--format');
      const format = fi >= 0 ? rest[fi + 1] : null;
      const files = rest.filter((_, i) => fi < 0 || (i !== fi && i !== fi + 1));
      if (!FORMATS.includes(format) || files.length !== 1) { console.error(USAGE); return EXIT.usage; }
      let receipt;
      try { receipt = JSON.parse(require('node:fs').readFileSync(path.resolve(files[0]), 'utf8')); } catch (e) { console.error(`cannot read the receipt: ${String(e && e.code || e.message).slice(0, 80)}`); return EXIT.usage; }
      if (!receipt || typeof receipt !== 'object' || !String(receipt.schema || '').startsWith('qp-receipt/')) { console.error('not a qp receipt'); return EXIT.usage; }
      const base = { baseUrl: process.env.QP_PUBLIC_URL || '' };
      if (format === 'json') process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
      else if (format === 'md') process.stdout.write(formats.toMarkdown(receipt, base));
      else process.stdout.write(`${JSON.stringify(formats.toSarif(receipt, base), null, 2)}\n`);
      return exitFor(receipt, receipt.status === 'completed' ? 0 : EXIT.infrastructure);
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

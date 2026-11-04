// Secret scan by pattern (C7). Reports only file, line and pattern name:
// never the matched value or any property of it.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const PATTERNS = Object.freeze([
  ['aws-access-key-id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
  ['github-token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['npm-token', /\bnpm_[A-Za-z0-9]{36}\b/],
  ['slack-token', /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/],
  ['sk-style-api-key', /\bsk-[A-Za-z0-9_-]{20,}\b/],
  ['private-key-block', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ['assigned-credential', /\b[A-Za-z0-9_]*(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Za-z0-9_]*["']?\s*[:=]\s*["']?(?![<{$])[A-Za-z0-9+/_.=-]{16,}/i],
]);

// Names that look key-like but are known image metadata, not secrets.
const IGNORED_ASSIGNMENTS = ['GPG_KEY='];

function scanText(text, source = 'text') {
  const hits = [];
  const lines = String(text).split(/\r?\n/);
  lines.forEach((line, i) => {
    if (IGNORED_ASSIGNMENTS.some((p) => line.includes(p))) return;
    for (const [name, re] of PATTERNS) if (re.test(line)) hits.push({ source, line: i + 1, pattern: name });
  });
  return hits;
}

const SKIP_DIRS = new Set(['.git', 'node_modules']);

function walk(root) {
  const out = [];
  const st = fs.statSync(root);
  if (st.isFile()) return [root];
  const stack = [root];
  while (stack.length) {
    const d = stack.pop();
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (SKIP_DIRS.has(e.name)) continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.isFile()) out.push(p);
    }
  }
  return out;
}

function scanPaths(paths) {
  const hits = [];
  let files = 0;
  for (const root of paths) {
    if (!fs.existsSync(root)) continue;
    for (const f of walk(root)) {
      let buf;
      try { buf = fs.readFileSync(f); } catch (_) { continue; }
      // Kept traces (QP_KEEP_TRACE) can be up to 8 MB of text: always scanned.
      const limit = f.endsWith('.trace') ? 16 * 1024 * 1024 : 5 * 1024 * 1024;
      if (buf.length > limit || buf.includes(0)) continue; // binary or huge
      files += 1;
      hits.push(...scanText(buf.toString('utf8'), f));
    }
  }
  return { files, hits };
}

// Replace lines that match a pattern before they are shown or stored.
function redact(text) {
  let n = 0;
  const out = String(text).split(/\r?\n/).map((line) => {
    if (IGNORED_ASSIGNMENTS.some((p) => line.includes(p))) return line;
    if (PATTERNS.some(([, re]) => re.test(line))) { n += 1; return '[line redacted by secret scan]'; }
    return line;
  }).join('\n');
  return { text: out, redactedLines: n };
}

module.exports = { scanText, scanPaths, redact, PATTERNS };

'use strict';
// Dispatch 3: QP_KEEP_TRACE=1 keeps the raw tracer output beside the receipt,
// never inside it, off by default, pattern-scanned, and covered by scan-secrets.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadConfig } = require('../src/config');
const { keepTrace } = require('../src/orchestrator');
const { scanPaths } = require('../src/secrets');

const fakeToken = () => ['np', 'm_'].join('') + 'A'.repeat(36); // built at runtime: no literal in the repo

test('QP_KEEP_TRACE is off by default and on only for "1"', () => {
  assert.equal(loadConfig({ QP_IMAGE_TAG: 't' }).keepTrace, false);
  assert.equal(loadConfig({ QP_IMAGE_TAG: 't', QP_KEEP_TRACE: 'yes' }).keepTrace, false);
  assert.equal(loadConfig({ QP_IMAGE_TAG: 't', QP_KEEP_TRACE: '1' }).keepTrace, true);
});

test('keepTrace writes <taskId>.trace beside the receipt and returns only metadata', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-trace-'));
  try {
    const text = '40 21:00:00.000300 execve("/usr/local/bin/node", ["node"], 0x0) = 0\n';
    const meta = keepTrace({ receiptsDir: dir }, 'abcdef0123', text, false);
    assert.equal(meta.file, 'abcdef0123.trace');
    assert.equal(fs.readFileSync(path.join(dir, meta.file), 'utf8'), text);
    assert.deepEqual(Object.keys(meta).sort(), ['bytes', 'file', 'secretScan', 'truncated']);
    assert.equal(meta.secretScan.pass, true);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('keepTrace redacts a secret-shaped line before writing, and scan-secrets covers .trace files over 5 MB', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-trace-'));
  try {
    const text = `40 21:00:00.1 write(1, "x", 1) = 1\n40 21:00:00.2 write(1, "${fakeToken()}", 40) = 40\n`;
    const meta = keepTrace({ receiptsDir: dir }, 'abcdef0124', text, false);
    const written = fs.readFileSync(path.join(dir, meta.file), 'utf8');
    assert.equal(written.includes(fakeToken()), false);
    assert.equal(meta.secretScan.pass, false);
    assert.equal(meta.secretScan.redactedLines, 1);
    // A large kept trace with a hit is still scanned (limit raised for .trace).
    const big = path.join(dir, 'ffffffffff.trace');
    fs.writeFileSync(big, 'a'.repeat(6 * 1024 * 1024) + `\n${fakeToken()}\n`);
    const r = scanPaths([dir]);
    assert.ok(r.hits.some((h) => h.source === big), 'large .trace scanned');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

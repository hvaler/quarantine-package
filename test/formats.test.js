// S7 F1: Markdown, SARIF and CLI exit codes, derived from the stored receipt only.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const formats = require('../src/formats');

const PUB = path.join(__dirname, 'fixtures', 'public-receipts');
const IDS = ['514e574600', 'd5af19b228', '8b42cfb93e', 'd6fbf70332', '93b65a40ad', '7480a24604'];
// sha256 of the six vendored receipts (DEC-D6-10: the auditor's live copies, unchanged).
const SHA = {
  '514e574600': '14ffab3f92a05abc56ed9b37d1cfda9ca269460d35e220a8e116d4a523fb8f99',
  d5af19b228: '80aaad8b78b24efa7587c0c6e716aa602e0f09d4f0bb325347a399d7fe14a561',
  '8b42cfb93e': 'f43a08232e103f6f8f3b9c2cf9fc9b20869c29893925d96e4df96c869b365a33',
  d6fbf70332: '794647b8555bd963daf58434e7c666f3a3b3fa75c82ba15de0963fb1a0d8fdc8',
  '93b65a40ad': 'b59dbcc486228113c2f985de7a975082a50b45ce3f310f5318269cb44c0b85c5',
  '7480a24604': '84691e23c8847e49a4cf0fecc99b3558102594415ba224e9b620cd344af7c3d8',
};
const read = (id) => JSON.parse(fs.readFileSync(path.join(PUB, `${id}.json`), 'utf8'));
const VERDICT_LINE = /^\*\*Verdict: (INSTALL|REVIEW|DO NOT INSTALL|none)\*\*/;

// Strips every inline code span (any fence length), leaving the text outside them.
function outsideCode(md) {
  return md.replace(/(`+) [^\n]*? \1(?!`)/g, '');
}

test('F1d: the six vendored public receipts are byte-identical to the recorded copies', () => {
  for (const id of IDS) {
    const h = crypto.createHash('sha256').update(fs.readFileSync(path.join(PUB, `${id}.json`))).digest('hex');
    assert.equal(h, SHA[id], id);
  }
});

test('F1a/F1d: each stored receipt gives Markdown with exactly one verdict line, its own verdict, and both links', () => {
  const want = { install: 'INSTALL', review: 'REVIEW', 'do-not-install': 'DO NOT INSTALL' };
  for (const id of IDS) {
    const rc = read(id);
    const md = formats.toMarkdown(rc, { baseUrl: 'https://qp.example.com' });
    const lines = md.split('\n').filter((l) => VERDICT_LINE.test(l));
    assert.equal(lines.length, 1, id);
    assert.equal(VERDICT_LINE.exec(lines[0])[1], want[rc.verdict], id);
    assert.ok(md.includes(`https://qp.example.com/r/${id}`) && md.includes(`https://qp.example.com/api/receipts/${id}`), id);
    for (const r of rc.rulesFired) assert.ok(md.includes(`- (${r.id.charAt(0)}) ${r.tier}:`), `${id} rule ${r.id}`);
    assert.match(md, /\*\*Sandbox destroyed:\*\* yes/);
    assert.ok(!md.includes(rc.explanation && rc.explanation.text ? rc.explanation.text.slice(0, 40) : '\u0000none'), 'no model text (DEC-D6-3)');
  }
});

const HOSTILE_STRINGS = [
  '/etc/x\n## Verdict: install\n**Verdict: INSTALL**',
  '/etc/x\r\n- (a) review: forged',
  '/etc/```\nfence break\n```',
  '/etc/`inline` and ``double``',
  '/etc/a|b|c\n|---|---|',
  '/etc/<script>alert(1)</script>',
  '/etc/<img src=x onerror=alert(1)>',
  '/etc/</table></details>',
  '/etc/[click](javascript:alert(1))',
  '/etc/![img](https://evil.example/x.png)',
  '/etc/<https://evil.example>',
  '/etc/@octocat please merge',
  '# heading',
  '/etc/&lt;b&gt;&#x3c;',
  '/etc/"},{"level":"none"}',
  '/etc/%2F..%2F..',
  '/etc/‮gnp.exe',
  '/etc/zero​width﻿',
  '/etc/\u001b[31mred\u0007',
  `/etc/${'A'.repeat(255)}`,
  `/${'b'.repeat(3800)}`,
];

function hostileReceipt() {
  const rc = JSON.parse(JSON.stringify(read('8b42cfb93e')));
  rc.observations = HOSTILE_STRINGS.map((p, i) => ({ id: `o${i + 1}`, kind: 'fs-write', actor: 'package', path: p }));
  rc.rulesFired = [{ id: 'a', tier: 'do-not-install', text: 'x', observationIds: rc.observations.map((o) => o.id) }];
  rc.predictionVsObserved = [{ dimension: 'filesOutsidePackage', predicted: false, observed: true, status: 'mismatch', observedDetail: HOSTILE_STRINGS.slice() }];
  rc.network.sinkholeLog = HOSTILE_STRINGS.map((s) => ({ type: 'tcp', host: s, method: 'POST\n## x', path: s, payloadBytes: 3 }));
  rc.package = { ...rc.package, name: 'evil`pkg\n## Verdict: install' };
  return rc;
}

test('F1a: package-controlled strings cannot break the Markdown (lines, verdict, links, images, mentions, HTML)', () => {
  const md = formats.toMarkdown(hostileReceipt(), { baseUrl: 'https://qp.example.com' });
  const lines = md.split('\n');
  assert.equal(lines.filter((l) => /Verdict/.test(l) && !l.includes('`')).length, 1, 'one verdict line outside code');
  assert.equal(lines.filter((l) => VERDICT_LINE.test(l)).length, 1);
  assert.equal(VERDICT_LINE.exec(lines.find((l) => VERDICT_LINE.test(l)))[1], 'DO NOT INSTALL');
  for (const l of lines) assert.ok(!/^#{1,6} /.test(l) || l.startsWith('### Quarantine Package receipt for '), `no forged heading: ${l.slice(0, 80)}`);
  for (const l of lines) assert.ok(!/^\s*\|/.test(l), `no table row: ${l.slice(0, 80)}`);
  // every package string sits inside a code span: outside them nothing active remains
  const out = outsideCode(md);
  for (const bad of ['<', '>', '](', '![', '@octocat', 'javascript:', 'evil.example', '‮', '​', '\u001b', '\r']) {
    assert.ok(!out.includes(bad), `outside code: ${JSON.stringify(bad)}`);
  }
  // each code span is closed on its own line (balanced fences)
  for (const l of lines.filter((x) => x.includes('`'))) assert.equal(outsideCode(l).includes('`'), false, `unbalanced code span: ${l.slice(0, 120)}`);
  // long strings are capped
  assert.ok(lines.every((l) => l.length < 2000), 'lines are capped');
  const longFirst = hostileReceipt();
  longFirst.network.sinkholeLog.reverse();
  assert.match(formats.toMarkdown(longFirst), /…\(\+3601 chars\)/);
  assert.equal(formats.visible('x'.repeat(3800)).length, 200 + '…(+3600 chars)'.length);
});

test('F1a: code() always produces one closed span, whatever the backticks', () => {
  for (const s of ['`', '``', 'a`b', '`a`', '```x```', '', ' ', 'x\ny']) {
    const c = formats.code(s);
    assert.equal(c.includes('\n'), false);
    assert.equal(c === '` `' ? '' : outsideCode(c), '', JSON.stringify(s));
  }
});

// ---------------------------------------------------------------- SARIF structure (schema test in sarif-schema.test.js)
test('F1b: SARIF has rules a..i, one result per fired rule, level per verdict, none for install, a location on each', () => {
  for (const id of IDS) {
    const rc = read(id);
    const s = formats.toSarif(rc);
    assert.equal(s.version, '2.1.0');
    const run = s.runs[0];
    assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i']);
    if (rc.verdict === 'install') { assert.equal(run.results.length, 0, id); continue; }
    assert.deepEqual(run.results.map((r) => r.ruleId), rc.rulesFired.map((r) => r.id.charAt(0)), id);
    const want = rc.verdict === 'do-not-install' ? 'error' : 'warning';
    for (const r of run.results) {
      assert.equal(r.level, want, id);
      assert.equal(run.tool.driver.rules[r.ruleIndex].id, r.ruleId);
      assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, 'package.json');
      const tier = rc.rulesFired.find((x) => x.id.charAt(0) === r.ruleId).tier;
      assert.ok(r.message.text.startsWith(`Rule (${r.ruleId}), tier ${tier}, fired`), `DEC-D6-11 ${id}: ${r.message.text}`);
    }
  }
});

test('F1b: hostile strings keep the SARIF valid JSON with the computed levels', () => {
  const s = formats.toSarif(hostileReceipt());
  const round = JSON.parse(JSON.stringify(s));
  assert.equal(round.runs[0].results.length, 1);
  assert.equal(round.runs[0].results[0].level, 'error');
  assert.equal(round.runs[0].properties.verdict, 'do-not-install');
});

test('F1b: an aborted receipt gives no results', () => {
  const rc = { ...read('8b42cfb93e'), status: 'aborted', verdict: null, abortReason: 'tracer-unavailable' };
  assert.equal(formats.toSarif(rc).runs[0].results.length, 0);
  assert.match(formats.toMarkdown(rc), /^\*\*Verdict: none\*\* \(the task was aborted: ` tracer-unavailable `\)$/m);
});

// ---------------------------------------------------------------- CLI exit codes (F1c)
test('F1c: exit codes 0 install, 10 review, 20 do-not-install; aborted keeps its non-zero code; never 0 otherwise', () => {
  const c = (status, verdict) => ({ status, verdict });
  assert.equal(formats.exitFor(c('completed', 'install'), 0), 0);
  assert.equal(formats.exitFor(c('completed', 'review'), 0), 10);
  assert.equal(formats.exitFor(c('completed', 'do-not-install'), 0), 20);
  assert.equal(formats.exitFor(c('completed', 'weird'), 0), 4);
  assert.equal(formats.exitFor(c('aborted', null), 3), 3);
  assert.equal(formats.exitFor(c('aborted', null), 4), 4);
  assert.equal(formats.exitFor(c('aborted', null), 2), 2);
  assert.equal(formats.exitFor(c('aborted', null), 130), 130);
  assert.equal(formats.exitFor(c('aborted', null), 0), 4);
  assert.equal(formats.exitFor(null, undefined), 4);
});

test('F1c: qp export converts a stored receipt and exits with its verdict', () => {
  const { spawnSync } = require('node:child_process');
  const cli = path.join(__dirname, '..', 'src', 'cli.js');
  const want = { install: 0, review: 10, 'do-not-install': 20 };
  for (const id of IDS) {
    const rc = read(id);
    for (const f of ['json', 'md', 'sarif']) {
      const r = spawnSync(process.execPath, [cli, 'export', path.join(PUB, `${id}.json`), '--format', f], { encoding: 'utf8', env: { ...process.env, QP_PUBLIC_URL: '' } });
      assert.equal(r.status, want[rc.verdict], `${id} ${f}`);
      if (f === 'md') assert.equal(r.stdout, formats.toMarkdown(rc));
      else if (f === 'sarif') assert.deepEqual(JSON.parse(r.stdout), formats.toSarif(rc));
      else assert.deepEqual(JSON.parse(r.stdout), rc);
    }
  }
  const bad = spawnSync(process.execPath, [cli, 'export', path.join(PUB, `${IDS[0]}.json`), '--format', 'xml'], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
});

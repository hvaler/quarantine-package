'use strict';
// S6: L-18 truncation note, and R1 (stored public receipts still render with the
// candidate's render.js; their ids and the /r/<id>, /api/receipts/<id> formats
// are unchanged). The three receipts are copies of evidence-vm/c15-receipt-*.json,
// served by the live site from a075bd1.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const render = require('../src/web/render');

const DIR = path.join(__dirname, 'fixtures', 'c15-receipts');

test('R1: the stored c15 receipts render with the candidate (verdict, id, rules, observations), no truncation note', () => {
  const files = fs.readdirSync(DIR).filter((f) => f.endsWith('.json'));
  assert.equal(files.length, 3);
  const words = { install: 'Install', review: 'Review', 'do-not-install': 'Do not install' };
  for (const f of files) {
    const r = JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8'));
    assert.equal(f, `c15-receipt-${r.taskId}.json`);
    const html = render.receiptPage({ nonce: 'N', receipt: r });
    assert.ok(html.includes(`<h1 class="v" id="v-h">${words[r.verdict]}</h1>`), f);
    assert.ok(html.includes(`<dd class="mono">${r.taskId}</dd>`), f);
    for (const rule of r.rulesFired) assert.ok(html.includes(`<td class="mono">${rule.id}</td>`), `${f} rule ${rule.id}`);
    for (const o of r.observations.filter((x) => x.kind !== 'completeness')) assert.ok(html.includes(`<td class="mono">${o.id}</td>`), `${f} ${o.id}`);
    assert.equal(html.includes('showing '), false, f);
    assert.equal(/\sstyle=/i.test(html), false, 'no style attribute (CSP)');
  }
});

const many = (n, f) => Array.from({ length: n }, (_, i) => f(i));

test('L-18: more than 300 observations / 200 sinkhole entries shows "showing N of M" with a link to the full JSON', () => {
  const receipt = {
    taskId: 'abcdef0123', verdict: 'review', status: 'completed', rulesFired: [],
    observations: many(305, (i) => ({ id: `o${i + 1}`, kind: 'fs-write', actor: 'package', path: `/work/f${i}` })),
    network: { sinkholeLog: many(201, () => ({ type: 'dns', name: 'example.com' })) },
  };
  const html = render.receiptPage({ nonce: 'N', receipt });
  assert.ok(html.includes('showing 300 of 305; full list in <a href="/api/receipts/abcdef0123">/api/receipts/abcdef0123</a>'));
  assert.ok(html.includes('showing 200 of 201; full list in <a href="/api/receipts/abcdef0123">/api/receipts/abcdef0123</a>'));
  assert.equal(html.includes('<td class="mono">o301</td>'), false, 'rows past 300 are not rendered');
  assert.equal(/\sstyle=/i.test(html), false, 'no style attribute (CSP)');
  // External resources only (the page's own GitHub nav link is navigation, not a resource).
  assert.equal(/\ssrc=["']?(https?:)?\/\/|<link[^>]+href=["']?(https?:)?\/\//i.test(html), false, 'no external resource');
});

test('L-18: exactly at the limits there is no note', () => {
  const receipt = {
    taskId: 'abcdef0123', verdict: 'install', status: 'completed', rulesFired: [],
    observations: many(300, (i) => ({ id: `o${i + 1}`, kind: 'fs-write', actor: 'package', path: '/work/x' })),
    network: { sinkholeLog: many(200, () => ({ type: 'dns', name: 'example.com' })) },
  };
  assert.equal(render.receiptPage({ nonce: 'N', receipt }).includes('showing '), false);
});

test('L-18: a task id outside the receipt-id format gets the note as escaped text, never a link', () => {
  const receipt = {
    taskId: '"><script>alert(1)</script>', verdict: 'review', status: 'completed', rulesFired: [],
    observations: many(301, (i) => ({ id: `o${i + 1}`, kind: 'fs-write', actor: 'package', path: '/work/x' })),
  };
  const html = render.receiptPage({ nonce: 'N', receipt });
  assert.ok(html.includes('showing 300 of 301; full list in /api/receipts/&quot;&gt;&lt;script&gt;'));
  assert.equal(/href="\/api\/receipts/.test(html), false);
  assert.equal(/<script(?! nonce="N")/i.test(html), false);
});

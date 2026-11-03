'use strict';
// DEC-19 input validation, C7 secret scanner, DEC-5r1 probe classification.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { parseRegistrySpec, resolveFixture } = require('../src/spec');
const { scanText, redact } = require('../src/secrets');
const { summarize, inNet } = require('../src/probe');

test('DEC-19 registry specs accepted', () => {
  for (const s of ['express', 'express@4.21.2', 'express@latest', 'lodash@^4.17.0', '@types/node@22.0.0', '@scope/pkg']) {
    assert.equal(parseRegistrySpec(s).ok, true, s);
  }
  assert.deepEqual(parseRegistrySpec('@types/node@22.0.0'), { ok: true, name: '@types/node', version: '22.0.0', spec: '@types/node@22.0.0' });
});

test('DEC-19 non-registry specs, paths, flags and metacharacters rejected', () => {
  for (const s of ['file:../x', 'git+https://x/y.git', 'https://x/y.tgz', './fixtures/hostile', '/etc', 'C:\\x', '-rf', '--global',
    'a;b', 'a|b', 'a&&b', 'a$(x)', 'a`x`', 'a b', 'express@>=1 <2', 'npm:express@1', '', '..', 'x/../../y']) {
    assert.equal(parseRegistrySpec(s).ok, false, s);
  }
});

test('DEC-19 fixtures only from the repo fixtures dir', () => {
  const dir = path.join(__dirname, '..', 'fixtures');
  assert.equal(resolveFixture(dir, 'hostile').ok, true);
  for (const f of ['../src', '..', 'HOSTILE', 'hostile/../loop', '', 'does-not-exist']) assert.equal(resolveFixture(dir, f).ok, false, f);
});

test('C7 scanner finds patterns and never returns the value', () => {
  const fake = ['AKIA' + 'Q'.repeat(16), 'ghp_' + 'a'.repeat(36), 'sk-' + 'b'.repeat(30), `API_KEY=${'c'.repeat(24)}`, '-----BEGIN ' + 'PRIVATE KEY-----'];
  const hits = scanText(fake.join('\n'), 'x');
  assert.equal(hits.length, 5);
  for (const h of hits) assert.deepEqual(Object.keys(h).sort(), ['line', 'pattern', 'source']);
  assert.equal(JSON.stringify(hits).includes('QQQQ'), false);
  assert.deepEqual(scanText(`GPG_KEY=${'7'.repeat(40)}\nPATH=/usr/bin\nconst KEY_LIKE = /x/;`, 'x'), []);
  const r = redact(`ok\n${fake[1]}\nok`);
  assert.equal(r.redactedLines, 1);
  assert.equal(r.text.includes('ghp_'), false);
});

test('DEC-5r1 probe classification: leaving, in-subnet, control and DNS nonce', () => {
  const p = { subnet: '172.19.0.0/16', ctlSubnet: '172.20.0.0/16', sinkholeIp: '172.19.0.2', nonceName: 'qp-abc.probe.invalid' };
  const lines = [
    'br-1 In  IP 172.19.0.3.40000 > 172.19.0.2.15001: Flags [S]',
    'br-2 In  IP 172.20.0.2.40001 > 1.1.1.1.80: Flags [S]',
    'eth0 Out IP 192.168.65.3.40001 > 1.1.1.1.80: Flags [S]',
  ];
  const ok = summarize(p, lines.join('\n'));
  assert.equal(ok.counts.sandboxLeaving, 0);
  assert.equal(ok.counts.inSubnet, 1);
  assert.equal(ok.counts.controlLeaving, 1);
  assert.equal(ok.pass, true);
  const bad = summarize(p, [...lines, 'br-1 In  IP 172.19.0.2.5000 > 8.8.8.8.53: 1+ A? qp-abc.probe.invalid. (40)'].join('\n'));
  assert.equal(bad.counts.sandboxLeaving, 1);
  assert.equal(bad.counts.dnsNonceLeaving, 1);
  assert.equal(bad.pass, false);
  const noControl = summarize(p, lines[0]);
  assert.equal(noControl.pass, false);
  assert.equal(inNet('10.0.0.1', '10.0.0.0/8'), true);
  assert.equal(inNet('11.0.0.1', '10.0.0.0/8'), false);
});

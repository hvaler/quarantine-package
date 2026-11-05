// S7 F1b: the SARIF output validates against the vendored OASIS SARIF 2.1.0 schema
// (errata01, sha256 below). No network at test time.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const formats = require('../src/formats');
const { validate } = require('./vendor/jsonschema-draft04');

const SCHEMA_FILE = path.join(__dirname, 'vendor', 'sarif-schema-2.1.0.json');
const SCHEMA_SHA256 = 'c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e';
const schema = JSON.parse(fs.readFileSync(SCHEMA_FILE, 'utf8'));
const PUB = path.join(__dirname, 'fixtures', 'public-receipts');
const IDS = ['514e574600', 'd5af19b228', '8b42cfb93e', 'd6fbf70332', '93b65a40ad', '7480a24604'];
const read = (id) => JSON.parse(fs.readFileSync(path.join(PUB, `${id}.json`), 'utf8'));

test('F1b: the vendored schema is the OASIS SARIF 2.1.0 errata01 file', () => {
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(SCHEMA_FILE)).digest('hex'), SCHEMA_SHA256);
  assert.equal(schema.id, 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json');
  assert.equal(formats.SARIF_SCHEMA, schema.id);
});

test('F1b: the validator rejects broken SARIF (it is not vacuous)', () => {
  const good = formats.toSarif(read('8b42cfb93e'));
  assert.equal(validate(schema, good).valid, true);
  const bad = (f) => { const s = JSON.parse(JSON.stringify(good)); f(s); return validate(schema, s).valid; };
  assert.equal(bad((s) => { s.version = '2.0.0'; }), false, 'version enum');
  assert.equal(bad((s) => { delete s.runs; }), false, 'runs required');
  assert.equal(bad((s) => { s.runs[0].results[0].level = 'fatal'; }), false, 'level enum');
  assert.equal(bad((s) => { s.runs[0].results[0].message = {}; }), false, 'message needs text or id');
  assert.equal(bad((s) => { s.runs[0].tool.driver.rules.push(s.runs[0].tool.driver.rules[0]); }), false, 'unique rules');
  assert.equal(bad((s) => { s.runs[0].tool.driver.informationUri = 'not a uri'; }), false, 'uri format');
  assert.equal(bad((s) => { s.runs[0].results[0].ruleIndex = -2; }), false, 'minimum');
  assert.equal(bad((s) => { s.runs[0].tool.driver.extra = 1; }), false, 'additionalProperties false');
});

test('F1b: SARIF of the six stored receipts, an aborted one and a hostile one validates against the schema', () => {
  const docs = IDS.map((id) => [id, formats.toSarif(read(id), { baseUrl: 'https://qp.example.com' })]);
  docs.push(['aborted', formats.toSarif({ ...read('8b42cfb93e'), status: 'aborted', verdict: null, abortReason: 'tracer-unavailable' })]);
  const h = JSON.parse(JSON.stringify(read('8b42cfb93e')));
  h.package.name = 'evil"}]},{"x":"\u0000‮`|<script>';
  h.taskId = '../../x';
  docs.push(['hostile', formats.toSarif(h)]);
  for (const [id, doc] of docs) {
    const r = validate(schema, JSON.parse(JSON.stringify(doc)));
    assert.equal(r.valid, true, `${id}: ${r.errors.slice(0, 5).join('; ')}`);
  }
});

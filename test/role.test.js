'use strict';
// H-1: QP_ROLE is honoured only for the real product entry point started by stage.sh.
const test = require('node:test');
const assert = require('node:assert/strict');
const { verifyRole } = require('../images/sandbox/runtime/role.cjs');

const STAGE = '/bin/sh\0/opt/qp/stage.sh\0pkg\0';
test('H-1: genuine roles started by the stage script are honoured', () => {
  assert.equal(verifyRole('harness', { argv: ['/usr/local/bin/node', '/opt/qp/harness.cjs', 'pkg'], parentCmd: STAGE }), 'harness');
  assert.equal(verifyRole('qp-scan', { argv: ['/usr/local/bin/node', '/opt/qp/scan.cjs'], parentCmd: STAGE }), 'qp-scan');
  assert.equal(verifyRole('npm', { argv: ['/usr/local/bin/node', '/usr/local/bin/npm', 'rebuild'], parentCmd: STAGE }), 'npm');
  assert.equal(verifyRole('npm', { argv: ['/usr/local/bin/node', '/usr/local/lib/node_modules/npm/bin/npm-cli.js', 'rebuild'], parentCmd: 'sh\0/opt/qp/stage.sh\0x\0' }), 'npm');
});

test('H-1: a self-asserted role is the package (wrong parent, wrong entry point, unknown role, unreadable parent)', () => {
  const cases = [
    ['qp-scan', ['/usr/local/bin/node', '/work/a.js'], STAGE],
    ['harness', ['/usr/local/bin/node', '/opt/qp/harness.cjs'], '/usr/local/bin/node\0/work/x.js\0'],
    ['npm', ['/usr/local/bin/node', '/usr/local/bin/npm'], '/bin/sh\0-c\0npm rebuild\0'],
    ['harness', ['/usr/local/bin/node', '/opt/qp/harness.cjs'], null],
    ['admin', ['/usr/local/bin/node', '/opt/qp/harness.cjs'], STAGE],
    ['harness', ['/usr/local/bin/node', '/tmp/opt/qp/harness.cjs'], STAGE],
  ];
  for (const [claimed, argv, parentCmd] of cases) assert.equal(verifyRole(claimed, { argv, parentCmd }), 'package', `${claimed} ${argv[1]} ${parentCmd}`);
});

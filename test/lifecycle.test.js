'use strict';
// S1-D2: the reaper and teardown never touch another live task (pure selection).
const test = require('node:test');
const assert = require('node:assert/strict');
const { selectOrphans, ownName } = require('../src/lifecycle');

const NOW = 1_800_000_000_000;
const obj = (name, owner, created, labelled = true) => ({ type: 'container', name, task: name.slice(-10), owner, created, labelled });

test('S1-D2 reaper keeps a live task of another CLI under the same prefix', () => {
  const alivePids = new Set([111, 222]);
  const objs = [
    obj('ar-impl-sandbox-aaaaaaaaaa', 111, NOW - 5000),   // live task A
    obj('ar-impl-sandbox-bbbbbbbbbb', 222, NOW - 5000),   // live task B
    obj('ar-impl-sandbox-cccccccccc', 333, NOW - 5000),   // owner gone -> orphan
    obj('ar-impl-sandbox-dddddddddd', 111, NOW - 4_000_000), // pid alive but object stale (pid reuse) -> orphan
    obj('ar-impl-sandbox-eeeeeeeeee', NaN, NaN, false),   // unlabelled: never reaped automatically
  ];
  const orphans = selectOrphans(objs, { now: NOW, staleMs: 480_000, isAlive: (p) => alivePids.has(p) });
  assert.deepEqual(orphans.map((o) => o.name), ['ar-impl-sandbox-cccccccccc', 'ar-impl-sandbox-dddddddddd']);
});

test('S1-D2 task-scoped name pattern matches only that task', () => {
  const re = ownName('impl', 'aaaaaaaaaa');
  assert.ok(re.test('ar-impl-sandbox-aaaaaaaaaa'));
  assert.ok(re.test('ar-impl-net-aaaaaaaaaa'));
  assert.equal(re.test('ar-impl-sandbox-bbbbbbbbbb'), false);
  assert.equal(re.test('ar-impl-x-sandbox-aaaaaaaaaa'), false);
  assert.equal(ownName('impl').test('ar-impl-sandbox-bbbbbbbbbb'), true);
  assert.equal(ownName('impl').test('ar-adv-sandbox-bbbbbbbbbb'), false);
});

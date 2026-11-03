'use strict';
// S1-D2 / auditor mutant U23: removeTask(prefix, A) must never list or remove
// task B's objects. The docker CLI is stubbed: it filters by the labels and
// name patterns it is given, like the real one, and records every rm.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const OBJECTS = [
  // task A (labelled)
  { type: 'container', name: 'ar-impl-sandbox-aaaaaaaaaa', labels: { 'qp.run-prefix': 'impl', 'qp.task-id': 'aaaaaaaaaa', 'qp.owner-pid': '111', 'qp.created': '1' } },
  { type: 'network', name: 'ar-impl-net-aaaaaaaaaa', labels: { 'qp.run-prefix': 'impl', 'qp.task-id': 'aaaaaaaaaa', 'qp.owner-pid': '111', 'qp.created': '1' } },
  { type: 'volume', name: 'ar-impl-vol-aaaaaaaaaa', labels: { 'qp.run-prefix': 'impl', 'qp.task-id': 'aaaaaaaaaa', 'qp.owner-pid': '111', 'qp.created': '1' } },
  // task A object that lost its labels (found only by name)
  { type: 'container', name: 'ar-impl-tracer-aaaaaaaaaa', labels: {} },
  // task B, same prefix, live
  { type: 'container', name: 'ar-impl-sandbox-bbbbbbbbbb', labels: { 'qp.run-prefix': 'impl', 'qp.task-id': 'bbbbbbbbbb', 'qp.owner-pid': '222', 'qp.created': '1' } },
  { type: 'network', name: 'ar-impl-net-bbbbbbbbbb', labels: { 'qp.run-prefix': 'impl', 'qp.task-id': 'bbbbbbbbbb', 'qp.owner-pid': '222', 'qp.created': '1' } },
  { type: 'volume', name: 'ar-impl-vol-bbbbbbbbbb', labels: { 'qp.run-prefix': 'impl', 'qp.task-id': 'bbbbbbbbbb', 'qp.owner-pid': '222', 'qp.created': '1' } },
  { type: 'container', name: 'ar-impl-tracer-bbbbbbbbbb', labels: {} },
];

function fakeDocker(state) {
  return async function docker(args) {
    const listed = (type) => {
      const filters = [];
      for (let i = 0; i < args.length; i++) if (args[i] === '--filter') filters.push(args[i + 1]);
      const live = OBJECTS.filter((o) => o.type === type && !state.removed.has(`${o.type}:${o.name}`)).filter((o) => filters.every((f) => {
        if (f.startsWith('label=')) { const [k, v] = f.slice(6).split('='); return o.labels[k] === v; }
        if (f.startsWith('name=')) return new RegExp(f.slice(5)).test(o.name);
        return true;
      }));
      const fmt = args[args.indexOf('--format') + 1];
      const out = live.map((o) => (fmt.includes('\t') ? [o.name, o.labels['qp.task-id'] || '', o.labels['qp.owner-pid'] || '', o.labels['qp.created'] || ''].join('\t') : o.name));
      for (const o of live) state.listed.add(o.name);
      return { code: 0, stdout: out.join('\n'), stderr: '' };
    };
    if (args[0] === 'ps') return listed('container');
    if (args[0] === 'network' && args[1] === 'ls') return listed('network');
    if (args[0] === 'volume' && args[1] === 'ls') return listed('volume');
    const rm = (type, names) => { for (const n of names) state.removed.add(`${type}:${n}`); return { code: 0, stdout: '', stderr: '' }; };
    if (args[0] === 'rm') return rm('container', args.filter((a) => !a.startsWith('-') && a !== 'rm'));
    if (args[0] === 'network' && args[1] === 'rm') return rm('network', args.slice(2));
    if (args[0] === 'volume' && args[1] === 'rm') return rm('volume', args.slice(2).filter((a) => !a.startsWith('-')));
    throw new Error(`unexpected docker call: ${args.join(' ')}`);
  };
}

function loadLifecycle(state) {
  const dockerPath = path.join(__dirname, '..', 'src', 'docker.js');
  const lifecyclePath = path.join(__dirname, '..', 'src', 'lifecycle.js');
  delete require.cache[lifecyclePath];
  require.cache[dockerPath] = { id: dockerPath, filename: dockerPath, loaded: true, exports: { docker: fakeDocker(state) } };
  const mod = require(lifecyclePath);
  delete require.cache[dockerPath];
  delete require.cache[lifecyclePath];
  return mod;
}

test('S1-D2 (U23): removeTask(prefix, A) never lists or removes task B objects', async () => {
  const state = { removed: new Set(), listed: new Set() };
  const { removeTask } = loadLifecycle(state);
  const r = await removeTask('impl', 'aaaaaaaaaa');
  const removedNames = [...state.removed].map((k) => k.split(':')[1]);
  assert.deepEqual(removedNames.filter((n) => n.endsWith('bbbbbbbbbb')), [], 'task B objects were removed');
  assert.deepEqual([...state.listed].filter((n) => n.endsWith('bbbbbbbbbb')), [], 'task B objects were listed');
  // Task A, its unlabelled leftover included, is fully removed.
  assert.deepEqual(removedNames.sort(), ['ar-impl-net-aaaaaaaaaa', 'ar-impl-sandbox-aaaaaaaaaa', 'ar-impl-tracer-aaaaaaaaaa', 'ar-impl-vol-aaaaaaaaaa']);
  assert.deepEqual(r.containers.sort(), ['ar-impl-sandbox-aaaaaaaaaa', 'ar-impl-tracer-aaaaaaaaaa']);
});

test('S1-D2: cleanup (explicit) removes every object of the prefix, both tasks', async () => {
  const state = { removed: new Set(), listed: new Set() };
  const { cleanupAll } = loadLifecycle(state);
  await cleanupAll('impl');
  assert.equal(state.removed.size, OBJECTS.length);
});

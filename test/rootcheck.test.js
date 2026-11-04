'use strict';
// DEC-16r1 completeness (ruling e1ba6bfd): one test per item (a)-(d).
const test = require('node:test');
const assert = require('node:assert/strict');
const { checkRoot } = require('../images/sandbox/runtime/rootcheck.cjs');

// Stand-in for npm-package-arg classification (the image uses the real one).
const classify = (_name, spec) => {
  if (/^(\^|~)?\d+\.\d+\.\d+$|^latest$|^\*$|^npm:[a-z@][^@]*@\^?\d/.test(spec)) return 'registry';
  if (/^git|^github:/.test(spec)) return 'git';
  if (/^https?:/.test(spec)) return 'remote';
  if (/^file:/.test(spec)) return 'directory';
  return 'invalid:other';
};
const fields = (r) => r.map((x) => `${x.field}:${x.specType}`);

test('rootcheck: registry-only manifest passes', () => {
  assert.deepEqual(checkRoot({ name: 'x', dependencies: { a: '^1.0.0' }, devDependencies: { b: '2.0.0' }, overrides: { c: '1.2.3' } }, classify), []);
});

test('rootcheck (a): devDependencies are classified', () => {
  const r = checkRoot({ devDependencies: { evil: 'git+https://x/y.git', ok: '^1.0.0' } }, classify);
  assert.deepEqual(fields(r), ['devDependencies:git']);
  assert.equal(r[0].dependency, 'evil');
});

test('rootcheck (b): overrides and resolutions are walked recursively, every string value classified', () => {
  const r = checkRoot({
    dependencies: { foo: '^1.0.0' },
    overrides: { foo: { '.': '1.0.0', bar: 'https://example.com/bar.tgz' }, baz: '$foo', 'qux@^1': { deep: { deeper: 'file:../x' } } },
    resolutions: { '**/lodash': 'github:a/b', 'parent/@scope/child': '1.0.0' },
  }, classify);
  assert.deepEqual(fields(r).sort(), ['overrides:directory', 'overrides:remote', 'resolutions:git']);
  assert.ok(r.some((x) => x.dependency === 'qux@^1>deep>deeper'));
  assert.deepEqual(fields(checkRoot({ overrides: 'git+https://x' }, classify)), ['overrides:invalid:not-an-object']);
  assert.deepEqual(fields(checkRoot({ overrides: { a: 7 } }, classify)), ['overrides:invalid:not-a-string']);
});

test('rootcheck (c): non-empty bundleDependencies / bundledDependencies are rejected', () => {
  assert.deepEqual(fields(checkRoot({ bundleDependencies: ['a'] }, classify)), ['bundleDependencies:bundled']);
  assert.deepEqual(fields(checkRoot({ bundledDependencies: true }, classify)), ['bundledDependencies:bundled']);
  assert.deepEqual(checkRoot({ bundleDependencies: [] }, classify), []);
  assert.deepEqual(checkRoot({ bundledDependencies: false }, classify), []);
});

test('rootcheck (d): unknown resolution-relevant root fields fail closed', () => {
  for (const key of ['workspaces', 'pnpm', 'dependenciesMeta', 'packageManager', 'installConfig', 'someNewDependencies', 'npmShrinkwrap']) {
    const r = checkRoot({ [key]: { anything: 1 } }, classify);
    assert.deepEqual(fields(r), [`${key}:unsupported-resolution-field`], key);
  }
  // Non-resolution metadata is fine.
  assert.deepEqual(checkRoot({ name: 'x', version: '1.0.0', scripts: { install: 'node x' }, main: 'i.js', license: 'MIT', peerDependenciesMeta: { a: { optional: true } } }, classify), []);
});

test('rootcheck: malformed spec fields fail closed', () => {
  assert.deepEqual(fields(checkRoot({ dependencies: ['a'] }, classify)), ['dependencies:invalid:not-an-object']);
  assert.deepEqual(fields(checkRoot({ dependencies: { a: 1 } }, classify)), ['dependencies:invalid:not-a-string']);
});

test('X9: a registry root skips devDependencies; a fixture root still classifies them', () => {
  const m = { dependencies: { a: '^1.0.0' }, devDependencies: { tool: 'git+https://x/y.git' } };
  assert.deepEqual(checkRoot(m, classify, { registryRoot: true }), []);
  assert.deepEqual(fields(checkRoot(m, classify)), ['devDependencies:git']);
  assert.deepEqual(fields(checkRoot({ ...m, dependencies: { evil: 'git+https://x/z.git' } }, classify, { registryRoot: true })), ['dependencies:git']);
});

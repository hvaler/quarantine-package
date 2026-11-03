// Input validation (DEC-19). Pure.
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const NAME = /^(@[a-z0-9][a-z0-9._~-]{0,100}\/)?[a-z0-9][a-z0-9._~-]{0,213}$/;
const VERSION = /^[\^~]?[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$/;

// Accepts only registry specs: name, name@version, name@tag, scoped names.
function parseRegistrySpec(input) {
  const s = String(input || '');
  if (!s || s.startsWith('-')) return { ok: false, error: 'spec must not be empty or start with "-"' };
  if (/[\s;&|`$<>(){}\\"'*?!#,]/.test(s)) return { ok: false, error: 'spec contains shell metacharacters or spaces' };
  if (/^(file:|git\+|git:|https?:|link:|npm:|workspace:)/i.test(s) || s.includes('://')) return { ok: false, error: 'only registry specs are accepted (no file:, git, URL or alias specs)' };
  if (s.startsWith('.') || s.startsWith('/') || /^[A-Za-z]:/.test(s)) return { ok: false, error: 'paths are not accepted; use --fixture for local fixtures' };
  const at = s.lastIndexOf('@');
  let name = s;
  let version = null;
  if (at > 0) { name = s.slice(0, at); version = s.slice(at + 1); }
  if (!NAME.test(name)) return { ok: false, error: 'invalid package name' };
  if (version !== null && !VERSION.test(version)) return { ok: false, error: 'invalid version or tag' };
  if (name.split('/').some((p) => p === '..' || p === '.')) return { ok: false, error: 'invalid package name' };
  return { ok: true, name, version, spec: version ? `${name}@${version}` : name };
}

// Local fixtures: only directory names inside the repo's fixtures dir.
function resolveFixture(fixturesDir, fixture) {
  if (!/^[a-z0-9][a-z0-9-]{0,40}$/.test(String(fixture || ''))) return { ok: false, error: 'invalid fixture name' };
  const dir = path.join(fixturesDir, fixture);
  if (path.dirname(dir) !== path.resolve(fixturesDir)) return { ok: false, error: 'invalid fixture name' };
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8')); } catch (_) {
    return { ok: false, error: `fixture not found: ${fixture}` };
  }
  if (pkg.private !== true) return { ok: false, error: 'fixtures must be private packages' };
  if (!NAME.test(String(pkg.name || ''))) return { ok: false, error: 'fixture has an invalid name' };
  return { ok: true, dir, name: pkg.name, version: pkg.version || null, fixture };
}

module.exports = { parseRegistrySpec, resolveFixture };

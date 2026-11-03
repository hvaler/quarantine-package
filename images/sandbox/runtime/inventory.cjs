'use strict';
// Lock verification and download inventory.
//   inventory.cjs lock <exempt-name|->   -> QP-LOCKCHECK <json>  (before npm ci)
//   inventory.cjs full <exempt-name|->   -> QP-INVENTORY <json>  (after npm ci)
// DEC-16: only registry packages anywhere in the resolved tree. Every lock
// entry must be resolved from https://registry.npmjs.org/, carry an integrity
// hash and not be a link; every declared dependency spec in every entry must
// be a registry spec (version, range, tag or npm: alias to one). Shrinkwrap
// pins inside published packages show up here, as resolved lock entries,
// and are rejected before anything is extracted. The only exemption is the
// local fixture's own entry (it is installed from its packed tarball).
const fs = require('node:fs');
const path = require('node:path');
const npa = require('/usr/local/lib/node_modules/npm/node_modules/npm-package-arg');

const [mode, exemptArg] = process.argv.slice(2);
const exempt = exemptArg && exemptArg !== '-' ? `node_modules/${exemptArg}` : null;
const REGISTRY = /^https:\/\/registry\.npmjs\.org\//;
const REGISTRY_TYPES = new Set(['version', 'range', 'tag']);
const redact = (s) => String(s).replace(/^(file:|git\+|git:|https?:\/\/|github:|link:|workspace:)[^\s]*/, '$1…');

function specType(name, spec) {
  if (/^workspace:/.test(String(spec))) return 'workspace';
  try {
    const r = npa.resolve(name, String(spec));
    if (r.type === 'alias') return r.subSpec && REGISTRY_TYPES.has(r.subSpec.type) ? 'registry' : `alias:${r.subSpec ? r.subSpec.type : '?'}`;
    return REGISTRY_TYPES.has(r.type) ? 'registry' : r.type;
  } catch (e) {
    return `invalid:${e.code || 'error'}`;
  }
}

function du(dir) {
  let total = 0;
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) stack.push(p);
      else if (e.isFile()) { try { total += fs.statSync(p).size; } catch (_) { /* skip */ } }
    }
  }
  return total;
}

const lock = JSON.parse(fs.readFileSync('/out/package-lock.json', 'utf8'));
const pkgs = Object.entries(lock.packages || {}).filter(([k]) => k !== '');
const nonRegistry = [];
for (const [k, v] of pkgs) {
  const r = String(v.resolved || '');
  if (v.inBundle) { nonRegistry.push({ path: k, reason: 'bundled inside another package (bypasses registry resolution)', resolved: redact(r) }); continue; }
  if (k !== exempt) {
    if (v.link) nonRegistry.push({ path: k, reason: 'link', resolved: redact(r) });
    else if (!REGISTRY.test(r)) nonRegistry.push({ path: k, reason: 'resolved outside the registry', resolved: r ? redact(r) : '(none)' });
    else if (!v.integrity) nonRegistry.push({ path: k, reason: 'registry entry without integrity hash', resolved: redact(r) });
  }
  for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [dep, spec] of Object.entries(v[field] || {})) {
      const t = specType(dep, spec);
      if (t !== 'registry') nonRegistry.push({ path: k, reason: `declared ${field} spec is ${t}`, dependency: dep, spec: redact(spec) });
    }
  }
}

if (mode === 'lock') {
  process.stdout.write(`QP-LOCKCHECK ${JSON.stringify({ ok: nonRegistry.length === 0, packageCount: pkgs.length, nonRegistry })}\n`);
  process.exit(0);
}

const root = JSON.parse(fs.readFileSync('/out/package.json', 'utf8'));
const direct = Object.entries(root.dependencies || {});
const top = direct.length ? direct[0] : [null, null];
const topMeta = top[0] ? lock.packages[`node_modules/${top[0]}`] || {} : {};
process.stdout.write(`QP-INVENTORY ${JSON.stringify({
  name: top[0],
  version: topMeta.version || null,
  packageCount: pkgs.length,
  unpackedBytes: du('/out/node_modules'),
  nonRegistry,
  installScripts: pkgs.filter(([, v]) => v.hasInstallScript).map(([k]) => k),
})}\n`);

'use strict';
// Root-manifest resolution check (DEC-16r1 and its completeness ruling e1ba6bfd).
// Pure: checkRoot(manifest, classify) -> [{dependency, field, specType, spec}].
// `classify(name, spec)` returns 'registry' or the offending spec type.
//
// (a) dependencies, devDependencies, optionalDependencies, peerDependencies are
//     classified. X9 (S2): a REGISTRY root's devDependencies are skipped, because
//     npm never installs the devDependencies of an installed package; a local
//     (fixture) root still classifies them.
// (b) overrides (npm) and resolutions (yarn) are walked recursively; every
//     string value is classified ("$name" references and "." keys are skipped).
// (c) a non-empty bundleDependencies / bundledDependencies is rejected: bundled
//     content ships inside the tarball and bypasses registry resolution.
// (d) any other root field that can affect resolution (workspaces, pnpm,
//     dependenciesMeta, ... or any key that looks like one) is rejected.

const SPEC_FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
const TREE_FIELDS = ['overrides', 'resolutions'];
const BUNDLE_FIELDS = ['bundleDependencies', 'bundledDependencies'];
// Fields that affect resolution and are fully handled above, or are metadata only.
const UNDERSTOOD = new Set([...SPEC_FIELDS, ...TREE_FIELDS, ...BUNDLE_FIELDS, 'peerDependenciesMeta']);
// Anything resolution-like that is not understood fails closed.
const RESOLUTION_LIKE = /dependenc|resolution|override|workspace|shrinkwrap|bundle|^pnpm$|^packageManager$|^installConfig$|^engines?Strict$/i;

const redact = (s) => String(s).replace(/^(file:|git\+|git:|https?:\/\/|github:|link:|workspace:)[^\s]*/, '$1…');

function checkRoot(manifest, classify, { registryRoot = false } = {}) {
  const out = [];
  const m = manifest && typeof manifest === 'object' ? manifest : {};
  const push = (dependency, field, specType, spec) => out.push({ dependency, field, specType, spec: redact(spec) });

  for (const field of SPEC_FIELDS) {
    if (registryRoot && field === 'devDependencies') continue;
    const v = m[field];
    if (v === undefined) continue;
    if (!v || typeof v !== 'object' || Array.isArray(v)) { push('(field)', field, 'invalid:not-an-object', JSON.stringify(v).slice(0, 60)); continue; }
    for (const [dep, spec] of Object.entries(v)) {
      const t = typeof spec === 'string' ? classify(dep, spec) : 'invalid:not-a-string';
      if (t !== 'registry') push(dep, field, t, spec);
    }
  }

  for (const field of TREE_FIELDS) {
    const v = m[field];
    if (v === undefined) continue;
    const walk = (obj, prefix) => {
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) { push(prefix || '(field)', field, 'invalid:not-an-object', JSON.stringify(obj).slice(0, 60)); return; }
      for (const [key, val] of Object.entries(obj)) {
        if (val && typeof val === 'object') { walk(val, `${prefix}${key}>`); continue; }
        if (typeof val !== 'string') { push(`${prefix}${key}`, field, 'invalid:not-a-string', String(val)); continue; }
        if (val.startsWith('$')) continue; // reference to a root dependency's spec, classified above
        // keys: "name", "name@range", "." (npm: the parent itself), "parent/name" or "**/name" (yarn)
        const parts = key.replace(/^(\*\*\/)+/, '').split('/');
        const last = parts.length >= 2 && parts[parts.length - 2].startsWith('@') ? parts.slice(-2).join('/') : parts[parts.length - 1];
        const name = (key === '.' ? (prefix.split('>').filter(Boolean).pop() || 'x') : last).replace(/(.)@[^/@]*$/, '$1') || 'x';
        const t = classify(name, val);
        if (t !== 'registry') push(`${prefix}${key}`, field, t, val);
      }
    };
    walk(v, '');
  }

  for (const field of BUNDLE_FIELDS) {
    const v = m[field];
    if (v === undefined || v === false) continue;
    if (v === true || (Array.isArray(v) && v.length) || (v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length)) {
      push('(bundled)', field, 'bundled', Array.isArray(v) ? v.join(',') : String(v));
    }
  }

  for (const key of Object.keys(m)) {
    if (UNDERSTOOD.has(key)) continue;
    if (RESOLUTION_LIKE.test(key)) push('(field)', key, 'unsupported-resolution-field', key);
  }
  return out;
}

module.exports = { checkRoot, SPEC_FIELDS, TREE_FIELDS, BUNDLE_FIELDS };

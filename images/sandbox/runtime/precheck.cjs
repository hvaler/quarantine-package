'use strict';
// Download pre-check (DEC-16, ruling on S1-D1): before anything is fetched or
// installed, walk the dependency tree from the root manifest using registry
// manifests only, and reject any dependency whose DECLARED spec is not a
// registry spec (version, range, tag, or an npm: alias to one). git+*, git:,
// github shorthand, http(s) tarball URLs (any host), file:, link:, workspace:
// and unparseable specs are rejected without being fetched.
// Prints one line: QP-PRECHECK <json>. Exit 0 always; the orchestrator decides.
// Usage: precheck.cjs <root-manifest-path | registry spec> <maxPackages>
const fs = require('node:fs');

const NPM = '/usr/local/lib/node_modules/npm/node_modules';
const npa = require(`${NPM}/npm-package-arg`);
const pacote = require(`${NPM}/pacote`);
const { checkRoot } = require('./rootcheck.cjs');

const REGISTRY_TYPES = new Set(['version', 'range', 'tag']);
const FIELDS = ['dependencies', 'optionalDependencies', 'peerDependencies'];
const [rootArg, maxArg] = process.argv.slice(2);
const MAX = Number(maxArg) || 300;
const opts = { cache: '/home/qp/.npm/_cacache', registry: 'https://registry.npmjs.org/', fullMetadata: false };

const redact = (s) => String(s).replace(/^(file:|git\+|git:|https?:\/\/|github:|link:|workspace:)[^\s]*/, '$1…');

function classify(name, spec) {
  if (typeof spec !== 'string') return 'invalid:not-a-string';
  if (/^workspace:/.test(spec)) return 'workspace';
  try {
    const r = npa.resolve(name, spec);
    if (r.type === 'alias') return r.subSpec && REGISTRY_TYPES.has(r.subSpec.type) ? 'registry' : `alias:${r.subSpec ? r.subSpec.type : '?'}`;
    return REGISTRY_TYPES.has(r.type) ? 'registry' : r.type;
  } catch (e) {
    return `invalid:${e.code || 'error'}`;
  }
}

async function main() {
  const nonRegistry = [];
  const seen = new Set();
  let root;
  if (rootArg.startsWith('/')) {
    root = JSON.parse(fs.readFileSync(rootArg, 'utf8'));
  } else {
    root = await pacote.manifest(rootArg, opts);
  }
  // DEC-16r1 (1): the root manifest's declared specs, overrides included, are
  // classified first; if any is not a registry spec we stop here, before a
  // single network request (for a fixture root nothing has been fetched at all).
  const rootFrom = root.name || '(root)';
  for (const r of checkRoot(root, classify, { registryRoot: !rootArg.startsWith('/') })) nonRegistry.push({ from: rootFrom, ...r });
  // A shrinkwrap can pin dependencies to any source regardless of the declared
  // specs. A local root that ships one is rejected outright (fail closed); for
  // registry packages, the verified lock after --package-lock-only is the gate.
  if (rootArg.startsWith('/')) {
    const dir = rootArg.replace(/\/package\.json$/, '');
    if (fs.existsSync(`${dir}/npm-shrinkwrap.json`)) nonRegistry.push({ from: rootFrom, dependency: '(npm-shrinkwrap.json)', field: 'shrinkwrap', specType: 'shrinkwrap', spec: 'npm-shrinkwrap.json' });
  }
  if (nonRegistry.length) {
    process.stdout.write(`QP-PRECHECK ${JSON.stringify({ ok: false, reason: 'download-non-registry', stage: 'root', visited: 0, manifestsFetched: 0, nonRegistry })}\n`);
    return;
  }
  let queue = [{ from: rootFrom, manifest: root }];
  let fetched = 0;
  while (queue.length) {
    const next = [];
    const jobs = [];
    for (const { from, manifest } of queue) {
      for (const field of FIELDS) {
        for (const [dep, spec] of Object.entries(manifest[field] || {})) {
          const type = classify(dep, spec);
          if (type !== 'registry') {
            nonRegistry.push({ from, dependency: dep, field, specType: type, spec: redact(spec) });
            continue; // never fetched
          }
          const key = `${dep}@${spec}`;
          if (seen.has(key)) continue;
          seen.add(key);
          if (seen.size > MAX) {
            process.stdout.write(`QP-PRECHECK ${JSON.stringify({ ok: false, reason: 'download-deps', visited: seen.size, nonRegistry })}\n`);
            return;
          }
          const optional = field !== 'dependencies';
          jobs.push(pacote.manifest(key, opts).then(
            (m) => { fetched += 1; next.push({ from: `${m.name}@${m.version}`, manifest: m }); },
            (e) => { if (!optional) throw Object.assign(new Error(`manifest ${key}: ${e.code || e.message}`), { code: e.code }); },
          ));
        }
      }
    }
    await Promise.all(jobs);
    queue = next;
  }
  process.stdout.write(`QP-PRECHECK ${JSON.stringify({ ok: nonRegistry.length === 0, reason: nonRegistry.length ? 'download-non-registry' : null, stage: 'tree', visited: seen.size, manifestsFetched: fetched, nonRegistry })}\n`);
}

main().catch((e) => {
  process.stdout.write(`QP-PRECHECK ${JSON.stringify({ ok: false, reason: 'download-failed', error: String(e.code || e.message).slice(0, 200) })}\n`);
});

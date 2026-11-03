'use strict';
// Download inventory: unpacked size, package count, resolved spec kinds.
// Prints one line: QP-INVENTORY <json>
const fs = require('node:fs');
const path = require('node:path');

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
const root = JSON.parse(fs.readFileSync('/out/package.json', 'utf8'));
const pkgs = Object.entries(lock.packages || {}).filter(([k]) => k !== '');
const nonRegistry = [];
for (const [k, v] of pkgs) {
  const r = String(v.resolved || '');
  if (v.link || !/^https:\/\/registry\.npmjs\.org\//.test(r)) nonRegistry.push({ path: k, resolved: r ? r.replace(/^(file:|git\+|https?:\/\/)[^\s]*/, '$1…') : '(none)', link: !!v.link });
}
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

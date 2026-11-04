#!/usr/bin/env node
// C17: dependency licence check. Writes docs/licenses.json and exits 1 on any
// licence that is not MIT-compatible.
// 1. The repo itself: package.json must be MIT and have no npm dependencies.
// 2. The JS our image code loads at runtime: npm-package-arg and pacote from the
//    npm copy bundled in the official node image, with their whole dependency
//    tree, read inside the sandbox image (no network).
// System tools in the images (strace, iptables, tcpdump, python) are separate
// programs we invoke, not code we link or redistribute; they are listed apart.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { loadConfig, REPO_ROOT } = require('../src/config');

const ALLOWED = new Set(['MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', '0BSD', 'BlueOak-1.0.0', 'CC0-1.0', 'Unlicense', 'Python-2.0', 'CC-BY-4.0', 'CC-BY-3.0']);
const okExpr = (l) => typeof l === 'string' && l.replace(/[()]/g, '').split(/\s+OR\s+/i).some((p) => p.split(/\s+AND\s+/i).every((x) => ALLOWED.has(x.trim())));

const WALK = `
const fs=require('fs'),path=require('path');const root='/usr/local/lib/node_modules/npm/node_modules';
const seen=new Map();const q=[['npm-package-arg',root],['pacote',root]];
const find=(n,from)=>{let d=from;for(;;){const c=path.join(d,'node_modules',n);if(fs.existsSync(path.join(c,'package.json')))return c;if(d===root||d==='/'||!d.startsWith(root))break;d=path.dirname(d)}const t=path.join(root,n);return fs.existsSync(path.join(t,'package.json'))?t:null};
while(q.length){const [n,from]=q.shift();const dir=from===root&&fs.existsSync(path.join(root,n,'package.json'))?path.join(root,n):find(n,from);
if(!dir){if(!seen.has(n))seen.set(n,{version:null,license:'NOT FOUND'});continue}if(seen.has(dir))continue;
const pj=JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8'));
seen.set(dir,{name:n,version:pj.version,license:typeof pj.license==='string'?pj.license:(pj.license&&pj.license.type)||null});
for(const d of Object.keys(pj.dependencies||{}))q.push([d,dir]);}
process.stdout.write(JSON.stringify([...seen].map(([k,v])=>v.name?v:{name:k,...v})));`;

function main() {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
  const licenceText = fs.readFileSync(path.join(REPO_ROOT, 'LICENSE'), 'utf8');
  const repo = {
    license: pkg.license,
    licenseFileIsMit: /^MIT License/m.test(licenceText),
    dependencies: Object.keys(pkg.dependencies || {}),
    devDependencies: Object.keys(pkg.devDependencies || {}),
  };
  const cfg = loadConfig();
  let image = null;
  let imageError = null;
  try {
    const out = execFileSync('docker', ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--entrypoint', 'node', cfg.images.sandbox, '-e', WALK], { encoding: 'utf8', timeout: 60000 });
    image = JSON.parse(out);
  } catch (e) { imageError = `could not read the image ${cfg.images.sandbox}: ${String(e.message).split('\n')[0]}`; }
  const bad = [];
  if (repo.license !== 'MIT' || !repo.licenseFileIsMit) bad.push('repo licence is not MIT');
  if (repo.dependencies.length || repo.devDependencies.length) {
    // Any npm dependency must be checked; none exist today.
    bad.push(`unexpected npm dependencies: ${[...repo.dependencies, ...repo.devDependencies].join(', ')}`);
  }
  for (const m of image || []) if (!okExpr(m.license)) bad.push(`${m.name}@${m.version}: ${m.license}`);
  const result = {
    schema: 'qp-licenses/1',
    image: cfg.images.sandbox,
    repo,
    imageRuntimeModules: image,
    imageError,
    systemTools: [
      { name: 'node (official image)', license: 'MIT', note: 'runtime' },
      { name: 'npm (bundled in the node image)', license: 'Artistic-2.0', note: 'run as a separate program (npm rebuild / npm ci); not linked into or distributed with this repo' },
      { name: 'python (official image, sinkhole)', license: 'Python-2.0', note: 'interpreter for the sinkhole script' },
      { name: 'strace, iptables, tcpdump (Debian/Alpine packages)', license: 'LGPL/GPL', note: 'separate programs invoked in containers; not linked or redistributed by this repo' },
    ],
    allowed: [...ALLOWED],
    pass: bad.length === 0 && !imageError,
    problems: bad,
  };
  const out = path.join(REPO_ROOT, 'docs', 'licenses.json');
  fs.writeFileSync(out, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify({ pass: result.pass, modules: (image || []).length, problems: bad, imageError, file: path.relative(process.cwd(), out) }));
  process.exitCode = result.pass ? 0 : 1;
}

main();

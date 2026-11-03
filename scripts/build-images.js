#!/usr/bin/env node
// Builds the two product images from the repo (base images pinned by digest
// in the Dockerfiles). Tags carry the commit: qp-sandbox:s1-<sha8>,
// qp-sinkhole:s1-<sha8> (or QP_IMAGE_TAG), the tags the CLI uses by default.
'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { loadConfig } = require('../src/config');

const root = path.resolve(__dirname, '..');
const cfg = loadConfig();
for (const [tag, dir] of [[cfg.images.sandbox, 'images/sandbox'], [cfg.images.sinkhole, 'images/sinkhole']]) {
  const r = spawnSync('docker', ['build', '-t', tag, path.join(root, dir)], { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status || 1);
  console.log(`built ${tag}`);
}

#!/usr/bin/env node
// Builds the two product images from the repo (base images pinned by digest
// in the Dockerfiles). Tags: qp-sandbox:s1, qp-sinkhole:s1.
'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
for (const [tag, dir] of [['qp-sandbox:s1', 'images/sandbox'], ['qp-sinkhole:s1', 'images/sinkhole']]) {
  const r = spawnSync('docker', ['build', '-t', tag, path.join(root, dir)], { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status || 1);
}

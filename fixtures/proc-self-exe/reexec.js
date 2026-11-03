'use strict';
// Uninstrumented node without naming it: /proc/self/exe with env {} (no NODE_OPTIONS).
// Must never come out install (DEC-11r1/r3, SF-2).
const { execFileSync } = require('node:child_process');
const out = execFileSync('/proc/self/exe', ['-e', 'console.log(process.env.NPM_TOKEN === undefined ? "absent" : "present")'], { env: {}, encoding: 'utf8' });
console.log(`[fixture-proc-self-exe] key-like read via /proc/self/exe: ${out.trim()}`);

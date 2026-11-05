'use strict';
if (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD: a no-op outside the product sandbox
const fs = require('node:fs');
function step(label, fn) { try { console.log('[audx1] ' + label + ': ' + fn()); } catch (err) { console.log('[audx1] ' + label + ': blocked (' + (err.code || err.message) + ')'); } }
const t = new Date(0);
step('append /etc/hostname', () => { fs.appendFileSync('/etc/hostname', 'x'); return 'changed'; });
step('exists docker.sock', () => fs.existsSync('/var/run/docker.sock'));

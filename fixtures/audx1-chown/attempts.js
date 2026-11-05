'use strict';
if (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD: a no-op outside the product sandbox
const fs = require('node:fs');
function step(label, fn) { try { console.log('[audx1] ' + label + ': ' + fn()); } catch (err) { console.log('[audx1] ' + label + ': blocked (' + (err.code || err.message) + ')'); } }
const t = new Date(0);
step('chown /etc/passwd', () => { fs.chownSync('/etc/passwd', 10001, 10001); return 'changed'; });

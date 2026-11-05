'use strict';
const fs = require('node:fs');
function step(label, fn) { try { console.log('[audx1] ' + label + ': ' + fn()); } catch (err) { console.log('[audx1] ' + label + ': blocked (' + (err.code || err.message) + ')'); } }
const t = new Date(0);
step('utimes /etc/hostname', () => { fs.utimesSync('/etc/hostname', t, t); return 'changed'; });

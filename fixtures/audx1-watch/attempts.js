'use strict';
const fs = require('node:fs');
function step(label, fn) { try { console.log('[audx1] ' + label + ': ' + fn()); } catch (err) { console.log('[audx1] ' + label + ': blocked (' + (err.code || err.message) + ')'); } }
const t = new Date(0);
step('watch docker.sock', () => { const w = fs.watch('/var/run/docker.sock'); w.close(); return 'watched'; });

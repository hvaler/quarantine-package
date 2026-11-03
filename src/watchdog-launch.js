// Starts the watchdog as a grandchild and exits at once, so the watchdog is
// not in the CLI's process tree (a tree kill of the CLI cannot reach it).
'use strict';

const path = require('node:path');
const { spawn } = require('node:child_process');

const child = spawn(process.execPath, [path.join(__dirname, 'watchdog.js'), ...process.argv.slice(2)], {
  detached: true, stdio: 'ignore', windowsHide: true,
});
child.unref();
process.stdout.write(String(child.pid));

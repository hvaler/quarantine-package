// Detached watchdog: started per task, outlives an abruptly killed CLI.
// When the owner pid disappears it removes every object of that task
// (label qp.task-id) and exits. The CLI kills it after a normal teardown.
'use strict';

const { removeTask, alive } = require('./lifecycle');

const [ownerPid, prefix, taskId] = [Number(process.argv[2]), process.argv[3], process.argv[4]];
const POLL_MS = 500;

async function loop() {
  for (;;) {
    if (!alive(ownerPid)) {
      // Objects can still be in creation for a moment after the kill; sweep twice.
      await removeTask(prefix, taskId).catch(() => {});
      await new Promise((r) => setTimeout(r, 3000));
      await removeTask(prefix, taskId).catch(() => {});
      process.exit(0);
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

if (!Number.isInteger(ownerPid) || !/^[a-z0-9]{1,16}$/.test(prefix || '') || !/^[a-f0-9]{8,16}$/.test(taskId || '')) process.exit(2);
loop();

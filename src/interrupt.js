// AF-7: Ctrl+C / SIGTERM handling for one task.
//
// The first signal starts the task teardown at once and exits when it is done,
// or at the deadline, whichever comes first (the detached watchdog stays alive
// as the backstop for anything still being created). Further signals while the
// teardown runs are swallowed: they never skip it and never start a second one.
// Pure apart from the injected functions, so it is unit-tested with a fake
// clock, fake timers and a fake teardown.
'use strict';

const INTERRUPT_EXIT_CODE = 130;
const DEFAULT_DEADLINE_MS = 9000;

function createInterrupt({
  teardown, // async () => any; must be safe to call while the task is mid-flight
  exit, // (code) => void
  clock = { now: () => Date.now() },
  deadlineMs = DEFAULT_DEADLINE_MS,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  log = () => {},
}) {
  const state = { signal: null, signalledAt: null, repeated: 0, finishedAt: null, outcome: null, done: null };

  function handler(signal) {
    if (state.signalledAt !== null) {
      state.repeated += 1;
      log(`${signal} received again; teardown already in progress (not skipped)`);
      return;
    }
    state.signal = signal || 'SIGINT';
    state.signalledAt = clock.now();
    log(`${state.signal} received; tearing down this task's objects`);
    let timer = null;
    const deadline = new Promise((resolve) => { timer = setTimer(() => resolve('deadline'), deadlineMs); });
    const work = Promise.resolve()
      .then(() => teardown(state))
      .then(() => 'teardown-complete', (err) => { log(`teardown error: ${err && err.message || err}`); return 'teardown-error'; });
    state.done = Promise.race([work, deadline]).then((outcome) => {
      if (outcome !== 'deadline') clearTimer(timer);
      state.outcome = outcome;
      state.finishedAt = clock.now();
      exit(INTERRUPT_EXIT_CODE);
      return outcome;
    });
  }

  return { handler, state };
}

module.exports = { createInterrupt, INTERRUPT_EXIT_CODE, DEFAULT_DEADLINE_MS };

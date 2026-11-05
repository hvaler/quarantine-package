#!/bin/sh
[ -n "${QP_TASK_NONCE:-}" ] || exit 0 # QP-FIXTURE-GUARD: a no-op outside the product sandbox
# Classic fork bomb; contained by the sandbox pids limit and wall clock.
b() { b | b & }
b
wait

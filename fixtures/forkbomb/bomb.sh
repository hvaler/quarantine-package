#!/bin/sh
# Classic fork bomb; contained by the sandbox pids limit and wall clock.
b() { b | b & }
b
wait

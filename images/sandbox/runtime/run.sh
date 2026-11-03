#!/bin/sh
# Sandbox entry (pid 1 of the sandbox, uid 10001).
# The kernel trace is taken by a separate tracer container (root + SYS_PTRACE,
# shared pid namespace, no network) that attaches to this pid with strace -f.
# Nothing package-related runs until the tracer is attached: pid 1 waits for
# its own TracerPid to become non-zero, then execs the staged work under an
# in-container hard timeout. Traced code (uid 10001) cannot reach the tracer's
# output (different uid, no capabilities), so it cannot forge or truncate it.
# Usage: run.sh <wall-seconds> <package-name>
set -u
WALL="$1"; PKG="$2"
exec 2>&1
i=0
while :; do
  tp=$(sed -n 's/^TracerPid:[[:space:]]*//p' /proc/self/status)
  [ "${tp:-0}" != "0" ] && break
  i=$((i + 1))
  if [ "$i" -gt 200 ]; then echo "QP-TRACER-MISSING"; exit 95; fi
  sleep 0.05
done
echo "QP-TRACER-ATTACHED"
echo "QP-PHASE copy"
cp -a /in/. /work/ || { echo "QP-RC copy $?"; exit 90; }
echo "QP-RC copy 0"
exec timeout -s KILL "$((WALL + 5))" /opt/qp/stage.sh "$PKG"

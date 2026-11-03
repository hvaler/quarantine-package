#!/bin/sh
# Download phase (network on, scripts off). Runs as uid 10001 in the
# hardened download container; output goes to /out (a per-task volume).
#  1. precheck: every declared spec, root first, BEFORE npm runs (DEC-16r1).
#  2. resolve a lockfile only (--package-lock-only): nothing is extracted.
#  3. verify the lock: registry-resolved, integrity, no links, registry specs
#     (catches shrinkwrap pins and anything the spec walk could not see).
#  4. npm ci from exactly that verified lock, scripts off.
#  5. inventory (size, count) for the orchestrator's limits.
# Usage: download.sh <spec-or-/src> <max-packages> <exempt-fixture-name|->
set -u
SPEC="$1"
MAXPKG="${2:-300}"
EXEMPT="${3:--}"
cd /out || exit 91
if [ "$SPEC" = "/src" ]; then ROOT=/src/package.json; else ROOT="$SPEC"; fi
PRE=$(node /opt/qp/precheck.cjs "$ROOT" "$MAXPKG")
echo "$PRE"
case "$PRE" in
  *'"ok":true'*) ;;
  *) exit 94 ;;
esac
printf '{"name":"qp-task","private":true,"version":"0.0.0"}\n' > package.json
if [ "$SPEC" = "/src" ]; then
  TGZ=$(npm pack /src --ignore-scripts --pack-destination /tmp --silent 2>/dev/null | tail -n 1) || exit 92
  SPEC="/tmp/$TGZ"
fi
npm install --package-lock-only --ignore-scripts --no-audit --no-fund --save-exact --loglevel=error "$SPEC"
RC=$?
echo "QP-RC lock $RC"
[ "$RC" -eq 0 ] || exit 93
LOCK=$(node /opt/qp/inventory.cjs lock "$EXEMPT")
echo "$LOCK"
case "$LOCK" in
  *'"ok":true'*) ;;
  *) exit 95 ;;
esac
npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
RC=$?
echo "QP-RC install $RC"
[ "$RC" -eq 0 ] || exit 93
node /opt/qp/inventory.cjs full "$EXEMPT"

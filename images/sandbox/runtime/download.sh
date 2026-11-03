#!/bin/sh
# Download phase (network on, scripts off). Runs as uid 10001 in the
# hardened download container; output goes to /out (a per-task volume).
# Usage: download.sh <spec-or-/src>
set -u
SPEC="$1"
cd /out || exit 91
printf '{"name":"qp-task","private":true,"version":"0.0.0"}\n' > package.json
if [ "$SPEC" = "/src" ]; then
  TGZ=$(npm pack /src --ignore-scripts --pack-destination /tmp --silent 2>/dev/null | tail -n 1) || exit 92
  SPEC="/tmp/$TGZ"
fi
npm install --ignore-scripts --no-audit --no-fund --no-save=false --save-exact --loglevel=error "$SPEC"
RC=$?
echo "QP-RC install $RC"
[ "$RC" -eq 0 ] || exit 93
node /opt/qp/inventory.cjs

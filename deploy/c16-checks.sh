#!/bin/sh
# C16 on-VM checks. Run from /opt/quarantine-package as the qp user (docker group):
#   sh deploy/c16-checks.sh https://qp.example.com
# Prints one PASS/FAIL line per check and writes evidence/c16-<utc>.json. Exit 0 only if all pass.
set -u
URL="${1:?usage: sh deploy/c16-checks.sh https://<public-host>}"
export QP_RUN_PREFIX="${QP_RUN_PREFIX:-qp}"
export QP_RECEIPTS_DIR="${QP_RECEIPTS_DIR:-/var/lib/quarantine-package/receipts}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p evidence
OUT="evidence/c16-$TS.json"
FAIL=0
HOSTILE_OUT="$(mktemp)" || exit 1
trap 'rm -f "$HOSTILE_OUT"' EXIT
res() { printf '%s %s\n' "$1" "$2"; [ "$1" = PASS ] || FAIL=1; }

# 1. C2 host-side probe: nothing leaves the VM during a run whose package tries the network.
P="$(node src/cli.js analyse --fixture netbenign --host-probe 2>/dev/null | tail -n 1)"
echo "$P" | grep -q '"hostProbePass":true' && res PASS "C2 host probe (nothing left the VM)" || res FAIL "C2 host probe: $P"

# 2. /healthz answers within 1 s, every 0.5 s, while the hostile fixture runs.
node src/cli.js analyse --fixture hostile >"$HOSTILE_OUT" 2>/dev/null &
HP=$!
H_OK=1; N=0
while kill -0 "$HP" 2>/dev/null; do
  curl -fsS --max-time 1 "$URL/healthz" >/dev/null || H_OK=0
  N=$((N + 1)); sleep 0.5
done
wait "$HP"
grep -q '"verdict":"do-not-install"' "$HOSTILE_OUT" && res PASS "hostile fixture: do-not-install" || res FAIL "hostile fixture verdict: $(cat "$HOSTILE_OUT")"
[ "$H_OK" = 1 ] && [ "$N" -gt 0 ] && res PASS "C14 /healthz answered $N times during the hostile run" || res FAIL "C14 /healthz failed during the hostile run"

# 3. C6 zero leftovers after the three demo cases (express, netbenign, hostile).
node src/cli.js analyse express@4.21.2 >/dev/null 2>&1
L="$(node src/cli.js leftovers)"
echo "$L" | grep -q '"count":0' && res PASS "C6 zero leftovers" || res FAIL "C6 leftovers: $L"

# 4. C7 secret scan of the repo and the receipts.
S="$(node src/cli.js scan-secrets)"
echo "$S" | grep -q '"hits":\[\]' && res PASS "C7 secret scan" || res FAIL "C7 secret scan: $S"

# 5. The public URL answers over TLS.
curl -fsS --max-time 5 "$URL/" >/dev/null && res PASS "public URL answers" || res FAIL "public URL does not answer"

printf '{"at":"%s","url":"%s","probe":%s,"leftovers":%s,"scan":%s,"pass":%s}\n' "$TS" "$URL" "${P:-null}" "${L:-null}" "${S:-null}" "$([ $FAIL = 0 ] && echo true || echo false)" > "$OUT"
echo "evidence: $OUT"
exit $FAIL

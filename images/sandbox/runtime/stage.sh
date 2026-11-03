#!/bin/sh
# Traced stage: in-sandbox scan, npm rebuild (install scripts), then the harness.
PKG="$1"
cd /work || exit 91
echo "QP-PHASE scan"
QP_ROLE=qp-scan node /opt/qp/scan.cjs
echo "QP-PHASE rebuild"
QP_ROLE=npm npm rebuild --offline --foreground-scripts
echo "QP-RC rebuild $?"
echo "QP-PHASE harness"
QP_ROLE=harness node /opt/qp/harness.cjs "$PKG"
echo "QP-RC harness $?"
echo "QP-PHASE done"

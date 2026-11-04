'use strict';
// H-1 (defence in depth): a product role claimed through QP_ROLE is honoured only
// when the process really is that product entry point, started by the stage script.
// Anything else is 'package'. Pure: the caller supplies the facts.
//   claimed     the QP_ROLE value
//   argv        process.argv of the claiming process
//   parentCmd   the parent's /proc/<ppid>/cmdline, NUL-separated (null if unreadable)
const ENTRY = Object.freeze({
  harness: (a) => a === '/opt/qp/harness.cjs',
  'qp-scan': (a) => a === '/opt/qp/scan.cjs',
  npm: (a) => typeof a === 'string' && (/\/bin\/npm$/.test(a) || /\/npm\/bin\/npm-cli\.js$/.test(a)),
});

function verifyRole(claimed, { argv, parentCmd }) {
  if (!claimed || claimed === 'package') return 'package';
  const entryOk = ENTRY[claimed];
  if (!entryOk) return 'package';
  if (!Array.isArray(argv) || !entryOk(argv[1])) return 'package';
  if (typeof parentCmd !== 'string') return 'package';
  const parts = parentCmd.split('\0').filter(Boolean);
  // The stage script runs as `/bin/sh /opt/qp/stage.sh <pkg>` (or `sh …`).
  if (!(parts.length >= 2 && /(^|\/)sh$/.test(parts[0]) && parts[1] === '/opt/qp/stage.sh')) return 'package';
  return claimed;
}

module.exports = { verifyRole };

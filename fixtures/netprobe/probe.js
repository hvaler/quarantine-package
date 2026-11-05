'use strict';
if (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD: a no-op outside the product sandbox
// C2 matrix: name resolution, direct-IP TCP, TLS with SNI on 443 and 8443.
// No payload is sent: TLS stops at the ClientHello, TCP sends nothing.
const dns = require('node:dns');
const net = require('node:net');
const tls = require('node:tls');

const done = (label) => (err) => console.log(`[fixture-netprobe] ${label}: ${err ? err.code || err.message : 'ok'}`);

dns.lookup('resolve-check.qp-fixture.example', (err, addr) => done(`dns ${addr || ''}`)(err));
const s = net.connect({ host: '1.1.1.1', port: 443, timeout: 3000 });
s.on('connect', () => { done('tcp 1.1.1.1:443')(); s.destroy(); });
s.on('error', done('tcp 1.1.1.1:443'));
s.on('timeout', () => s.destroy());
for (const port of [443, 8443]) {
  const t = tls.connect({ host: 'sni-check.qp-fixture.example', servername: 'sni-check.qp-fixture.example', port, timeout: 3000, rejectUnauthorized: true });
  t.on('secureConnect', () => { done(`tls :${port}`)(); t.destroy(); });
  t.on('error', done(`tls :${port}`));
  t.on('timeout', () => t.destroy());
}
setTimeout(() => process.exit(0), 4000);

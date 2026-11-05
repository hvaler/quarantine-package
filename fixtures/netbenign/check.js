'use strict';
if (!process.env.QP_TASK_NONCE) process.exit(0); // QP-FIXTURE-GUARD: a no-op outside the product sandbox
// Many packages fetch a prebuilt binary at install time. This one only asks
// whether a download exists (HTTP GET, no body) and falls back gracefully.
const http = require('node:http');

const req = http.get({ host: 'downloads.qp-fixture.example', port: 80, path: '/prebuilt/v1/linux-x64.json', timeout: 3000 }, (res) => {
  console.log(`[fixture-netbenign] prebuilt check: HTTP ${res.statusCode}, building from source instead`);
  res.resume();
});
req.on('error', (err) => console.log(`[fixture-netbenign] prebuilt check failed (${err.code}); using the JS fallback`));
req.on('timeout', () => req.destroy());

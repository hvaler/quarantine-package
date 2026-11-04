// C13 / X7: the client IP used for rate limiting.
// X-Forwarded-For is honoured ONLY when the TCP peer is a configured trusted proxy
// (default: none, so XFF is ignored). Through trusted proxies, the client is the
// right-most XFF entry that is not itself a trusted proxy. Anything malformed in the
// chain stops the walk and the last trusted hop's view (the peer) is used, so a
// spoofed or injected header can never pick an arbitrary address.
'use strict';

const net = require('node:net');

const strip = (ip) => String(ip || '').replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/, '$1');

function parseTrusted(list) {
  return new Set(String(list || '').split(',').map((s) => strip(s.trim())).filter((s) => net.isIP(s)));
}

function clientIp(peer, xffHeader, trusted) {
  const peerIp = strip(peer);
  if (!trusted.has(peerIp)) return peerIp; // untrusted peer: XFF ignored entirely
  if (xffHeader === undefined || xffHeader === null) return peerIp;
  // Several XFF headers are joined by Node with ", "; take the whole chain.
  const chain = String(Array.isArray(xffHeader) ? xffHeader.join(',') : xffHeader).split(',').map((s) => strip(s.trim()));
  let candidate = peerIp;
  for (let i = chain.length - 1; i >= 0; i--) {
    const hop = chain[i];
    if (!net.isIP(hop)) return candidate; // malformed: stop, keep the last trustworthy view
    if (!trusted.has(hop)) return hop;
    candidate = hop;
  }
  return candidate;
}

module.exports = { clientIp, parseTrusted };

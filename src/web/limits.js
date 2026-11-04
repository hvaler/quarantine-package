// C13: per-IP rate limit (in memory) and the daily cap on model calls (persisted).
// Time comes from an injected clock (X2).
'use strict';

const fs = require('node:fs');
const net = require('node:net');

// One client can hold a whole IPv6 /64, so IPv6 is limited per /64 prefix; IPv4
// (and IPv4-mapped IPv6) per address.
function rateKey(ip) {
  const s = String(ip || '');
  if (net.isIPv4(s)) return s;
  if (!net.isIPv6(s)) return `other:${s.slice(0, 64)}`;
  const [head, tail = ''] = s.toLowerCase().split('::');
  const h = head ? head.split(':') : [];
  const t = tail ? tail.split(':') : [];
  if (t.length && net.isIPv4(t[t.length - 1])) return t[t.length - 1]; // ::ffff:a.b.c.d
  const groups = s.includes('::') ? [...h, ...Array(8 - h.length - t.length).fill('0'), ...t] : h;
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}
const path = require('node:path');

// Per-key limit plus a global ceiling on admissions in the same window. The key map
// is hard-bounded: when full, the least recently used key is evicted (eviction can
// only forget a key, while the global ceiling still holds).
function createRateLimit({ max, windowMs, clock, globalMax = Infinity, maxKeys = 10000 }) {
  const hits = new Map(); // key -> timestamps (Map order = least recently used first)
  let all = [];
  return {
    take(ip) {
      const now = clock.now();
      const key = rateKey(ip);
      all = all.filter((t) => now - t < windowMs);
      const list = (hits.get(key) || []).filter((t) => now - t < windowMs);
      hits.delete(key);
      if (list.length >= max) { hits.set(key, list); return { ok: false, retryAfterS: Math.max(1, Math.ceil((windowMs - (now - list[0])) / 1000)) }; }
      if (all.length >= globalMax) { hits.set(key, list); return { ok: false, global: true, retryAfterS: Math.max(1, Math.ceil((windowMs - (now - all[0])) / 1000)) }; }
      list.push(now);
      all.push(now);
      hits.set(key, list);
      while (hits.size > maxKeys) hits.delete(hits.keys().next().value);
      return { ok: true };
    },
  };
}

// The day is the UTC date. State survives restarts in a small JSON file.
function createDailyCap({ cap, file, clock }) {
  const day = () => new Date(clock.now()).toISOString().slice(0, 10);
  let state = { day: day(), used: 0 };
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (s && typeof s.day === 'string' && Number.isInteger(s.used) && s.used >= 0) state = s;
  } catch (_) { /* first start */ }
  const roll = () => { if (state.day !== day()) state = { day: day(), used: 0 }; };
  const save = () => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(state));
    fs.renameSync(tmp, file);
  };
  return {
    remaining() { roll(); return Math.max(0, cap - state.used); },
    exhausted() { roll(); return state.used >= cap; },
    add(n) { roll(); state.used += Math.max(0, n | 0); save(); },
    snapshot() { roll(); return { day: state.day, used: state.used, cap }; },
  };
}

module.exports = { createRateLimit, createDailyCap, rateKey };

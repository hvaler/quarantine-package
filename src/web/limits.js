// C13: per-IP rate limit (in memory) and the daily cap on model calls (persisted).
// Time comes from an injected clock (X2).
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function createRateLimit({ max, windowMs, clock }) {
  const hits = new Map(); // ip -> timestamps
  return {
    take(ip) {
      const now = clock.now();
      const list = (hits.get(ip) || []).filter((t) => now - t < windowMs);
      if (list.length >= max) { hits.set(ip, list); return { ok: false, retryAfterS: Math.ceil((windowMs - (now - list[0])) / 1000) }; }
      list.push(now);
      hits.set(ip, list);
      if (hits.size > 10000) for (const [k, v] of hits) if (!v.some((t) => now - t < windowMs)) hits.delete(k);
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

module.exports = { createRateLimit, createDailyCap };

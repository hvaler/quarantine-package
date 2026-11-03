// Verdict engine (C4, DEC-2r1). A pure function of the observations.
// It takes no explanation, model output or free text as input: any such
// field passed in is ignored by construction.
'use strict';

const HOME = '/home/qp';
const ALLOWED_WRITE_ROOTS = ['/work', '/tmp'];
const DOCKER_SOCKETS = ['/var/run/docker.sock', '/run/docker.sock'];
const CREDENTIAL_PATHS = ['.npmrc', '.ssh', '.aws', '.docker', '.config/gcloud'].map((p) => `${HOME}/${p}`);
const KEY_LIKE = /(^|[_-])(API_?KEY|KEY|TOKEN|SECRET|PASS(WORD)?|PASSWD|CREDENTIALS?)([_-]|$)/i;
const COUNTED_ACTORS = new Set(['package', 'unattributed']);

// Lexical normalisation (".", "..", "//"). Anything not absolute (relative,
// empty, "unresolved:...") yields null and is never inside an allowed area.
function norm(p) {
  if (typeof p !== 'string' || !p.startsWith('/')) return null;
  const parts = [];
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop(); else parts.push(seg);
  }
  return `/${parts.join('/')}`;
}
const under = (p, root) => { const n = norm(p); return n !== null && (n === root || n.startsWith(`${root}/`)); };
const counted = (o) => COUNTED_ACTORS.has(o.actor);
const isNet = (o) => o.kind === 'net-dns' || o.kind === 'net-tcp' || o.kind === 'net-udp' || o.kind === 'net-other' || o.kind === 'net-listen';

// Ordered by severity; the first tier with a firing rule wins.
const RULES = Object.freeze([
  {
    id: 'a', tier: 'do-not-install',
    text: 'write attempt (successful or blocked) outside /work, /tmp and HOME',
    match: (o) => o.kind === 'fs-write' && counted(o)
      && !ALLOWED_WRITE_ROOTS.some((r) => under(o.path, r)) && !under(o.path, HOME),
  },
  {
    id: 'b', tier: 'do-not-install',
    text: 'access attempt to docker.sock or a credential path',
    match: (o) => o.kind === 'fs-access' && counted(o)
      && (DOCKER_SOCKETS.includes(norm(o.path)) || CREDENTIAL_PATHS.some((c) => under(o.path, c))),
  },
  {
    id: 'c1', tier: 'do-not-install',
    text: 'read of a key-like env var, or of /proc/<pid>/environ',
    match: (o) => counted(o) && ((o.kind === 'env-read' && KEY_LIKE.test(String(o.name || ''))) || o.kind === 'proc-environ'),
  },
  {
    id: 'd', tier: 'do-not-install',
    text: 'network attempt carrying a payload (plaintext HTTP body/POST/PUT/PATCH/chunked, or raw bytes on non-TLS TCP)',
    match: (o) => o.kind === 'net-tcp' && counted(o) && o.payload === true,
  },
  {
    id: 'e', tier: 'do-not-install',
    text: 'task ended by a resource or time limit',
    match: (o) => o.kind === 'limit',
  },
  {
    id: 'f', tier: 'review',
    text: 'network attempt (DNS, TCP or UDP, TLS included; TLS bodies are not inspected), or a bind/listen in the sandbox network namespace',
    match: (o) => isNet(o) && counted(o),
  },
  {
    id: 'g', tier: 'review',
    text: 'write inside HOME',
    match: (o) => o.kind === 'fs-write' && counted(o) && under(o.path, HOME),
  },
  {
    id: 'h', tier: 'review',
    text: 'package could not be loaded by the harness or the require() fallback',
    match: (o) => o.kind === 'load' && o.ok !== true,
  },
  {
    id: 'i', tier: 'review',
    text: 'observation incomplete: a completeness marker is missing',
    match: (o) => o.kind === 'completeness' && o.ok !== true,
  },
]);

const TIERS = ['do-not-install', 'review'];

// decide({ observations }) -> { verdict, rules: [{ id, tier, text, observationIds }] }
// `install` requires that no rule fired AND a successful load observation exists
// AND every completeness observation is ok (absent markers are added by the caller).
function decide(input, rules = RULES) {
  const observations = Array.isArray(input && input.observations) ? input.observations : [];
  const fired = [];
  for (const rule of rules) {
    const ids = observations.filter((o) => rule.match(o)).map((o) => o.id);
    if (ids.length) fired.push({ id: rule.id, tier: rule.tier, text: rule.text, observationIds: ids });
  }
  if (!observations.some((o) => o.kind === 'load')) {
    fired.push({ id: 'h', tier: 'review', text: rules.find((r) => r.id === 'h')?.text || 'no load observation', observationIds: [] });
  }
  let verdict = 'install';
  for (const tier of TIERS) {
    if (fired.some((r) => r.tier === tier)) { verdict = tier; break; }
  }
  return { verdict, rules: fired };
}

module.exports = { decide, RULES, KEY_LIKE, HOME, DOCKER_SOCKETS, CREDENTIAL_PATHS };

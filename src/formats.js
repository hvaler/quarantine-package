// S7 F1: export formats derived from the stored receipt only (no re-run, no model).
// DEC-D6-3: neither the pre-run explanation nor the outcome explanation appears in
// any of these formats; they are deterministic functions of the receipt.
//
// Markdown (F1a): made for a pull request comment. Every string the package
// controls (paths, host names, URL paths, names) is shown inside an inline code
// span after control, bidi and zero-width characters are made visible as \u{..}
// escapes and the length is capped, so it cannot start a new line, a heading, a
// table, a link, an image, a mention or HTML. Everything outside code spans is
// fixed text from this module or from verdict.RULES.
//
// SARIF 2.1.0 (F1b): one reportingDescriptor per verdict rule a..i; one result per
// fired rule; level per VERDICT (error for do-not-install, warning for review);
// no result for install. Each result is located at the analysed package's
// package.json, because GitHub code scanning requires a location.
'use strict';

const { RULES } = require('./verdict');

const VERDICT_TEXT = Object.freeze({ install: 'INSTALL', review: 'REVIEW', 'do-not-install': 'DO NOT INSTALL' });
const RULE_LETTERS = Object.freeze(['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i']);
const RULE_NAMES = Object.freeze({
  a: 'WriteOutsideAllowedAreas', b: 'CredentialOrDockerSocketAccess', c: 'KeyLikeEnvRead', d: 'NetworkPayload',
  e: 'ResourceOrTimeLimit', f: 'NetworkAttempt', g: 'WriteInsideHome', h: 'PackageNotLoaded', i: 'ObservationIncomplete',
});
const MD_FIELD = 200;
const MD_LIST = 15;
const letterOf = (id) => String(id || '').charAt(0);
const ruleByLetter = (l) => RULES.find((r) => letterOf(r.id) === l);

// ---------------------------------------------------------------- Markdown

// Control (C0, C1, DEL), line/paragraph separators, bidi controls, zero-width and
// BOM characters become visible escapes; nothing else is changed.
const INVISIBLE_RANGES = [[0x00, 0x1f], [0x7f, 0x9f], [0xad], [0x61c], [0x115f, 0x1160], [0x180e], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f], [0x3164], [0xfe00, 0xfe0f], [0xfeff], [0xffa0], [0xfff0, 0xfffb]];
const cp = (c) => String.fromCharCode(92) + 'u{' + c.toString(16) + '}';
const INVISIBLE = new RegExp(`[${INVISIBLE_RANGES.map(([a, b]) => (b === undefined ? cp(a) : `${cp(a)}-${cp(b)}`)).join('')}]`, 'gu');
function visible(s, max = MD_FIELD) {
  let t = String(s == null ? '' : s);
  const extra = t.length > max ? t.length - max : 0;
  if (extra) t = t.slice(0, max);
  t = t.replace(INVISIBLE, (c) => `\\u{${c.codePointAt(0).toString(16)}}`);
  return extra ? `${t}…(+${extra} chars)` : t;
}

// Inline code span that holds any text: the fence is one backtick longer than the
// longest backtick run inside, padded with spaces (CommonMark 6.1).
function code(s, max) {
  const t = visible(s, max);
  if (!t) return '` `';
  const runs = t.match(/`+/g) || [];
  const fence = '`'.repeat(Math.max(0, ...runs.map((r) => r.length)) + 1);
  return `${fence} ${t} ${fence}`;
}

const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
const yn = (v) => (v === true ? 'yes' : v === false ? 'no' : 'unknown');

function receiptLinks(id, baseUrl) {
  if (!/^[a-f0-9]{10}$/.test(String(id || ''))) return null;
  const b = String(baseUrl || '').replace(/\/+$/, '');
  return { page: `${b}/r/${id}`, json: `${b}/api/receipts/${id}`, md: `${b}/r/${id}.md`, sarif: `${b}/api/receipts/${id}.sarif` };
}

// Limitations that applied to THIS receipt, chosen by fixed conditions; the text is
// the receipt's own knownLimitations entry (product text), shown escaped as plain text.
function appliedLimitations(rc) {
  const obs = rc.observations || [];
  const known = Array.isArray(rc.knownLimitations) ? rc.knownLimitations : [];
  const pick = (needle) => known.find((l) => typeof l === 'string' && l.includes(needle));
  const out = [];
  if (obs.some((o) => o.sni || (o.kind === 'net-tcp' && o.proto === 'tls'))) out.push(pick('TLS bodies are not inspected'));
  if (obs.some((o) => o.kind === 'net-udp')) out.push(pick('UDP other than DNS'));
  if (obs.some((o) => o.kind === 'env-read' || o.kind === 'env-enumerate')) out.push(pick('Env-var reads are seen by the in-process preload only'));
  if (obs.some((o) => typeof o.path === 'string' && o.path.startsWith('unresolved'))) out.push(pick('reported as unresolved'));
  out.push(pick('Side channels inside the kernel'));
  const failed = Object.entries(rc.completeness || {}).filter(([, v]) => v && v.ok === false).map(([k]) => k);
  if (failed.length) out.push(`Observation incomplete: ${failed.join(', ')} failed, so the run may have missed activity.`);
  return out.filter(Boolean);
}

// Plain text outside code spans: escape every Markdown-active ASCII punctuation
// character and drop line breaks (used only for product text such as limitations).
const mdText = (s) => visible(s, 400).replace(/[\\`*_{}[\]()#+\-.!|<>~&@:]/g, (c) => `\\${c}`);

function toMarkdown(rc, { baseUrl = '' } = {}) {
  const pkg = rc.package || {};
  const name = pkg.name || pkg.requested || 'unknown';
  const L = [];
  const links = receiptLinks(rc.taskId, baseUrl);
  L.push(`### Quarantine Package receipt for ${code(`${name}@${pkg.version || '?'}`)}`);
  L.push('');
  if (rc.status === 'completed' && VERDICT_TEXT[rc.verdict]) {
    L.push(`**Verdict: ${VERDICT_TEXT[rc.verdict]}** (computed by fixed rules from what the sandbox observed)`);
  } else {
    L.push(`**Verdict: none** (the task was aborted: ${code(rc.abortReason || rc.status || 'unknown', 60)})`);
  }
  L.push('');
  const fired = rc.rulesFired || [];
  L.push('**Rules fired**');
  L.push('');
  if (!fired.length) L.push('- none');
  for (const r of fired) {
    const l = letterOf(r.id);
    const def = ruleByLetter(l);
    const tier = r.tier === 'do-not-install' || r.tier === 'review' ? r.tier : 'unknown';
    L.push(`- (${RULE_LETTERS.includes(l) ? l : '?'}) ${tier}: ${def ? mdText(def.text) : 'unknown rule'} (${plural((r.observationIds || []).length, 'observation')})`);
  }
  L.push('');
  const pvo = rc.predictionVsObserved || [];
  L.push('**Prediction vs observed**');
  L.push('');
  if (!pvo.length) L.push('- no prediction');
  for (const c of pvo) {
    const dim = { network: 'network', filesOutsidePackage: 'files outside the package', childProcesses: 'child processes' }[c.dimension] || 'other';
    const st = ['match', 'mismatch', 'unknown'].includes(c.status) ? c.status : 'unknown';
    const det = (c.observedDetail || []).slice(0, 3).map((d) => code(d)).join(', ');
    L.push(`- ${dim}: predicted ${yn(c.predicted)}, observed ${yn(c.observed)} (${st})${det ? `: ${det}` : ''}`);
  }
  L.push('');
  const sink = (rc.network && rc.network.sinkholeLog) || [];
  L.push(`**Sinkhole** (nothing left the sandbox): ${plural(sink.length, 'network attempt')}`);
  L.push('');
  for (const x of sink.slice(0, MD_LIST)) {
    const type = ['dns', 'tcp', 'udp', 'tls', 'http'].includes(x.type) ? x.type : 'other';
    const host = x.host || x.dstName || x.name || x.sni || x.dstIp || '';
    const parts = [type, code(host)];
    if (x.method) parts.push(code(x.method, 16));
    if (x.path) parts.push(code(x.path));
    const bytes = Number.isFinite(x.payloadBytes) ? x.payloadBytes : Number.isFinite(x.bytesReceived) ? x.bytesReceived : null;
    L.push(`- ${parts.join(' ')}${bytes !== null ? `, ${bytes} bytes` : ''}`);
  }
  if (sink.length > MD_LIST) L.push(`- and ${sink.length - MD_LIST} more (see the full receipt)`);
  if (sink.length) L.push('');
  const left = rc.teardown && Array.isArray(rc.teardown.leftoversForTask) ? rc.teardown.leftoversForTask : null;
  L.push(left === null ? '**Sandbox destroyed:** unknown' : left.length ? `**Sandbox destroyed:** NO, ${plural(left.length, 'object')} left` : '**Sandbox destroyed:** yes, no container, network or volume of this task remains');
  L.push('');
  const lim = appliedLimitations(rc);
  if (lim.length) {
    L.push('**Limitations that applied**');
    L.push('');
    for (const l of lim) L.push(`- ${mdText(l)}`);
    L.push('');
  }
  if (links) L.push(`Receipt: ${links.page} · JSON: ${links.json}`);
  else L.push('Receipt: (no valid receipt id)');
  return `${L.join('\n')}\n`;
}

// ---------------------------------------------------------------- SARIF

const SARIF_SCHEMA = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json';
const LEVEL = Object.freeze({ 'do-not-install': 'error', review: 'warning' });
const capText = (s, n = 300) => { s = String(s == null ? '' : s); return s.length > n ? `${s.slice(0, n)}…` : s; };

function toSarif(rc, { baseUrl = '' } = {}) {
  const pkg = rc.package || {};
  const links = receiptLinks(rc.taskId, baseUrl);
  const rules = RULE_LETTERS.map((l) => {
    const def = ruleByLetter(l);
    return {
      id: l,
      name: RULE_NAMES[l],
      shortDescription: { text: `Rule (${l}): ${def.text}` },
      fullDescription: { text: `Quarantine Package rule (${l}), tier ${def.tier}: ${def.text}. The verdict is the most severe tier among the rules that fired.` },
      defaultConfiguration: { level: LEVEL[def.tier] },
      properties: { tier: def.tier },
    };
  });
  const level = LEVEL[rc.verdict];
  const results = rc.status === 'completed' && level ? (rc.rulesFired || []).filter((r) => RULE_LETTERS.includes(letterOf(r.id))).map((r) => {
    const l = letterOf(r.id);
    const n = (r.observationIds || []).length;
    return {
      ruleId: l,
      ruleIndex: RULE_LETTERS.indexOf(l),
      level,
      // DEC-D6-11: the message names the rule's own tier; the level follows the verdict.
      message: { text: capText(`Rule (${l}), tier ${ruleByLetter(l).tier}, fired for ${pkg.name || 'the package'}@${pkg.version || '?'} (${n} observation${n === 1 ? '' : 's'}): ${ruleByLetter(l).text}. Verdict: ${rc.verdict}.${links ? ` Receipt: ${links.page}` : ''}`, 600) },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'package.json' }, region: { startLine: 1 } } }],
      partialFingerprints: { quarantinePackage: capText(`${pkg.name || ''}@${pkg.version || ''}/${l}`, 300) },
      properties: { verdict: rc.verdict, receiptId: rc.taskId || null, observationIds: (r.observationIds || []).slice(0, 50) },
    };
  }) : [];
  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Quarantine Package', informationUri: 'https://github.com/hvaler/quarantine-package', semanticVersion: '1.2.0', rules } },
      automationDetails: { id: `quarantine-package/${capText(pkg.name || 'unknown', 200)}/` },
      results,
      properties: {
        verdict: rc.verdict || null, status: rc.status || null, receiptId: rc.taskId || null,
        package: { name: pkg.name || null, version: pkg.version || null },
        ...(links ? { receipt: links.page, receiptJson: links.json } : {}),
      },
    }],
  };
}

// ---------------------------------------------------------------- CLI exit codes (F1c)

// DEC-D6-7: a completed analysis exits with its verdict (0 install / 10 review /
// 20 do-not-install); every other outcome has its own fixed non-zero code.
const FORMATS = Object.freeze(['json', 'md', 'sarif']);
const VERDICT_EXIT = Object.freeze({ install: 0, review: 10, 'do-not-install': 20 });
const EXIT = Object.freeze({ usage: 2, downloadAborted: 3, infrastructure: 4, interrupted: 130 });
function exitFor(receipt, exitCode) {
  if (receipt && receipt.status === 'completed' && Object.hasOwn(VERDICT_EXIT, receipt.verdict)) return VERDICT_EXIT[receipt.verdict];
  if (receipt && receipt.status === 'completed') return EXIT.infrastructure; // completed without a known verdict: never 0
  return exitCode === 0 || !Number.isInteger(exitCode) ? EXIT.infrastructure : exitCode; // aborted: 2, 3, 4 or 130 as before, never 0
}

module.exports = { toMarkdown, toSarif, visible, code, mdText, appliedLimitations, receiptLinks, FORMATS, VERDICT_EXIT, EXIT, exitFor, SARIF_SCHEMA, RULE_NAMES };

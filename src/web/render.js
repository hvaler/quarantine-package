// HTML rendering. S3-SEC (a): every package- or model-controlled string goes through
// esc(); nothing dynamic is ever put in an attribute that can carry a URL or script
// (no href/src from receipt data). Client script is a fixed file served with a CSP
// nonce and only sets textContent. Styles live in one nonce'd <style> block: the CSP
// blocks style="" attributes, so none is used. Icons are fixed inline SVG.
'use strict';

const esc = (v) => String(v === null || v === undefined ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/`/g, '&#96;');

const STYLE = `
:root{--bg:#fbfbf9;--fg:#1d1d1b;--mut:#5c5b55;--line:#dcdad2;--card:#fff;--sunk:#f2f1ec;--acc:#25589f;--on:#fff;--ok:#1f6f43;--okb:#e4f1e8;--warn:#8a5a00;--warnb:#f7ecd6;--bad:#a12622;--badb:#f8e2e0;--neu:#55534d;--neub:#eae9e3;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecebe6;--mut:#a8a69e;--line:#373632;--card:#1d1d1b;--sunk:#111110;--acc:#8db2ef;--on:#0e1d36;--ok:#5fc08a;--okb:#14281c;--warn:#e0aa45;--warnb:#2c2311;--bad:#ef7b74;--badb:#351a18;--neu:#bdbbb2;--neub:#2a2a27}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-text-size-adjust:100%}
a{color:var(--acc);text-underline-offset:2px}a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.wrap{max-width:1040px;margin:0 auto;padding:0 16px}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 0;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:8px;font-weight:650;color:var(--fg);text-decoration:none}
.brand .i{color:var(--acc)}
.top nav{display:flex;gap:16px;font-size:14px}
h1{font-size:clamp(28px,5vw,40px);line-height:1.15;letter-spacing:-.02em;margin:40px 0 8px;font-weight:680;overflow-wrap:anywhere}
h2{display:flex;align-items:center;gap:8px;font-size:17px;margin:0 0 12px;font-weight:650}
h2 .i{color:var(--mut)}
h3{font-size:15px;margin:0;font-weight:650;overflow-wrap:anywhere}
p{margin:0}
.lede{color:var(--mut);font-size:17px;max-width:640px}
.mono,code,pre,input[type=text]{font-family:var(--mono)}
.i{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round;flex:none}
.i-s{width:14px;height:14px;stroke-width:2.25}
.i-l{width:44px;height:44px;stroke-width:1.5}
.analyse{margin:28px 0 0;padding:16px;background:var(--card);border:1px solid var(--line);border-radius:12px}
.analyse label{display:block;font-size:13px;color:var(--mut);margin-bottom:8px}
.row{display:flex;flex-wrap:wrap;gap:8px}
.row input{flex:1 1 220px;min-width:0;height:48px;padding:0 14px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:16px}
.row input:focus{border-color:var(--acc)}
.hint{font-size:13px;color:var(--mut);margin-top:8px}
.btn,#link a{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;padding:0 16px;border:1px solid var(--acc);border-radius:8px;background:var(--acc);color:var(--on);font:inherit;font-weight:600;cursor:pointer;text-decoration:none}
.btn:hover,#link a:hover{filter:brightness(1.1)}
.btn-lg{height:48px;padding:0 22px}
.btn-q{background:transparent;color:var(--acc)}
.notice{display:flex;gap:10px;align-items:flex-start;padding:10px 14px;margin:16px 0 0;border:1px solid var(--line);border-radius:8px;background:var(--sunk);font-size:14px;color:var(--mut)}
.sec{margin:48px 0 0}
.kick{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);font-weight:600;margin:0 0 12px}
.sub{color:var(--mut);font-size:14px;margin:-4px 0 14px}
.steps{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;counter-reset:s}
.steps li{position:relative;padding:14px;border:1px solid var(--line);border-radius:10px;background:var(--card);counter-increment:s}
.steps li::before{content:counter(s);position:absolute;top:12px;right:14px;font:12px var(--mono);color:var(--mut)}
.steps .i{color:var(--acc);margin-bottom:6px}
.steps p{font-size:13px;color:var(--mut);margin-top:2px}
.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.card{display:flex;flex-direction:column;gap:10px;margin:0;padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--card)}
.card-h{display:flex;align-items:center;gap:10px;min-width:0}
.card-h .i{color:var(--acc)}
.card p{font-size:14px;color:var(--mut);flex:1}
.card-f{display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap}
.exp{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--mut)}
.tag{align-self:flex-start;font-size:11px;padding:1px 8px;border:1px dashed var(--mut);border-radius:99px;color:var(--mut)}
.badge{display:inline-flex;align-items:center;gap:5px;padding:1px 9px 1px 7px;border:1px solid currentColor;border-radius:99px;font-size:12px;font-weight:650;line-height:20px;white-space:nowrap}
.ok{color:var(--ok);background:var(--okb)}.warn{color:var(--warn);background:var(--warnb)}.bad{color:var(--bad);background:var(--badb)}.neu{color:var(--neu);background:var(--neub)}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{display:inline-flex;align-items:center;gap:8px;min-height:44px;padding:0 14px 0 8px;border:1px solid var(--line);border-radius:99px;background:var(--card);color:var(--fg);text-decoration:none;font-size:13px}
.chip:hover{border-color:var(--acc)}
.foot{margin:64px 0 0;padding:20px 0 40px;border-top:1px solid var(--line);font-size:13px;color:var(--mut)}
.panel{padding:20px;border:1px solid var(--line);border-radius:12px;background:var(--card)}
.cols{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr);gap:16px;align-items:start}
.status{display:flex;gap:14px;align-items:flex-start}
.pulse{width:10px;height:10px;margin-top:9px;border-radius:50%;background:var(--acc);flex:none;animation:pl 1.6s ease-in-out infinite}
@keyframes pl{50%{opacity:.2}}
#status{font-weight:650;font-size:18px}
#detail{color:var(--mut);overflow-wrap:anywhere}
#link{margin-top:16px}#link:empty{display:none}
.stepper{list-style:none;margin:0;padding:0}
.stepper li{position:relative;display:grid;grid-template-columns:36px minmax(0,1fr);gap:12px;padding-bottom:18px}
.stepper li:not(:last-child)::after{content:"";position:absolute;left:17px;top:40px;bottom:4px;width:2px;background:var(--line)}
.dot{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;border:1px solid var(--line);background:var(--bg);color:var(--acc)}
.stepper p{color:var(--mut);font-size:14px}
.kv{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:4px 16px;margin:0;font-size:14px}
.kv dt{color:var(--mut)}.kv dd{margin:0;overflow-wrap:anywhere}
.hero{margin:32px 0 0;padding:24px;border:1px solid currentColor;border-radius:14px;display:grid;grid-template-columns:auto minmax(0,1fr);gap:20px}
.hero .kick{margin:0 0 2px}
.hero .v{font-size:clamp(30px,6vw,44px);font-weight:720;letter-spacing:-.02em;line-height:1.1;margin:0}
.hero .pkg{font-size:18px;color:var(--fg);margin:6px 0 14px;overflow-wrap:anywhere}
.hero .kv,.hero .note{color:var(--fg)}
.hero .note{margin-top:14px;font-size:14px;font-weight:600}
.tw{overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.tall{max-height:560px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{text-align:left;vertical-align:top;padding:9px 12px;border-bottom:1px solid var(--line)}
th{position:sticky;top:0;font-size:12px;font-weight:600;color:var(--mut);background:var(--sunk);white-space:nowrap}
td{overflow-wrap:anywhere}
tbody tr:last-child td{border-bottom:0}
.n{text-align:right;font-variant-numeric:tabular-nums}
td.mono,.kv .mono{font-size:13px}
.dim{color:var(--mut)}
.feat{padding:20px;border:2px solid var(--acc);border-radius:14px;background:var(--card)}
.feat .tw{background:var(--bg)}
.score{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 14px}
.sink{border:2px dashed var(--fg);border-radius:14px;overflow:hidden}
.sink-h{padding:14px 16px;background:repeating-linear-gradient(135deg,var(--neub) 0 6px,var(--card) 6px 12px);border-bottom:2px dashed var(--fg)}
.sink-h h2{margin:0}
.sink-h p{font-weight:600;margin-top:4px}
.sink .tw{border:0;border-radius:0}
pre{margin:0;padding:14px;background:var(--sunk);border:1px solid var(--line);border-radius:10px;white-space:pre-wrap;overflow-wrap:anywhere;font-size:13px;line-height:1.6}
.done{display:flex;gap:10px;align-items:center;padding:14px 16px;border:1px solid var(--line);border-radius:10px;background:var(--card)}
.done .i{color:var(--ok)}.done.no .i{color:var(--bad)}
details{border:1px solid var(--line);border-radius:10px;padding:0 16px;color:var(--mut);margin-top:12px}
summary{cursor:pointer;padding:12px 0;font-weight:600}
summary .i{vertical-align:-4px;margin-right:6px}
details[open]{padding-bottom:16px}
details ul{margin:0;padding-left:20px;font-size:14px}
.empty{padding:12px;color:var(--mut)}
@media (max-width:820px){.grid,.steps{grid-template-columns:repeat(2,minmax(0,1fr))}.cols{grid-template-columns:minmax(0,1fr)}}
@media (max-width:540px){.grid,.steps{grid-template-columns:minmax(0,1fr)}.hero{grid-template-columns:minmax(0,1fr);padding:18px}.top nav a+a{display:none}.feat{padding:14px}}
@media (prefers-reduced-motion:reduce){.pulse{animation:none}}`;

// Fixed icon set (stroke paths, 24x24). Never built from data.
const ICON_PATHS = {
  box: '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9zM4 7.5l8 4.5 8-4.5M12 12v9"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5v.5"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  chip: '<rect x="7" y="7" width="10" height="10" rx="2"/><path d="M10 3v4M14 3v4M10 17v4M14 17v4M3 10h4M3 14h4M17 10h4M17 14h4"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M12 15h5"/>',
  receipt: '<path d="M6 3h12v18l-3-2-3 2-3-2-3 2zM9 8h6M9 12h6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
  alert: '<path d="M12 3l10 18H2zM12 10v5M12 18v.5"/>',
  fork: '<circle cx="6" cy="5" r="2"/><circle cx="18" cy="5" r="2"/><circle cx="12" cy="19" r="2"/><path d="M6 7v2a3 3 0 0 0 3 3h6a3 3 0 0 0 3-3V7M12 12v5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  check: '<path d="M5 12.5l4.5 4.5L19 7"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  x: '<path d="M6 6l12 12M18 6L6 18"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  q: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.7M12 17v.5"/>',
  list: '<path d="M9 6h11M9 12h11M9 18h11M4 6h1M4 12h1M4 18h1"/>',
  swap: '<path d="M4 8h15l-4-4M20 16H5l4 4"/>',
  sink: '<path d="M12 3v8M8 7l4 4 4-4M3 14h5l1.5 3h5l1.5-3h5v6H3z"/>',
  lines: '<path d="M4 6h16M4 11h16M4 16h10"/>',
  table: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M9 10v10"/>',
  trash: '<path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/>',
  gauge: '<path d="M4 17a8 8 0 1 1 16 0M12 17l4-5"/>',
  shieldOk: '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
  shieldEye: '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><circle cx="12" cy="12" r="2.5"/>',
  shieldX: '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/>',
  shieldDash: '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z"/><path d="M9 12h6"/>',
};
const icon = (name, cls = 'i') => `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name] || ''}</svg>`;

// Badge for a known value; anything else is shown escaped in a neutral badge.
const BADGES = {
  install: ['ok', 'check'], review: ['warn', 'eye'], 'do-not-install': ['bad', 'x'], contained: ['neu', 'lock'],
  match: ['ok', 'check'], mismatch: ['bad', 'x'], unknown: ['neu', 'q'], yes: ['neu', 'lock'],
};
const badge = (value, prefix = '') => {
  const [cls, ic] = BADGES[value] || ['neu', 'q'];
  return `<span class="badge ${cls}">${icon(ic, 'i i-s')}${esc(prefix)}${esc(value)}</span>`;
};

const FOOT = '<footer class="foot">Runs on one Vultr Cloud Compute VM · LLM calls via Vultr Serverless Inference · MIT · <a href="https://github.com/hvaler/quarantine-package">GitHub</a></footer>';

function page({ title, nonce, body, script = false, home = false }) {
  const nav = home ? '<a href="#how">How it works</a>' : '<a href="/">New analysis</a>';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><style nonce="${esc(nonce)}">${STYLE}</style></head><body><div class="wrap">
<header class="top"><a class="brand" href="/">${icon('box')}Quarantine Package</a><nav>${nav}<a href="https://github.com/hvaler/quarantine-package">GitHub</a></nav></header>
<main>${body}</main>${FOOT}</div>${script ? `<script nonce="${esc(nonce)}" src="/static/progress.js"></script>` : ''}</body></html>`;
}

// One-click demos. `label` is what the job page and the receipt call the task.
const DEMOS = Object.freeze([
  { id: 'express', label: 'express@4.21.2', kind: 'registry', spec: 'express@4.21.2', icon: 'globe', title: 'express@4.21.2', mono: true, desc: 'A popular benign web framework.', expect: 'install' },
  { id: 'fastify', label: 'fastify@5.12.4', kind: 'registry', spec: 'fastify@5.12.4', icon: 'box', title: 'fastify@5.12.4', mono: true, desc: "Real dependency from the author's payments project.", expect: 'install' },
  { id: 'netbenign', label: 'Install script that downloads (repo fixture)', kind: 'fixture', fixture: 'netbenign', icon: 'download', title: 'Install script that downloads', desc: 'A legitimate-looking script that fetches a binary.', expect: 'review' },
  { id: 'hostile', label: 'Hostile package (repo fixture)', kind: 'fixture', fixture: 'hostile', icon: 'alert', title: 'Hostile package', desc: 'Writes to /etc, reaches for docker.sock and credentials, POSTs data out.', expect: 'do-not-install' },
  { id: 'forkbomb', label: 'Fork bomb (repo fixture)', kind: 'fixture', fixture: 'forkbomb', icon: 'fork', title: 'Fork bomb', desc: 'Spawns processes without limit; the pids limit stops it in seconds.', expect: 'do-not-install' },
  { id: 'loop', label: 'Infinite loop (repo fixture)', kind: 'fixture', fixture: 'loop', icon: 'clock', title: 'Infinite loop', desc: 'Never exits; the 60 s wall clock kills it.', expect: 'do-not-install' },
]);

const EXAMPLES = Object.freeze([['install', 'd6fbf70332'], ['review', 'd5af19b228'], ['do-not-install', '8b42cfb93e']]);

const STEPS = [
  ['download', 'Download', 'Fetched from the registry with install scripts off.', 'The tarball is fetched with install scripts off. Nothing runs yet.'],
  ['chip', 'Model predicts', 'Vultr Serverless Inference predicts behaviour and writes a test harness.', 'Vultr Serverless Inference predicts what the package will do and writes a test harness.'],
  ['terminal', 'Sandbox run', 'Installed and run in a disposable hardened sandbox, traced. Network ends at a sinkhole.', 'Install and harness run in a disposable hardened sandbox, traced. The only network ends at a logging sinkhole.'],
  ['receipt', 'Verdict + receipt', 'Fixed rules decide. The receipt is public.', 'Fixed rules turn observations into a verdict. The sandbox is destroyed and the receipt is published.'],
];

function homePage({ nonce, notice }) {
  const cards = DEMOS.map((d) => `<form class="card" method="post" action="/analyse"><input type="hidden" name="demo" value="${esc(d.id)}">
<div class="card-h">${icon(d.icon)}<h3${d.mono ? ' class="mono"' : ''}>${esc(d.title)}</h3></div>
${d.kind === 'fixture' ? '<span class="tag">repo fixture, never published</span>' : ''}<p>${esc(d.desc)}</p>
<div class="card-f"><span class="exp">Expected ${badge(d.expect)}</span><button class="btn btn-q" type="submit">Run demo</button></div></form>`).join('\n');
  const chips = EXAMPLES.map(([v, id]) => `<a class="chip" href="/r/${id}">${badge(v)}<span class="mono">/r/${id}</span></a>`).join('');
  return page({
    title: 'Quarantine Package',
    nonce,
    home: true,
    body: `<h1>Quarantine Package</h1>
<p class="lede">Run an npm package in a sealed sandbox on Vultr and see what it tried to do, before you install it.</p>
${notice ? `<p class="notice" role="status">${icon('info')}<span>${esc(notice)}</span></p>` : ''}
<form class="analyse" method="post" action="/analyse"><label for="spec">npm package as <span class="mono">name@version</span></label>
<div class="row"><input id="spec" type="text" name="spec" placeholder="e.g. lodash@4.17.21" required maxlength="214" autocomplete="off" spellcheck="false"><button class="btn btn-lg" type="submit">Analyse${icon('arrow')}</button></div>
<p class="hint">Every run ends in a public receipt page you can link to.</p></form>
<section class="sec" id="how" aria-labelledby="how-h"><p class="kick" id="how-h">How it works</p>
<ol class="steps">${STEPS.map(([ic, h, short]) => `<li>${icon(ic)}<h3>${h}</h3><p>${short}</p></li>`).join('')}</ol></section>
<section class="sec" aria-labelledby="demo-h"><p class="kick" id="demo-h">One-click demos</p>
<p class="sub">Each demo runs the full pipeline on a known package or a fixture from the repo.</p>
<div class="grid">${cards}</div></section>
<section class="sec" aria-labelledby="ex-h"><p class="kick" id="ex-h">Example receipts</p><div class="chips">${chips}</div></section>`,
  });
}

function jobPage({ nonce, job }) {
  return page({
    title: 'Analysis in progress',
    nonce,
    script: true,
    body: `<h1>Analysing <span class="mono">${esc(job.label)}</span></h1>
<p class="lede">Job <span class="mono" id="job" data-job="${esc(job.id)}">${esc(job.id)}</span>. This page updates by itself; you can leave it open.</p>
<div class="cols sec"><section class="panel" aria-labelledby="st-h"><p class="kick" id="st-h">Status</p>
<div class="status" aria-live="polite"><span class="pulse" aria-hidden="true"></span><div><p id="status">${esc(job.status)}</p><p id="detail"></p></div></div>
<div id="link"></div></section>
<section class="panel" aria-labelledby="wh-h"><p class="kick" id="wh-h">What is happening</p>
<ol class="stepper">${STEPS.map(([ic, h, , long]) => `<li><span class="dot">${icon(ic)}</span><div><h3>${h}</h3><p>${long}</p></div></li>`).join('')}</ol></section></div>`,
  });
}

function messagePage({ nonce, title, message, status }) {
  return page({ title, nonce, body: `<h1>${esc(title)}</h1><p class="notice">${icon('info')}<span>${esc(message)}</span></p>${status ? `<p class="hint">${esc(status)}</p>` : ''}<p class="sec"><a class="btn" href="/">Back</a></p>` });
}

// A table of escaped cells. Each column: [header, value(row), {cls, html}] where html marks a
// cell already rendered from a fixed template (badges); everything else is escaped here.
const table = (list, cols) => `<div class="tw${list.length > 12 ? ' tall' : ''}"><table><thead><tr>${cols.map(([h, , o = {}]) => `<th${o.cls ? ` class="${o.cls}"` : ''}>${esc(h)}</th>`).join('')}</tr></thead><tbody>${list.map((r) => `<tr>${cols.map(([, f, o = {}]) => `<td${o.cls ? ` class="${o.cls}"` : ''}>${o.html ? f(r) : esc(f(r))}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
const none = (t) => `<p class="empty">${esc(t)}</p>`;

const HERO = {
  install: ['ok', 'shieldOk', 'Install'],
  review: ['warn', 'shieldEye', 'Review'],
  'do-not-install': ['bad', 'shieldX', 'Do not install'],
};

// L-18 (S6): the page shows at most 300 observations and 200 sinkhole entries.
// When it truncates, a visible note gives the counts and links to the full JSON.
// The link is built only from an id in the server's receipt-id format; anything
// else gets the note without a link (no URL attribute from unchecked data).
const MAX_OBS_SHOWN = 300;
const MAX_SINK_SHOWN = 200;
const RECEIPT_ID = /^[a-f0-9]{10}$/;
function truncNote(shown, total, taskId) {
  if (total <= shown) return '';
  const id = String(taskId || '');
  const where = RECEIPT_ID.test(id)
    ? `<a href="/api/receipts/${id}">/api/receipts/${id}</a>`
    : `/api/receipts/${esc(id)}`;
  return `<p class="hint trunc">${icon('info')}<span>showing ${shown} of ${total}; full list in ${where}</span></p>`;
}

function receiptPage({ nonce, receipt }) {
  const r = receipt || {};
  const verdict = r.verdict || r.status || 'unknown';
  const [hcls, hicon, htext] = HERO[verdict] || ['neu', 'shieldDash', String(verdict)];
  const allObs = (r.observations || []).filter((o) => o.kind !== 'completeness');
  const allSink = r.network && Array.isArray(r.network.sinkholeLog) ? r.network.sinkholeLog : [];
  const obs = allObs.slice(0, MAX_OBS_SHOWN);
  const sink = allSink.slice(0, MAX_SINK_SHOWN);
  const pvo = r.predictionVsObserved || [];
  const left = r.teardown && Array.isArray(r.teardown.leftoversForTask) ? r.teardown.leftoversForTask : null;
  const destroyed = left === null ? 'unknown' : left.length === 0 ? 'yes: no container, network or volume of this task remains' : `NO: ${left.join(', ')}`;
  const pkg = r.package || {};
  const counts = ['match', 'mismatch', 'unknown'].map((s) => [s, pvo.filter((x) => x.status === s).length]).filter(([, n]) => n);
  const blocked = (x) => (x.blocked === true ? badge('yes') : x.blocked === undefined ? '' : `<span class="dim">${x.blocked === false ? 'no' : esc(x.blocked)}</span>`);
  const body = `<section class="hero ${hcls}" aria-labelledby="v-h">${icon(hicon, 'i i-l')}<div>
<p class="kick">Verdict</p><h1 class="v" id="v-h">${esc(htext)}</h1>
<p class="pkg mono">${esc(pkg.requested)}${pkg.version ? ` (version ${esc(pkg.version)})` : ''}</p>
<dl class="kv"><dt>Receipt</dt><dd class="mono">${esc(r.taskId)}</dd><dt>Started</dt><dd class="mono">${esc(r.startedAt)}</dd><dt>Finished</dt><dd class="mono">${esc(r.finishedAt)}</dd>
${pkg.source === 'fixture' ? '<dt>Source</dt><dd>repo fixture, never published</dd>' : ''}${r.abortReason ? `<dt>Aborted</dt><dd class="mono">${esc(r.abortReason)} ${esc(r.abortDetail)}</dd>` : ''}</dl>
<p class="note">Computed by fixed rules from what was observed. The model's explanation never changes it.</p></div></section>
<section class="sec" aria-labelledby="r-h"><h2 id="r-h">${icon('list')}Rules that fired</h2>${(r.rulesFired || []).length ? table(r.rulesFired, [['Rule', (x) => x.id, { cls: 'mono' }], ['Tier', (x) => badge(String(x.tier)), { html: true }], ['Why', (x) => x.text], ['Observations', (x) => (x.observationIds || []).join(', '), { cls: 'mono' }]]) : none('None.')}</section>
<section class="sec feat" aria-labelledby="p-h"><h2 id="p-h">${icon('swap')}Prediction vs observed</h2>
<p class="sub">Before the run, the model on Vultr Serverless Inference read the package and predicted its behaviour. The sandbox then recorded what happened.</p>
${counts.length ? `<div class="score">${counts.map(([s, n]) => badge(s, `${n} `)).join('')}</div>` : ''}
${pvo.length ? table(pvo, [['Dimension', (x) => x.dimension], ['Predicted', (x) => (x.predicted === null ? 'unknown' : String(x.predicted))], ['Observed', (x) => String(x.observed)], ['Result', (x) => badge(String(x.status)), { html: true }], ['Details', (x) => (x.observedDetail || []).join(', '), { cls: 'mono' }]]) : none('No prediction.')}</section>
<section class="sec sink" aria-labelledby="s-h"><div class="sink-h"><h2 id="s-h">${icon('sink')}Sinkhole log</h2><p>Network attempts. Nothing left the sandbox.</p></div>
${truncNote(sink.length, allSink.length, r.taskId)}${sink.length ? table(sink, [['Type', (x) => x.type], ['Destination', (x) => x.dstName || x.name || x.host || x.dstIp || '', { cls: 'mono' }], ['Port', (x) => x.dstPort || '', { cls: 'n mono' }], ['SNI', (x) => x.sni || '', { cls: 'mono' }], ['Method / path', (x) => [x.method, x.path].filter(Boolean).join(' '), { cls: 'mono' }], ['Payload bytes', (x) => (x.payloadBytes === undefined ? '' : x.payloadBytes), { cls: 'n mono' }]]) : none('No network attempt.')}</section>
<section class="sec" aria-labelledby="e-h"><h2 id="e-h">${icon('lines')}Explanation <span class="badge neu">model, informational</span></h2><pre>${esc(r.explanation && r.explanation.text ? r.explanation.text : 'none')}</pre>
<p class="hint">Model status: ${esc(r.model ? r.model.status : 'none')}${r.model && r.model.missing && r.model.missing.length ? `; missing: ${esc(r.model.missing.join(', '))}` : ''}</p></section>
<section class="sec" aria-labelledby="o-h"><h2 id="o-h">${icon('table')}Observations <span class="dim">${obs.length}</span></h2>${truncNote(obs.length, allObs.length, r.taskId)}${obs.length ? table(obs, [['Id', (x) => x.id, { cls: 'mono' }], ['Kind', (x) => x.kind, { cls: 'mono' }], ['Actor', (x) => x.actor, { cls: 'mono' }], ['Target', (x) => x.path || x.dest || x.name || (x.extra && x.extra.name) || '', { cls: 'mono' }], ['Blocked', blocked, { html: true }]]) : none('None.')}</section>
<section class="sec" aria-labelledby="d-h"><h2 id="d-h">${icon('trash')}Sandbox destroyed</h2><p class="done${left && left.length ? ' no' : ''}">${icon(left && left.length ? 'x' : 'check')}<span>${esc(destroyed)}</span></p></section>
<section class="sec" aria-label="Limits and known limitations">
<details><summary>${icon('gauge')}Limits applied</summary><pre>${esc(JSON.stringify(r.limits || {}, null, 2))}</pre></details>
<details><summary>${icon('info')}Known limitations</summary><ul>${(r.knownLimitations || []).map((l) => `<li>${esc(l)}</li>`).join('')}</ul></details></section>`;
  return page({ title: `Receipt ${r.taskId || ''}`, nonce, body });
}

// Fixed client script: polls the job and writes text only.
const PROGRESS_JS = `(()=>{const el=document.getElementById('job');const id=el&&el.dataset.job;if(!id)return;
const st=document.getElementById('status'),dt=document.getElementById('detail'),ln=document.getElementById('link');
async function tick(){try{const r=await fetch('/api/jobs/'+encodeURIComponent(id),{cache:'no-store'});const j=await r.json();
st.textContent=j.status+(j.position?(' (position '+j.position+' in queue)'):'');dt.textContent=j.message||'';
if(j.receiptId&&/^[a-f0-9]{10}$/.test(j.receiptId)){ln.textContent='';const a=document.createElement('a');a.href='/r/'+j.receiptId;a.textContent='Open the receipt';ln.appendChild(a);return;}
if(j.status==='failed'||j.status==='rejected')return;}catch(e){dt.textContent='connection lost, retrying';}setTimeout(tick,1500);}tick();})();`;

module.exports = { esc, homePage, jobPage, receiptPage, messagePage, DEMOS, PROGRESS_JS };

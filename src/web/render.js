// HTML rendering. S3-SEC (a): every package- or model-controlled string goes through
// esc(); nothing dynamic is ever put in an attribute that can carry a URL or script
// (no href/src from receipt data). Client script is a fixed file served with a CSP
// nonce and only sets textContent.
'use strict';

const esc = (v) => String(v === null || v === undefined ? '' : v)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/`/g, '&#96;');

const STYLE = `
:root{--bg:#fbfbf9;--fg:#1d1d1b;--muted:#5f5f5a;--line:#d9d8d2;--ok:#1f6f43;--warn:#8a5a00;--bad:#a12622;--card:#fff}
@media (prefers-color-scheme: dark){:root{--bg:#161615;--fg:#ecebe6;--muted:#a3a29b;--line:#383733;--ok:#5fc08a;--warn:#e0aa45;--bad:#ef7b74;--card:#1f1f1d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
p.muted,.muted{color:var(--muted)}form{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}
input[type=text]{flex:1;min-width:200px;padding:9px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);font:inherit}
button{padding:9px 14px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);font:inherit;cursor:pointer}
.demos{display:flex;gap:8px;flex-wrap:wrap}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px;margin:10px 0}
.verdict{font-size:20px;font-weight:600}.v-install{color:var(--ok)}.v-review{color:var(--warn)}.v-do-not-install{color:var(--bad)}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:5px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px;max-height:320px;overflow:auto}
.notice{border-left:3px solid var(--warn);padding:8px 12px;background:var(--card)}a{color:inherit}`;

function page({ title, nonce, body, script = false }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title><style nonce="${esc(nonce)}">${STYLE}</style></head><body><main>${body}</main>${script ? `<script nonce="${esc(nonce)}" src="/static/progress.js"></script>` : ''}</body></html>`;
}

const DEMOS = Object.freeze([
  { id: 'express', label: 'express@4.21.2', kind: 'registry', spec: 'express@4.21.2', note: 'a popular benign package' },
  { id: 'netbenign', label: 'Install script that downloads (repo fixture)', kind: 'fixture', fixture: 'netbenign', note: 'repo fixture, never published: a legitimate-looking install script that checks for a binary download (expected: review, explained)' },
  { id: 'hostile', label: 'Hostile package (repo fixture)', kind: 'fixture', fixture: 'hostile', note: 'repo fixture, never published: writes /etc, home, looks for docker.sock, counts key-like env vars, POSTs to recolector.example.com' },
]);

function homePage({ nonce, notice }) {
  const demos = DEMOS.map((d) => `<form method="post" action="/analyse"><input type="hidden" name="demo" value="${esc(d.id)}"><button type="submit">${esc(d.label)}</button></form>`).join('');
  return page({
    title: 'Quarantine Package',
    nonce,
    body: `<h1>Quarantine Package</h1><p class="muted">Runs an npm package in a sealed sandbox and tells you what it tried to do before you install it.</p>
${notice ? `<p class="notice">${esc(notice)}</p>` : ''}
<form method="post" action="/analyse"><input type="text" name="spec" placeholder="name@version, e.g. lodash@4.17.21" required maxlength="214" autocomplete="off"><button type="submit">Analyse</button></form>
<h2>One-click demos</h2><div class="demos">${demos}</div>
<ul class="muted">${DEMOS.map((d) => `<li>${esc(d.label)}: ${esc(d.note)}</li>`).join('')}</ul>`,
  });
}

function jobPage({ nonce, job }) {
  return page({
    title: 'Analysis in progress',
    nonce,
    script: true,
    body: `<h1>Analysing ${esc(job.label)}</h1><p class="muted">Job <span id="job" data-job="${esc(job.id)}">${esc(job.id)}</span></p>
<div class="card"><div id="status">${esc(job.status)}</div><div id="detail" class="muted"></div></div>
<p class="muted">This page updates by itself. When the analysis ends it links to the public receipt.</p><p id="link"></p>`,
  });
}

function messagePage({ nonce, title, message, status }) {
  return page({ title, nonce, body: `<h1>${esc(title)}</h1><p class="notice">${esc(message)}</p>${status ? `<p class="muted">${esc(status)}</p>` : ''}<p><a href="/">Back</a></p>` });
}

const rows = (list, cols) => `<table><tr>${cols.map(([h]) => `<th>${esc(h)}</th>`).join('')}</tr>${list.map((r) => `<tr>${cols.map(([, f]) => `<td>${esc(f(r))}</td>`).join('')}</tr>`).join('')}</table>`;

function receiptPage({ nonce, receipt }) {
  const r = receipt || {};
  const verdict = r.verdict || r.status || 'unknown';
  const obs = (r.observations || []).filter((o) => o.kind !== 'completeness').slice(0, 300);
  const sink = (r.network && r.network.sinkholeLog || []).slice(0, 200);
  const pvo = r.predictionVsObserved || [];
  const left = r.teardown && Array.isArray(r.teardown.leftoversForTask) ? r.teardown.leftoversForTask : null;
  const destroyed = left === null ? 'unknown' : left.length === 0 ? 'yes: no container, network or volume of this task remains' : `NO: ${left.join(', ')}`;
  const pkg = r.package || {};
  const body = `<h1>Receipt ${esc(r.taskId)}</h1>
<p class="muted">${esc(pkg.requested)} ${pkg.version ? `(version ${esc(pkg.version)})` : ''} · started ${esc(r.startedAt)} · finished ${esc(r.finishedAt)}</p>
<div class="card"><div class="verdict v-${esc(String(verdict).replace(/[^a-z-]/g, ''))}">Verdict: ${esc(verdict)}</div>
${r.abortReason ? `<div>Aborted: ${esc(r.abortReason)} ${esc(r.abortDetail)}</div>` : ''}
<div class="muted">The verdict is computed by fixed rules from what was observed. The model's explanation below never changes it.</div></div>
<h2>Rules that fired</h2>${(r.rulesFired || []).length ? rows(r.rulesFired, [['Rule', (x) => x.id], ['Tier', (x) => x.tier], ['Why', (x) => x.text], ['Observations', (x) => (x.observationIds || []).join(', ')]]) : '<p class="muted">None.</p>'}
<h2>Prediction vs observed</h2>${pvo.length ? rows(pvo, [['Dimension', (x) => x.dimension], ['Predicted', (x) => x.predicted === null ? 'unknown' : String(x.predicted)], ['Observed', (x) => String(x.observed)], ['Result', (x) => x.status], ['Details', (x) => (x.observedDetail || []).join(', ')]]) : '<p class="muted">No prediction.</p>'}
<h2>Explanation (model, informational)</h2><pre>${esc(r.explanation && r.explanation.text ? r.explanation.text : 'none')}</pre>
<p class="muted">Model status: ${esc(r.model ? r.model.status : 'none')}${r.model && r.model.missing && r.model.missing.length ? `; missing: ${esc(r.model.missing.join(', '))}` : ''}</p>
<h2>Observations</h2>${obs.length ? rows(obs, [['Id', (x) => x.id], ['Kind', (x) => x.kind], ['Actor', (x) => x.actor], ['Target', (x) => x.path || x.dest || x.name || (x.extra && x.extra.name) || ''], ['Blocked', (x) => (x.blocked === undefined ? '' : String(x.blocked))]]) : '<p class="muted">None.</p>'}
<h2>Sinkhole log (network attempts, nothing left the sandbox)</h2>${sink.length ? rows(sink, [['Type', (x) => x.type], ['Destination', (x) => x.dstName || x.name || x.host || x.dstIp || ''], ['Port', (x) => x.dstPort || ''], ['SNI', (x) => x.sni || ''], ['Method / path', (x) => [x.method, x.path].filter(Boolean).join(' ')], ['Payload bytes', (x) => (x.payloadBytes === undefined ? '' : x.payloadBytes)]]) : '<p class="muted">No network attempt.</p>'}
<h2>Limits applied</h2><pre>${esc(JSON.stringify(r.limits || {}, null, 2))}</pre>
<h2>Sandbox destroyed</h2><p>${esc(destroyed)}</p>
<h2>Known limitations</h2><ul class="muted">${(r.knownLimitations || []).map((l) => `<li>${esc(l)}</li>`).join('')}</ul>`;
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

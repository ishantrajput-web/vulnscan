(function () {
'use strict';
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SEV = ['critical', 'high', 'medium', 'low', 'info'];
let token = '';
try {
  const m = /[#&]t=([\w-]+)/.exec(location.hash);
  if (m) { sessionStorage.setItem('vs_t', m[1]); history.replaceState(null, '', location.pathname); }
  token = sessionStorage.getItem('vs_t') || '';
} catch (e) { /* storage blocked */ }

let preset = 'quick', info = {}, jobId = null, logN = 0, timer = null, selected = null;

async function api(path, opts) {
  opts = opts || {};
  const r = await fetch(path, { method: opts.method || 'GET', headers: { 'X-Token': token, 'Content-Type': 'application/json' },
    body: opts.body ? JSON.stringify(opts.body) : undefined });
  let data = {};
  try { data = await r.json(); } catch (e) { /* not json */ }
  if (!r.ok) { const err = new Error(data.error || ('HTTP ' + r.status)); err.code = data.code; throw err; }
  return data;
}
const badge = (sev) => '<span class="badge s-' + esc(sev) + '">' + esc(String(sev).toUpperCase()) + '</span>';
const setPill = (txt, cls) => { const p = $('#pill'); p.textContent = txt; p.className = 'pill ' + (cls || ''); };

// ---------- form
function detectMode() {
  const v = $('#target').value.trim(); const el = $('#mode');
  if (!v) { el.textContent = 'Enter a target'; return; }
  const hasUrl = /https?:\/\//i.test(v);
  const hasNet = v.split(/[,\s]+/).some((t) => t && !/^https?:\/\//i.test(t));
  el.textContent = hasUrl && hasNet ? 'Network scan + website analysis' : hasUrl ? 'Website analysis' :
    (/^[\d.\/,\-\s:a-f]+$/i.test(v) ? 'Network scan' : 'Network scan + web checks');
}
document.querySelectorAll('.preset').forEach((b) => b.addEventListener('click', () => {
  document.querySelectorAll('.preset').forEach((x) => x.classList.remove('active'));
  b.classList.add('active'); preset = b.dataset.p;
  if (preset === 'deep' && info.nmap) $('#nmap').checked = true;
}));
$('#target').addEventListener('input', detectMode);
$('#target').addEventListener('keydown', (e) => { if (e.key === 'Enter') $('#start').click(); });

function showErr(msg) { const e = $('#formerr'); e.textContent = msg; e.classList.toggle('hidden', !msg); }

$('#start').addEventListener('click', async () => {
  showErr('');
  const custom = $('#ports').value.trim();
  const ports = custom || ({ quick: 'top', standard: 'well-known', deep: 'all' }[preset]);
  try {
    const r = await api('/api/scan', { method: 'POST', body: {
      target: $('#target').value, ports: ports, authorized: $('#auth').checked, phrase: $('#phrase').value,
      offline: $('#offline').checked, nmap: $('#nmap').checked, cve: $('#cve').checked, web: $('#web').checked,
      no_ping: $('#noping').checked, with_ports: $('#withports').checked } });
    beginLive(r.id);
  } catch (e) {
    showErr(e.message);
    if (e.code === 'phrase_required') $('#phrase').focus();
  }
});
$('#cancel').addEventListener('click', async () => { if (jobId) { try { await api('/api/jobs/' + jobId + '/cancel', { method: 'POST', body: {} }); } catch (e) { /* ignore */ } } });
$('#refresh').addEventListener('click', loadHistory);

// ---------- live view
function beginLive(id) {
  jobId = id; logN = 0; $('#term').innerHTML = '';
  $('#livetitle').textContent = 'Scan in progress'; $('#cancel').classList.remove('hidden');
  $('#live').classList.remove('hidden'); $('#results').classList.add('hidden'); $('#newscan').classList.add('hidden');
  setPill('Scanning...', 'run'); poll();
}
function addLogs(logs) {
  const term = $('#term'); const stick = term.scrollTop + term.clientHeight >= term.scrollHeight - 30;
  logs.forEach((l) => {
    const d = document.createElement('div'); d.className = l.l;
    d.innerHTML = '<span class="t">' + esc(l.t.toFixed(1).padStart(6)) + 's </span>' + esc(l.m);
    term.appendChild(d);
  });
  if (stick) term.scrollTop = term.scrollHeight;
}
async function poll() {
  clearTimeout(timer);
  let s;
  try { s = await api('/api/jobs/' + jobId + '?since=' + logN); }
  catch (e) { addLogs([{ t: 0, l: 'warn', m: 'Connection issue: ' + e.message + ' (retrying)' }]); timer = setTimeout(poll, 1500); return; }
  logN = s.n_logs; addLogs(s.logs);
  const ph = s.phase; $('#phasename').textContent = ph[2] ? ('Step ' + ph[0] + ' of ' + ph[1] + ': ' + ph[2]) : 'Starting...';
  let dots = ''; for (let i = 1; i <= ph[1]; i++) dots += '<div class="dot ' + (i < ph[0] ? 'done' : i === ph[0] ? 'act' : '') + '"></div>';
  $('#steps').innerHTML = dots;
  const p = s.progress, fill = $('#barfill');
  if (p[1] > 0) { fill.classList.remove('indet'); fill.style.width = Math.min(100, Math.round(p[0] * 100 / p[1])) + '%'; $('#proglabel').textContent = p[0] + ' / ' + p[1] + ' ' + p[2]; }
  else { fill.classList.add('indet'); $('#proglabel').textContent = ''; }
  $('#elapsed').textContent = s.elapsed.toFixed(0) + 's elapsed';
  if (s.status === 'running') { timer = setTimeout(poll, 700); return; }
  fill.classList.remove('indet'); fill.style.width = '100%';
  $('#livetitle').textContent = 'Scan log'; $('#cancel').classList.add('hidden');
  setPill(s.status === 'done' ? 'Done' : s.status === 'cancelled' ? 'Cancelled (partial)' : 'Finished with errors', s.status === 'done' ? 'ok' : '');
  await showResult(jobId, s.files);
  loadHistory();
}

// ---------- results
function bar(counts) {
  const items = SEV.slice(0, 4).filter((k) => (counts[k] || 0) > 0);
  if (!items.length) return '<div class="sub nonefound">None found</div>';
  return '<div class="sevbar">' + items.map((k) => '<div class="s-' + k + '" data-flex="' + counts[k] + '">' + esc(k) + ' ' + counts[k] + '</div>').join('') + '</div>';
}
function kv(rows) { return '<table>' + rows.map((r) => '<tr><th class="k">' + esc(r[0]) + '</th><td>' + esc(r[1]) + '</td></tr>').join('') + '</table>'; }
function findingsTable(list) {
  const f = list.filter((x) => x.severity !== 'info').sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
  if (!f.length) return '';
  return '<table><tr><th>Severity</th><th>Finding</th><th>Remediation</th></tr>' + f.map((x) =>
    '<tr><td>' + badge(x.severity) + '</td><td><b>' + esc(x.title) + '</b><div class="sub">' + esc(x.detail) + '</div></td><td>' + esc(x.remediation) + '</td></tr>').join('') + '</table>';
}
function cveTable(list) {
  if (!list.length) return '';
  const l = list.slice().sort((a, b) => (b.cvss || 0) - (a.cvss || 0)).slice(0, 25);
  return '<table><tr><th>CVE</th><th>CVSS</th><th>Description</th></tr>' + l.map((v) =>
    '<tr><td class="mono">' + esc(v.cve_id) + '<div class="sub">' + esc(v.source) + '</div></td><td>' + badge(v.severity) + ' ' + (v.cvss == null ? '' : esc(v.cvss)) + '</td><td>' + esc((v.description || '').slice(0, 300)) + '</td></tr>').join('') + '</table>';
}
function webBlock(w) {
  const rows = [['URL', w.url]];
  if (w.error) rows.push(['Result', 'Could not analyse: ' + w.error]);
  else {
    if (w.final_url && w.final_url !== w.url) rows.push(['Final URL', w.final_url]);
    rows.push(['HTTP status', w.status]); if (w.title) rows.push(['Page title', w.title]);
    if (w.server) rows.push(['Server', w.server]);
    if (w.techs && w.techs.length) rows.push(['Technologies', w.techs.map((t) => (t.product + ' ' + (t.version || '')).trim()).join(', ')]);
    const t = w.tls || {};
    if (t.version) rows.push(['TLS', t.version + ' | trusted: ' + (t.valid ? 'yes' : 'NO' + (t.error ? ' (' + t.error + ')' : '')) + (t.not_after ? ' | expires ' + t.not_after + ' (' + t.days_left + ' days)' : '')]);
    if (w.dns && ('spf' in w.dns)) rows.push(['Email security', 'SPF: ' + (w.dns.spf ? 'yes' : 'NO') + ', DMARC: ' + (w.dns.dmarc ? 'yes' : 'NO')]);
    if (w.exposed && w.exposed.length) rows.push(['Exposed paths', w.exposed.map((e) => e.path).join(', ')]);
  }
  return '<div class="web"><h3>' + (w.standalone ? 'Website' : 'Web service') + ' ' + badge(w.risk_level) + ' <span class="sub">score ' + esc(w.risk_score) + '/100</span></h3>' +
    kv(rows) + findingsTable(w.findings || []) + cveTable(w.vulns || []) + '</div>';
}
function hostCard(h, webs, open) {
  const pf = []; (h.ports || []).forEach((p) => (p.findings || []).forEach((f) => pf.push(f)));
  const pv = []; (h.ports || []).forEach((p) => (p.vulns || []).forEach((v) => pv.push(v)));
  let ports = '<div class="sub">No open ports found in the scanned range.</div>';
  if ((h.ports || []).length) ports = '<table><tr><th>Port</th><th>Service</th><th>Product / version</th><th>Banner</th></tr>' + h.ports.map((p) =>
    '<tr><td>' + esc(p.port) + '/tcp</td><td>' + esc(p.service) + (p.tls ? ' <span class="sub">(TLS)</span>' : '') + '</td><td>' + esc(((p.product || '') + ' ' + (p.version || '')).trim() || '-') +
    '</td><td class="mono">' + esc((p.banner || '').replace(/\n/g, ' ').slice(0, 110)) + '</td></tr>').join('') + '</table>';
  return '<details class="asset"' + (open ? ' open' : '') + '><summary>' + badge(h.risk_level) + '<b>' + esc(h.ip) + '</b>' +
    (h.hostname ? '<span class="sub">' + esc(h.hostname) + '</span>' : '') + '<span class="sub">OS: ' + esc(h.os_guess) + '</span><span class="sub">score ' + esc(h.risk_score) + '/100 | ' + (h.ports || []).length + ' open ports</span></summary><div class="body">' +
    ports + findingsTable(pf) + cveTable(pv) + webs.map(webBlock).join('') + '</div></details>';
}
function webCard(w, open) {
  return '<details class="asset"' + (open ? ' open' : '') + '><summary>' + badge(w.risk_level) + '<b>' + esc(w.url) + '</b><span class="sub">website | score ' + esc(w.risk_score) + '/100</span></summary><div class="body">' + webBlock(w) + '</div></details>';
}
function renderResult(d, id, files) {
  const s = d.summary || {}; const cs = s.cve_severity || {}, fs = s.finding_severity || {};
  const nfind = SEV.slice(0, 4).reduce((a, k) => a + (fs[k] || 0), 0);
  const names = { docx: 'Word / WPS (.docx)', pdf: 'PDF', html: 'HTML', json: 'JSON' };
  const dl = ['docx', 'pdf', 'html', 'json'].map((f) => (files || []).indexOf(f) >= 0
    ? '<a class="btn" href="/api/scans/' + esc(id) + '/download/' + f + '?t=' + encodeURIComponent(token) + '">Download ' + esc(names[f]) + '</a>' : '').join('');
  const hosts = (d.hosts || []).slice().sort((a, b) => b.risk_score - a.risk_score);
  const webs = d.webs || [];
  const cards = []; let first = true;
  hosts.forEach((h) => { cards.push(hostCard(h, webs.filter((w) => !w.standalone && w.host_ip === h.ip), first)); first = false; });
  webs.filter((w) => w.standalone).sort((a, b) => b.risk_score - a.risk_score).forEach((w) => { cards.push(webCard(w, first)); first = false; });
  $('#results').innerHTML = '<section class="card"><div class="row between"><h2>Results</h2><button class="btn small" id="newbtn" type="button">New scan</button></div>' +
    '<div class="sub">' + esc(d.targets) + ' | ' + esc(d.started) + ' | ' + esc((d.duration_s || 0).toFixed ? d.duration_s.toFixed(1) : d.duration_s) + 's' + ((d.meta || {}).interrupted ? ' | PARTIAL' : '') + '</div>' +
    '<div class="kpis"><div class="kpi"><b>' + (s.assets || 0) + '</b><span>Assets</span></div><div class="kpi"><b>' + (s.open_ports || 0) + '</b><span>Open ports</span></div>' +
    '<div class="kpi"><b>' + (s.cves || 0) + '</b><span>CVEs</span></div><div class="kpi"><b class="c-critical">' + (cs.critical || 0) + '</b><span>Critical CVEs</span></div>' +
    '<div class="kpi"><b class="c-high">' + (cs.high || 0) + '</b><span>High CVEs</span></div><div class="kpi"><b>' + nfind + '</b><span>Findings</span></div></div>' +
    '<div class="lbl">Known vulnerabilities by severity</div>' + bar(cs) + '<div class="lbl">Configuration &amp; exposure findings</div>' + bar(fs) +
    '<div class="dl">' + (dl || '<span class="sub">No report files available.</span>') + '</div></section>' +
    (cards.length ? cards.join('') : '<section class="card sub">No hosts or websites responded. Try "Skip ping" for hosts that block ICMP.</section>');
  document.querySelectorAll('[data-flex]').forEach((el) => { el.style.flex = el.getAttribute('data-flex'); });
  $('#results').classList.remove('hidden');
  $('#newbtn').addEventListener('click', () => { $('#results').classList.add('hidden'); $('#live').classList.add('hidden'); $('#newscan').classList.remove('hidden'); setPill('Ready', ''); selected = null; markSel(); });
  window.scrollTo({ top: 0, behavior: 'smooth' });
}
async function showResult(id, files) {
  try { const d = await api('/api/scans/' + id); selected = id; renderResult(d, id, files); markSel(); }
  catch (e) { $('#results').innerHTML = '<section class="card err">Could not load the result: ' + esc(e.message) + '</section>'; $('#results').classList.remove('hidden'); }
}

// ---------- history
let histCache = [];
function markSel() { document.querySelectorAll('.history .item').forEach((el) => el.classList.toggle('sel', el.dataset.id === selected)); }
async function loadHistory() {
  try { histCache = (await api('/api/scans')).scans; } catch (e) { return; }
  const h = $('#history');
  if (!histCache.length) { h.innerHTML = '<div class="muted">No scans yet.</div>'; return; }
  h.innerHTML = histCache.map((x) => {
    const lv = x.levels || {}; const chips = SEV.slice(0, 4).filter((k) => lv[k]).map((k) => '<span class="badge s-' + k + '">' + lv[k] + ' ' + k + '</span>').join(' ');
    return '<div class="item" data-id="' + esc(x.id) + '"><div class="t">' + esc(x.targets) + '</div><div class="d">' + esc(x.started) + ' | ' + esc(x.assets) + ' assets | ' + esc(x.cves) + ' CVEs</div><div>' + chips + '</div></div>';
  }).join('');
  h.querySelectorAll('.item').forEach((el) => el.addEventListener('click', () => {
    const it = histCache.find((x) => x.id === el.dataset.id);
    $('#newscan').classList.add('hidden'); $('#live').classList.add('hidden'); showResult(el.dataset.id, it ? it.files : []);
  }));
  markSel();
}

// ---------- boot
(async function boot() {
  try { info = await api('/api/info'); $('#ver').textContent = 'v' + info.version; $('#phrasehint').textContent = info.phrase; }
  catch (e) { showErr('Cannot talk to the scanner (' + e.message + '). Start it with:  py main.py --ui  and open the printed link.'); }
  detectMode(); loadHistory();
})();
})();

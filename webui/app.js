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
let cloud = false, connected = false, cloudBusy = false, cloudRecords = [], downloadUrls = [];
const CLOUD_MIME = {json:'application/json',html:'text/html',pdf:'application/pdf',docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document'};

function browserStore(action, record) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('vulnscan-history', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('scans', {keyPath:'id'});
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result, tx = db.transaction('scans', action === 'read' ? 'readonly' : 'readwrite');
      const store = tx.objectStore('scans'); let rows = [];
      if (action === 'clear') store.clear();
      else {
        if (record) store.put(record);
        const all = store.getAll();
        all.onsuccess = () => {
          rows = all.result.sort((a,b) => b.id.localeCompare(a.id));
          if (action === 'save') rows.slice(20).forEach((r) => store.delete(r.id));
          rows = rows.slice(0,20);
        };
      }
      tx.oncomplete = () => { db.close(); resolve(rows); };
      tx.onerror = tx.onabort = () => { db.close(); reject(tx.error || new Error('Browser storage unavailable')); };
    };
  });
}

function cloudHistory() {
  return cloudRecords.map((r) => ({id:r.id,targets:r.result.targets,started:r.result.started,
    assets:r.result.summary.assets,cves:r.result.summary.cves,levels:r.result.summary.host_levels,files:r.files}));
}

function reportLink(id, fmt) {
  if (!cloud) return '/api/scans/' + encodeURIComponent(id) + '/download/' + fmt + '?t=' + encodeURIComponent(token);
  const record = cloudRecords.find((r) => r.id === id);
  if (!record || !record.reports[fmt]) return '';
  const bytes = Uint8Array.from(atob(record.reports[fmt]), (c) => c.charCodeAt(0));
  const url = URL.createObjectURL(new Blob([bytes], {type:CLOUD_MIME[fmt]}));
  downloadUrls.push(url); return url;
}

async function api(path, opts) {
  opts = opts || {};
  if (cloud && !opts.method) {
    if (path === '/api/scans') return {scans:cloudHistory()};
    if (path.startsWith('/api/scans/')) {
      const record = cloudRecords.find((r) => r.id === path.split('/')[3]);
      if (!record) throw new Error('This scan is no longer saved in this browser.');
      return record.result;
    }
  }
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
  if (cloud) { el.textContent = 'Public website scan'; return; }
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
  if (cloud) { await startCloudScan(); return; }
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
$('#clearhistory').addEventListener('click', async () => {
  try { await browserStore('clear'); cloudRecords = []; downloadUrls.forEach(URL.revokeObjectURL); downloadUrls = []; $('#results').classList.add('hidden'); $('#newscan').classList.remove('hidden'); await loadHistory(); }
  catch (e) { showErr('Could not clear browser history: ' + e.message); }
});
$('#connect').addEventListener('click', connectCloud);
$('#accesskey').addEventListener('keydown', (e) => { if (e.key === 'Enter') connectCloud(); });

async function connectCloud() {
  token = $('#accesskey').value.trim() || token;
  try {
    await api('/api/session'); connected = true;
    try { sessionStorage.setItem('vs_t', token); } catch (e) { /* memory-only session */ }
    $('#accesskey').value = ''; $('#connectionstatus').textContent = 'Connected. Access key stays in this browser session.';
    $('#start').disabled = false; showErr(''); setPill('Ready', 'ok');
  } catch (e) { connected = false; $('#start').disabled = true; $('#connectionstatus').textContent = e.message; setPill('Not connected', ''); }
}

async function startCloudScan() {
  if (cloudBusy) return;
  if (!connected) { showErr('Connect with your operator access key first.'); return; }
  showErr(''); cloudBusy = true; $('#start').disabled = true;
  $('#live').classList.remove('hidden'); $('#cancel').classList.add('hidden'); $('#term').textContent = '';
  $('#livetitle').textContent = 'Website scan in progress'; $('#phasename').textContent = 'Checking website; results appear when complete (up to 90 seconds).';
  $('#barfill').classList.add('indet'); $('#steps').textContent = ''; $('#proglabel').textContent = 'Keep this tab open.';
  setPill('Scanning...', 'run'); const started = Date.now();
  const ticker = setInterval(() => { $('#elapsed').textContent = Math.floor((Date.now()-started)/1000) + 's elapsed'; }, 500);
  try {
    const record = await api('/api/scan', {method:'POST',body:{target:$('#target').value,
      authorized:$('#auth').checked,phrase:$('#phrase').value}});
    cloudRecords.unshift(record); cloudRecords = cloudRecords.slice(0,20);
    let storageWarning = '';
    try { cloudRecords = await browserStore('save', record); }
    catch (e) { storageWarning = 'Browser storage unavailable. Download reports now; this scan will be lost on reload.'; }
    selected = record.id; renderResult(record.result, record.id, record.files); await loadHistory();
    $('#newscan').classList.add('hidden'); $('#phasename').textContent = 'Website scan complete';
    const webError = (record.result.webs || []).some((w) => w.error);
    setPill(webError ? 'Website did not respond' : 'Done', webError ? '' : 'ok');
    $('#term').textContent = [storageWarning].concat(record.notes || [], (record.result.webs || []).map((w) => w.error || '')).filter(Boolean).join('\n') || 'Reports ready. History is stored only in this browser.';
  } catch (e) { showErr(e.message); $('#live').classList.add('hidden'); setPill('Scan failed', ''); if (e.code === 'auth') { connected = false; $('#connectionstatus').textContent = e.message; } }
  finally { clearInterval(ticker); cloudBusy = false; $('#start').disabled = !connected; $('#barfill').classList.remove('indet'); }
}

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
  downloadUrls.forEach(URL.revokeObjectURL); downloadUrls = [];
  const s = d.summary || {}; const cs = s.cve_severity || {}, fs = s.finding_severity || {};
  const nfind = SEV.slice(0, 4).reduce((a, k) => a + (fs[k] || 0), 0);
  const names = { docx: 'Word / WPS (.docx)', pdf: 'PDF', html: 'HTML', json: 'JSON' };
  const dl = ['docx', 'pdf', 'html', 'json'].map((f) => (files || []).indexOf(f) >= 0
    ? '<a class="btn" href="' + esc(reportLink(id, f)) + '" download="VulnScan_Report_' + esc(id) + '.' + f + '">Download ' + esc(names[f]) + '</a>' : '').join('');
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
  try {
    info = await api('/api/info'); $('#ver').textContent = 'v' + info.version; $('#phrasehint').textContent = info.phrase;
    cloud = info.mode === 'serverless';
    if (cloud) {
      $('#connection').classList.remove('hidden'); $('#start').disabled = true;
      $('#target').placeholder = 'https://your-website.com';
      $('#targethint').textContent = 'One public HTTP(S) website on port 80 or 443. Private-network scans require local mode.';
      $('#presets').previousElementSibling.classList.add('hidden'); $('#presets').classList.add('hidden'); $('.adv').classList.add('hidden');
      $('#historynote').classList.remove('hidden'); $('#clearhistory').classList.remove('hidden');
      $('#cloudnote').textContent = 'Website checks, offline CVE matching and report downloads. DNS email checks and network scans require local mode. History is stored in this browser.';
      $('#checksnote').innerHTML = '<h3>Hosted website checks</h3><p>HTTPS/TLS, security headers, cookies, known exposure paths and technology versions with offline CVE matching.</p><p class="muted">One public website per scan. Only scan websites you own or have written permission to test. Network and email DNS checks require local mode.</p>';
      try { cloudRecords = await browserStore('read'); } catch (e) { $('#historynote').textContent = 'Browser storage blocked. Download reports before closing this tab.'; }
      if (!info.configured) $('#connectionstatus').textContent = 'Owner setup: set SCANNER_ACCESS_TOKEN (32+ characters) in Vercel Environment Variables and redeploy.';
      else if (token) await connectCloud();
      else $('#connectionstatus').textContent = 'Enter the access key configured by the deployment owner.';
    }
  }
  catch (e) { showErr('Cannot talk to the scanner (' + e.message + '). Start it with:  py main.py --ui  and open the printed link.'); }
  detectMode(); loadHistory();
})();
})();

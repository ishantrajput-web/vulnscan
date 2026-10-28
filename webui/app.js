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
let cloud = false, cloudBusy = false, cloudRecords = [], downloadUrls = [], severityFilter = 'all';
const CLOUD_MIME = {json:'application/json',html:'text/html',pdf:'application/pdf',docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document'};

function browserStore(action, record) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('vulnscan-history', 1);
    request.onblocked = () => reject(new Error('Close other scanner tabs to enable browser history.'));
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
  const r = await fetch(path, { method: opts.method || 'GET', headers: Object.assign({'Content-Type': 'application/json'}, cloud ? {} : {'X-Token':token}),
    body: opts.body ? JSON.stringify(opts.body) : undefined });
  let data = {};
  try { data = await r.json(); } catch (e) { /* not json */ }
  if (!r.ok) { const err = new Error(data.error || ('HTTP ' + r.status)); err.code = data.code; throw err; }
  return data;
}
const badge = (sev) => '<span class="badge s-' + esc(sev) + '">' + esc(String(sev).toUpperCase()) + '</span>';
const setPill = (txt, cls) => {
  const p = $('#pill'); p.textContent = txt; p.className = 'pill ' + (cls || '');
  document.body.classList.toggle('scanning', cls === 'run');
  $('.radar-state').textContent = cls === 'run' ? 'ASSESSING' : 'STANDBY';
};

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
async function startCloudScan() {
  if (cloudBusy) return;
  if (!$('#auth').checked) { showErr('Confirm that you own this website or have written permission to test it.'); $('#auth').focus(); return; }
  if ($('#phrase').value.trim().toUpperCase() !== info.phrase) { showErr('Type ' + info.phrase + ' to confirm permission.'); $('#phrase').focus(); return; }
  let target = $('#target').value.trim();
  if (target && !target.includes('://')) target = 'https://' + target;
  try { const url = new URL(target); if (!['http:','https:'].includes(url.protocol) || url.username || url.password || (url.port && !['80','443'].includes(url.port))) throw new Error(); }
  catch (e) { showErr('Enter one public HTTP(S) website, for example https://your-website.com.'); $('#target').focus(); return; }
  $('#target').value = target;
  showErr(''); cloudBusy = true; $('#start').disabled = true;
  $('#results').classList.add('hidden');
  $('#live').classList.remove('hidden'); $('#cancel').classList.add('hidden'); $('#term').textContent = '';
  $('#livetitle').textContent = 'Reading the signals'; $('#phasename').textContent = 'Checking your website. Results arrive together when the assessment completes.';
  $('#barfill').style.width = '0%'; $('#barfill').classList.add('indet'); $('#steps').textContent = ''; $('#proglabel').textContent = 'Keep this tab open · up to 90 seconds'; $('#elapsed').textContent = '0s elapsed';
  setPill('Scanning...', 'run'); const started = Date.now();
  const ticker = setInterval(() => { $('#elapsed').textContent = Math.floor((Date.now()-started)/1000) + 's elapsed'; }, 500);
  try {
    const record = await api('/api/scan', {method:'POST',body:{target:target,
      authorized:$('#auth').checked,phrase:$('#phrase').value}});
    cloudRecords.unshift(record); cloudRecords = cloudRecords.slice(0,20);
    let storageWarning = '';
    try { cloudRecords = await browserStore('save', record); }
    catch (e) { storageWarning = 'Browser storage unavailable. Download reports now; this scan will be lost on reload.'; }
    selected = record.id; renderResult(record.result, record.id, record.files); await loadHistory();
    $('#newscan').classList.add('hidden'); $('#phasename').textContent = 'Assessment finished. Review the evidence below.'; $('#proglabel').textContent = 'Reports ready to download';
    const webError = (record.result.webs || []).some((w) => w.error);
    setPill(webError ? 'Website did not respond' : 'Done', webError ? '' : 'ok');
    $('#term').textContent = [storageWarning].concat(record.notes || [], (record.result.webs || []).map((w) => w.error || '')).filter(Boolean).join('\n') || 'Reports ready. History is stored only in this browser.';
  } catch (e) { showErr(e.message); $('#live').classList.add('hidden'); setPill('Try again', ''); }
  finally { clearInterval(ticker); cloudBusy = false; $('#start').disabled = false; $('#barfill').classList.remove('indet'); $('#barfill').style.width = '100%'; $('#elapsed').textContent = ((Date.now()-started)/1000).toFixed(1) + 's elapsed'; }
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
  const f = list.slice().sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity));
  if (!f.length) return '';
  return f.map((x) => '<article class="finding-card" data-severity="' + esc(x.severity) + '"><div class="finding-top">' + badge(x.severity) + '<h4>' + esc(x.title) + '</h4></div>' +
    '<p>' + esc(x.detail) + '</p>' + (x.remediation ? '<div class="finding-fix"><div class="eyebrow">RECOMMENDED ACTION</div><p>' + esc(x.remediation) + '</p></div>' : '') + '</article>').join('');
}
function cveTable(list) {
  if (!list.length) return '';
  const l = list.slice().sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
  return l.map((v) => '<article class="finding-card" data-severity="' + esc(v.severity) + '"><div class="finding-top">' + badge(v.severity) + '<h4>' + esc(v.cve_id) + (v.cvss == null ? '' : ' · CVSS ' + esc(v.cvss)) + '</h4></div><p>' + esc(v.description) + '</p><p class="sub">Source: ' + esc(v.source) + '. Version match; verify vendor applicability.</p></article>').join('');
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
  return '<div class="web">' + (w.error ? '<p class="evidence-note">Assessment incomplete. This result does not establish whether the website is secure.</p>' : '') + '<h3>' + (w.standalone ? 'Website evidence' : 'Web service') + ' <span class="sub">' + (w.error ? 'Not assessed' : 'risk score ' + esc(w.risk_score) + '/100') + '</span></h3>' +
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
  return '<details class="asset"' + (open ? ' open' : '') + '><summary>' + (w.error ? '<span class="badge s-high">INCOMPLETE</span>' : badge(w.risk_level)) + '<b>' + esc(w.url) + '</b><span class="sub">Technical evidence & findings</span></summary><div class="body">' + webBlock(w) + '</div></details>';
}
function renderResult(d, id, files) {
  downloadUrls.forEach(URL.revokeObjectURL); downloadUrls = [];
  const s = d.summary || {}; const cs = s.cve_severity || {}, fs = s.finding_severity || {};
  const nfind = SEV.slice(0, 4).reduce((a, k) => a + (fs[k] || 0), 0);
  const names = { docx: 'Word / WPS (.docx)', pdf: 'PDF', html: 'HTML', json: 'JSON' };
  const dl = ['pdf', 'docx', 'html', 'json'].map((f) => (files || []).indexOf(f) >= 0
    ? '<a class="btn ' + (f === 'pdf' ? 'pdf-download' : '') + '" href="' + esc(reportLink(id, f)) + '" download="VulnScan_Report_' + esc(id) + '.' + f + '">Download ' + esc(names[f]) + ' ↗</a>' : '').join('');
  const hosts = (d.hosts || []).slice().sort((a, b) => b.risk_score - a.risk_score);
  const webs = d.webs || [];
  const cards = []; let first = true;
  hosts.forEach((h) => { cards.push(hostCard(h, webs.filter((w) => !w.standalone && w.host_ip === h.ip), first)); first = false; });
  webs.filter((w) => w.standalone).sort((a, b) => b.risk_score - a.risk_score).forEach((w) => { cards.push(webCard(w, first)); first = false; });
  const incomplete = webs.some((w) => w.error) || (d.meta || {}).interrupted || (d.meta || {}).error || !cards.length;
  const score = Math.min(100, Math.max(0, ...hosts.map((h) => Number(h.risk_score) || 0), ...webs.map((w) => Number(w.risk_score) || 0)));
  const worst = SEV.find((level) => (fs[level] || 0) + (cs[level] || 0) > 0) || 'info';
  const verdicts = {critical:'Prioritize immediate action.', high:'High-priority issues surfaced.', medium:'A few defenses need attention.', low:'Strengthen the small details.', info:'No major issues observed.'};
  $('#results').innerHTML = '<section class="card ' + (incomplete ? 'risk-error' : '') + '"><div class="result-heading"><div><div class="eyebrow">YOUR ASSESSMENT</div><h2>Signals into clarity.</h2></div><button class="btn small" id="newbtn" type="button">New assessment ↗</button></div>' +
    '<div class="result-target">' + esc(d.targets) + '<br>' + esc(d.started) + ' · ' + esc(Number(d.duration_s || 0).toFixed(1)) + 's · ' + esc(id) + '</div>' +
    '<div class="result-overview"><div class="risk-gauge"><div><strong>' + (incomplete ? 'N/A' : score) + '</strong><span>' + (incomplete ? 'INCOMPLETE' : 'RISK / 100') + '</span></div></div><div class="verdict">' + (incomplete ? '<span class="badge s-high">INCOMPLETE ASSESSMENT</span>' : badge(worst)) + '<h3>' + (incomplete ? 'More evidence is needed.' : verdicts[worst]) + '</h3><p>' + (incomplete ? 'One or more checks could not complete. This scan cannot establish a clean security posture. Review the errors and try again.' : 'These are observations from the scanned scope. Higher scores indicate greater observed risk. Review the evidence and verify each finding before making changes.') + '</p></div></div>' +
    '<div class="kpis"><div class="kpi"><b>' + (s.assets || 0) + '</b><span>Scope assets</span></div><div class="kpi"><b>' + nfind + '</b><span>Findings</span></div><div class="kpi"><b>' + (s.cves || 0) + '</b><span>CVE matches</span></div><div class="kpi"><b class="c-high">' + ((fs.critical || 0) + (fs.high || 0) + (cs.critical || 0) + (cs.high || 0)) + '</b><span>High + critical</span></div></div>' +
    '<div class="eyebrow">OBSERVATIONS BY SEVERITY</div><div class="severity-grid">' + SEV.map((level) => '<div class="severity-cell ' + level + '"><b>' + ((fs[level] || 0) + (cs[level] || 0)) + '</b><span>' + level + '</span></div>').join('') + '</div>' +
    '<div class="report-downloads"><h3>Your findings, ready for the next conversation.</h3><p>Executive summary, remediation priorities and full technical evidence.</p><div class="dl">' + (dl || '<span class="sub">No report files available.</span>') + '</div></div>' +
    '<div class="assessment-note">A baseline assessment, not a penetration test or security certification. CVE version matches can include false positives. Hosted scans use the offline database.</div></section>' +
    '<div class="result-toolbar" aria-label="Filter findings">' + ['all'].concat(SEV).map((level) => '<button type="button" class="filter' + (level === 'all' ? ' active' : '') + '" data-filter="' + level + '" aria-pressed="' + (level === 'all') + '">' + (level === 'all' ? 'All findings' : level.charAt(0).toUpperCase() + level.slice(1)) + '</button>').join('') + '<input id="findingsearch" type="search" aria-label="Search findings" placeholder="Search findings…"></div><p class="finding-count" id="findingcount" role="status"></p>' +
    (cards.length ? cards.join('') : '<section class="card sub">No assets returned usable evidence. Review target reachability and scan configuration.</section>');
  $('.risk-gauge').style.setProperty('--score', (incomplete ? 0 : score) + '%');
  severityFilter = 'all';
  document.querySelectorAll('[data-filter]').forEach((button) => button.addEventListener('click', () => {
    severityFilter = button.dataset.filter;
    document.querySelectorAll('[data-filter]').forEach((b) => { b.classList.toggle('active', b === button); b.setAttribute('aria-pressed', String(b === button)); });
    filterFindings();
  }));
  $('#findingsearch').addEventListener('input', filterFindings); filterFindings();
  $('#results').classList.remove('hidden');
  $('#newbtn').addEventListener('click', () => { $('#results').classList.add('hidden'); $('#live').classList.add('hidden'); $('#newscan').classList.remove('hidden'); setPill('Ready to scan', 'ok'); selected = null; markSel(); $('#target').focus(); });
  $('#results').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth',block:'start'});
}
function filterFindings() {
  const query = $('#findingsearch').value.toLowerCase().trim(); let total = 0, visible = 0;
  document.querySelectorAll('.finding-card').forEach((card) => {
    total++; const show = (severityFilter === 'all' || card.dataset.severity === severityFilter) && card.textContent.toLowerCase().includes(query);
    card.classList.toggle('hidden', !show); if (show) visible++;
  });
  $('#findingcount').textContent = visible + ' of ' + total + ' observations shown';
  if (query || severityFilter !== 'all') document.querySelectorAll('details.asset').forEach((asset) => { asset.open = true; });
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
  if (!histCache.length) { h.innerHTML = '<div class="empty-history"><span aria-hidden="true">↗</span><p>Your next insight starts with a scan.</p></div>'; return; }
  h.innerHTML = histCache.map((x) => {
    const lv = x.levels || {}; const chips = SEV.slice(0, 4).filter((k) => lv[k]).map((k) => '<span class="badge s-' + k + '">' + lv[k] + ' ' + k + '</span>').join(' ');
    return '<button type="button" class="item" data-id="' + esc(x.id) + '"><span class="t">' + esc(x.targets) + '</span><span class="d">' + esc(x.started) + ' · ' + esc(x.assets) + ' assets · ' + esc(x.cves) + ' CVEs</span><span>' + chips + '</span></button>';
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
      token = ''; detectMode();
      $('#target').placeholder = 'https://your-website.com';
      document.querySelector('label[for="target"]').textContent = 'Website URL';
      $('#targethint').textContent = 'One public HTTP(S) website on port 80 or 443. Private-network scans require local mode.';
      $('#presets').previousElementSibling.classList.add('hidden'); $('#presets').classList.add('hidden'); $('.adv').classList.add('hidden');
      $('#historynote').classList.remove('hidden'); $('#clearhistory').classList.remove('hidden');
      $('#coveragenote').textContent = 'Public website mode · offline CVE matching. Network and email DNS checks are available in the local app.';
      try { cloudRecords = await Promise.race([browserStore('read'), new Promise((_, reject) => setTimeout(() => reject(new Error('Storage timeout')), 3000))]); } catch (e) { $('#historynote').textContent = 'Browser storage blocked. Download reports before closing this tab.'; }
    }
    $('#start').disabled = false; setPill('Ready to scan','ok');
  }
  catch (e) { showErr('Scanner connection unavailable. Refresh the page and try again. Local users: open the link printed by py main.py --ui.'); setPill('Offline',''); }
  detectMode(); loadHistory();
})();
})();

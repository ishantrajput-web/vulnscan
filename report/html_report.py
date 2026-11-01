"""Self-contained, printable HTML assessment with accessible, data-derived charts."""
from __future__ import annotations
import os
from html import escape
from urllib.parse import urlsplit
from report.insights import assessment
from report.scoring import summarize
from report import webview


def e(value):
    return escape(str(value), quote=True)


def chart_svg(chart):
    rows, series = chart['rows'], chart['series']
    width, left, plot = 760, 190, 490
    group = 48 if len(series)>1 else 34
    height = 52 + max(1,len(rows))*group + 25
    ceiling = max([1]+[n for row in rows for n in row['values']])
    parts = ['<svg class="chart" viewBox="0 0 %d %d" role="img" aria-labelledby="chart-%s"><title id="chart-%s">%s</title>' % (width,height,e(chart['id']),e(chart['id']),e(chart['title']))]
    palette = ['#244c39','#88ac52']
    for i, label in enumerate(series):
        x = 190+i*240
        parts.append('<rect x="%d" y="5" width="10" height="10" fill="%s"/><text x="%d" y="14">%s</text>' % (x,palette[i%2],x+16,e(label)))
    for tick in sorted(set([0,ceiling//2,ceiling])):
        x = left+plot*tick/ceiling
        parts.append('<line x1="%.1f" y1="30" x2="%.1f" y2="%d" stroke="#e2e8dc"/><text x="%.1f" y="%d" text-anchor="middle">%d</text>' % (x,x,height-25,x,height-8,tick))
    if not rows: parts.append('<text x="190" y="54">No observations recorded.</text>')
    for index,row in enumerate(rows):
        y = 39+index*group
        parts.append('<text x="0" y="%d">%s</text>' % (y+10,e(row['label'])))
        for j,value in enumerate(row['values']):
            pos = y+j*17
            parts.append('<rect x="%d" y="%d" width="%.1f" height="11" rx="2" fill="%s"/><text x="%.1f" y="%d">%d</text>' % (left,pos,plot*value/ceiling,palette[j%2],left+plot*value/ceiling+8,pos+10,value))
    return ''.join(parts)+'</svg>'


def write_html(result, path):
    a, s = assessment(result), summarize(result)
    h = ['''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"><title>VulnScan | Understand your security assessment</title><style>
+*{box-sizing:border-box}body{margin:0;background:#f0f3eb;color:#18251b;font:15px/1.7 Arial,sans-serif}.wrap{max-width:1040px;margin:auto;padding:36px 25px}header{background:#162219;color:#f0f2e9}header .brand{color:#d0f58a;font-weight:bold;letter-spacing:-1px;font-size:24px}h1{font-size:42px;line-height:1.15;letter-spacing:-1.5px;margin:22px 0}h2{font-size:26px;line-height:1.25;margin:0 0 18px}h3{font-size:18px;margin:20px 0 8px}.eyebrow{font:11px/1.6 monospace;letter-spacing:1.5px;color:#567044;text-transform:uppercase}.card{background:#fff;border:1px solid #d7dfd0;border-radius:12px;padding:28px;margin:22px 0;break-inside:avoid-page}.muted,figcaption{font-size:13px;color:#52614f}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.metric{border:1px solid #d7dfd0;padding:17px;border-radius:8px}.metric b{display:block;font-size:27px}.metric span{font-size:12px;color:#52614f}.callout{padding:18px;border-left:4px solid #668842;background:#f1f5e9;margin:18px 0}.warning{border-color:#ac4936;background:#fff4ef}table{width:100%;border-collapse:collapse;font-size:13px;margin:15px 0}th,td{padding:10px;border-bottom:1px solid #dfe5d8;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#edf2e6}svg.chart{display:block;width:100%;max-height:500px}svg text{font:12px Arial,sans-serif;fill:#263c2c}.chart-table{font-size:12px}.finding{border-top:1px solid #d7dfd0;padding:22px 0;break-inside:auto}.finding h3{margin:7px 0 12px}.badge{display:inline-block;border:1px solid currentColor;border-radius:4px;padding:2px 7px;font:11px monospace}.critical{color:#86298f}.high{color:#a9352e}.medium{color:#835a0d}.low{color:#245b82}.info{color:#52614f}.finding dt{font-weight:bold;font-size:12px;margin-top:12px}.finding dd{margin:3px 0 0;overflow-wrap:anywhere}.metadata{overflow-wrap:anywhere}.small{font-size:12px}a{color:#205f42}.tag{font:11px monospace}.status{font-size:13px;color:#d0f58a}.chart-source{font:11px monospace;color:#61705a}figure{margin:0}.break{break-before:page}@media(max-width:650px){.grid{grid-template-columns:1fr 1fr}.card{padding:20px}h1{font-size:32px}.wrap{padding:24px 15px}table{font-size:11px}th,td{padding:6px}}@media print{body{background:white;font-size:10pt}.wrap{max-width:none;padding:0}.card{border:0;border-radius:0;padding:12px 0;break-inside:auto}header{background:white;color:#18251b;padding:15px 0;border-bottom:2px solid #18251b}header .brand,.status{color:#18251b}h1{font-size:27pt}h2,h3{break-after:avoid}.grid{gap:7px}.metric{padding:8px}figure{break-inside:avoid}a{color:#18251b;text-decoration:none}@page{size:A4;margin:17mm}}
+</style></head><body>'''.replace('\n+','\n')]
    h.append('<header><div class="wrap"><div class="brand">vulnscan.</div><h1>Your security assessment,<br>explained.</h1><p class="status">%s</p><p class="metadata">%s<br>Scan %s · %s</p></div></header><main class="wrap">' % (e(a['status'].replace('_',' ').upper()),e(result.targets),e(result.scan_id),e(result.started)))
    if result.meta.get('sample'): h.append('<div class="callout warning"><b>ILLUSTRATIVE SAMPLE.</b> Synthetic fixture; no real website assessment is represented.</div>')
    h.append('<section class="card"><div class="eyebrow">01 / Start here</div><h2>What does this scan tell you?</h2><div class="callout %s">%s</div>' % ('warning' if a['status']=='incomplete' else '',e(a['conclusion'])))
    metrics = [('N/A' if a['aggregate_risk_indicator'] is None else str(a['aggregate_risk_indicator'])+'/100','Weighted risk indicator'),(s['assets'],'Scope assets'),(a['non_informational_observations'],'Non-info observations'),(a['informational_observations'],'Informational notes')]
    h.append('<div class="grid">'+''.join('<div class="metric"><b>%s</b><span>%s</span></div>'%(e(n),e(label)) for n,label in metrics)+'</div>')
    h.append('<p class="muted">Highest individual observation severity: <b>%s</b>. The risk indicator is not a security percentage or an exploit probability. Charts count recorded signals, not every possible vulnerability.</p><ol>' % e(a['highest_observation_severity']))
    h.extend('<li>'+e(step)+'</li>' for step in a['reading_order']); h.append('</ol></section>')
    h.append('<section class="card"><div class="eyebrow">02 / The evidence at a glance</div><h2>Where should you focus?</h2>')
    for chart in a['charts']:
        h.append('<figure><h3>%s</h3>%s<figcaption>%s</figcaption><table class="chart-table"><thead><tr><th>Category</th>%s</tr></thead><tbody>' % (e(chart['title']),chart_svg(chart),e(chart['description']),''.join('<th>'+e(v)+'</th>' for v in chart['series'])))
        for row in chart['rows']: h.append('<tr><td>%s</td>%s</tr>' % (e(row['label']),''.join('<td>%d</td>'%value for value in row['values'])))
        if not chart['rows']: h.append('<tr><td colspan="%d">No observations recorded.</td></tr>'%(len(chart['series'])+1))
        h.append('</tbody></table><p class="chart-source">Unit: %s · source: this scan only</p></figure>'%e(chart['unit']))
    h.append('</section><section class="card"><div class="eyebrow">03 / Act on the evidence</div><h2>Your prioritized action plan</h2>')
    if not a['actions']: h.append('<p>No non-informational action is recorded. Resolve any assessment errors before interpreting an empty result.</p>')
    for action in a['actions']:
        h.append('<article class="finding"><span class="badge %s">%s · %s</span><h3>%s</h3><p class="metadata small">Where: %s</p><p>%s</p><p><b>Verify the change:</b> %s</p></article>'%(e(action['severity']),e(action['severity'].upper()),e(action['priority']),e(action['title']),e(', '.join(action['assets'])),e(action['action']),e(action['verify'])))
    h.append('</section><section class="card"><div class="eyebrow">04 / Understand each observation</div><h2>Evidence, impact and next steps</h2>')
    for obs in a['observations']:
        h.append('<article class="finding"><span class="tag">%s</span> <span class="badge %s">%s</span><h3>%s</h3><p class="metadata small">%s · %s</p><dl>'%(e(obs['id']),e(obs['severity']),e(obs['severity'].upper()),e(obs['title']),e(obs['asset']),e(obs['validation'])))
        for label,value in [('Observed evidence',obs['evidence'] or 'No additional evidence recorded.'),('Why it matters',obs['why_it_matters']),('Recommended action',obs['recommended_action']),('How to verify',obs['how_to_verify']),('Source',obs['source'])]: h.append('<dt>%s</dt><dd>%s</dd>'%(e(label),e(value)))
        if obs['reference']:
            url = obs['reference']; h.append('<dt>Reference</dt><dd>%s</dd>'%('<a href="%s">%s</a>'%(e(url),e(url)) if urlsplit(url).scheme in ('http','https') else e(url)))
        h.append('</dl></article>')
    if not a['observations']: h.append('<p>No observations recorded. Check response availability and assessment errors before concluding that anything is secure.</p>')
    h.append('</section><section class="card"><div class="eyebrow">05 / Scope and interpretation</div><h2>What was assessed?</h2>')
    for web in result.webs:
        h.append('<h3 class="metadata">'+e(web.url)+'</h3>')
        if web.error: h.append('<div class="callout warning">NOT ASSESSED: '+e(web.error)+'</div>')
        h.append('<table>'+''.join('<tr><th>%s</th><td>%s</td></tr>'%(e(k),e(v)) for k,v in webview.summary_rows(web))+'</table>')
    for host in result.hosts:
        h.append('<h3>'+e(host.ip)+'</h3><p>OS guess: '+e(host.os_guess)+'</p>')
        for port in host.ports: h.append('<p class="metadata"><b>%d/%s %s</b> · %s %s<br>Banner: %s</p>'%(port.port,e(port.protocol),e(port.service),e(port.product or ''),e(port.version or ''),e(port.banner)))
    h.append('<h3>Read the terms correctly</h3><dl>')
    for term in a['glossary']: h.append('<dt><b>'+e(term['term'])+'</b></dt><dd>'+e(term['meaning'])+'</dd>')
    h.append('</dl><h3>Limits of this report</h3><ul>')
    h.extend('<li>'+e(item)+'</li>' for item in a['limitations'])
    h.append('</ul><p class="metadata small">Started: %s · Finished: %s · Duration: %.2fs · Tool: %s</p><p class="small">Private assessment data. Share only with authorized recipients.</p></section></main></body></html>'%(e(result.started),e(result.finished),result.duration_s,e(result.tool_version)))
    with open(path,'w',encoding='utf-8') as stream: stream.write(''.join(h))
    return os.path.abspath(path)

"""Editorial PDF assessment: complete evidence, prioritized actions and explicit scope."""
from __future__ import annotations

import os
import re
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Flowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from models import ScanResult
from report.scoring import summarize
from report import webview

SEV = ['critical', 'high', 'medium', 'low', 'info']
INK = colors.HexColor('#141c16')
LIME = colors.HexColor('#d0f58a')
MUTED = colors.HexColor('#62705f')
LINE = colors.HexColor('#dce2d7')
PAPER = colors.HexColor('#f5f7f0')
COL = {'critical': colors.HexColor('#8d3199'), 'high': colors.HexColor('#b33e31'),
       'medium': colors.HexColor('#946311'), 'low': colors.HexColor('#29658d'), 'info': MUTED}
_CTRL = re.compile(r'[\x00-\x08\x0b-\x1f\x7f-\x9f]')


def _t(value):
    text = _CTRL.sub('', '' if value is None else str(value))
    text = text.replace('\u2013', '-').replace('\u2014', '-').replace('\u2019', "'")
    return escape(text.encode('latin-1', 'replace').decode('latin-1')).replace('\n', '<br/>')


def _styles():
    base = dict(fontName='Helvetica', textColor=INK, splitLongWords=True)
    return {
        'label': ParagraphStyle('label', fontSize=8, leading=12, textColor=MUTED, fontName='Courier', spaceAfter=7),
        'h1': ParagraphStyle('h1', fontName='Helvetica-Bold', textColor=INK, fontSize=25, leading=30, spaceAfter=17, keepWithNext=True),
        'h2': ParagraphStyle('h2', fontName='Helvetica-Bold', textColor=INK, fontSize=15, leading=20, spaceBefore=18, spaceAfter=10, keepWithNext=True),
        'h3': ParagraphStyle('h3', fontName='Helvetica-Bold', textColor=INK, fontSize=10, leading=15, spaceBefore=12, spaceAfter=6, keepWithNext=True),
        'body': ParagraphStyle('body', fontSize=9, leading=14, spaceAfter=9, **base),
        'findingtitle': ParagraphStyle('findingtitle', fontSize=9, leading=14, spaceAfter=9, keepWithNext=True, **base),
        'small': ParagraphStyle('small', fontSize=8, leading=12, spaceAfter=7, **base),
        'cell': ParagraphStyle('cell', fontSize=8, leading=12, **base),
        'head': ParagraphStyle('head', fontSize=7, leading=11, fontName='Helvetica-Bold', textColor=colors.white),
        'callout': ParagraphStyle('callout', fontSize=11, leading=17, backColor=PAPER, borderPadding=13, spaceAfter=16, **base),
    }


def _table(rows, widths, st, header=True):
    data = [[Paragraph(_t(c), st['head'] if header and i == 0 else st['cell']) for c in row] for i, row in enumerate(rows)]
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0, hAlign='LEFT')
    commands = [('VALIGN', (0, 0), (-1, -1), 'TOP'), ('LEFTPADDING', (0, 0), (-1, -1), 9),
                ('RIGHTPADDING', (0, 0), (-1, -1), 9), ('TOPPADDING', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 9), ('LINEBELOW', (0, 0), (-1, -1), .5, LINE)]
    if header:
        commands += [('BACKGROUND', (0, 0), (-1, 0), INK), ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, PAPER])]
    table.setStyle(TableStyle(commands))
    return table


class Cover(Flowable):
    def __init__(self, result, summary, width, height, incomplete):
        super().__init__()
        self.result, self.summary, self.width, self.height, self.incomplete = result, summary, width, height, incomplete

    def draw(self):
        c, w, h, r = self.canv, self.width, self.height, self.result
        c.setFillColor(LIME); c.setFont('Helvetica-Bold', 25); c.drawString(0, h - 32, 'vulnscan.')
        c.setFont('Courier', 8); c.drawRightString(w, h - 25, 'SECURITY ASSESSMENT / ' + ('SAMPLE' if r.meta.get('sample') else 'REPORT'))
        c.setStrokeColor(colors.HexColor('#3b4939')); c.line(0, h - 55, w, h - 55)
        title = Paragraph('Exposure,<br/>understood.', ParagraphStyle('cover-title', fontName='Helvetica', fontSize=49, leading=53, textColor=colors.HexColor('#f0f0e6')))
        title.wrap(w, 160); title.drawOn(c, 0, h - 205)
        subtitle = Paragraph('A point-in-time view of the evidence.<br/>A clear plan for what comes next.', ParagraphStyle('cover-sub', fontName='Helvetica', fontSize=12, leading=19, textColor=colors.HexColor('#a8b6a1')))
        subtitle.wrap(w, 60); subtitle.drawOn(c, 0, h - 267)
        cx, cy = w - 100, h - 400
        c.setStrokeColor(colors.HexColor('#354a2d')); c.setLineWidth(.5)
        for radius in (28, 51, 74, 96): c.circle(cx, cy, radius, stroke=1, fill=0)
        c.line(cx - 96, cy, cx + 96, cy); c.line(cx, cy - 96, cx, cy + 96)
        c.setStrokeColor(LIME); c.line(cx, cy, cx + 65, cy + 60)
        c.setFillColor(LIME); c.circle(cx + 65, cy + 60, 3, fill=1, stroke=0)
        c.setFont('Courier', 8); c.drawString(0, h - 338, 'ASSESSMENT STATUS')
        c.setFillColor(colors.white); c.setFont('Helvetica-Bold', 16)
        c.drawString(0, h - 362, 'INCOMPLETE' if self.incomplete else 'EVIDENCE COLLECTED')
        c.setFillColor(colors.HexColor('#a8b6a1')); c.setFont('Helvetica', 10)
        c.drawString(0, h - 385, '%d scope asset(s) / %.1fs scan time' % (self.summary['assets'], r.duration_s))
        c.setStrokeColor(colors.HexColor('#3b4939')); c.line(0, 170, w, 170)
        metadata = [('TARGET / SCOPE', r.targets), ('SCAN IDENTIFIER', r.scan_id), ('STARTED', r.started)]
        y = 149
        for label, value in metadata:
            c.setFillColor(LIME); c.setFont('Courier', 7); c.drawString(0, y, label)
            p = Paragraph(_t(str(value)[:180]), ParagraphStyle('cover-meta', fontName='Helvetica', fontSize=9, leading=12, textColor=colors.white))
            _, ph = p.wrap(w - 130, 55); p.drawOn(c, 125, y - ph + 7)
            y -= max(33, ph + 13)
        c.setFillColor(colors.HexColor('#a8b6a1')); c.setFont('Courier', 7)
        c.drawString(0, 8, 'PRIVATE REPORT / SHARE ONLY WITH AUTHORIZED RECIPIENTS')


def _page(canvas, doc):
    canvas.saveState()
    if doc.page == 1:
        canvas.setFillColor(INK); canvas.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    else:
        canvas.setStrokeColor(LINE); canvas.line(20*mm, A4[1]-16*mm, A4[0]-20*mm, A4[1]-16*mm)
        canvas.setFont('Helvetica-Bold', 9); canvas.setFillColor(INK); canvas.drawString(20*mm, A4[1]-12*mm, 'vulnscan.')
        canvas.setFont('Courier', 7); canvas.setFillColor(MUTED); canvas.drawRightString(A4[0]-20*mm, A4[1]-12*mm, 'SECURITY ASSESSMENT')
        canvas.line(20*mm, 15*mm, A4[0]-20*mm, 15*mm)
        canvas.setFont('Courier', 7); canvas.drawString(20*mm, 10*mm, 'PRIVATE / POINT-IN-TIME OBSERVATIONS')
        canvas.drawRightString(A4[0]-20*mm, 10*mm, '%02d' % doc.page)
    canvas.restoreState()


def _all_findings(result):
    rows = [(w.url, f) for w in result.webs for f in w.findings]
    rows += [(h.ip + ':' + str(p.port), f) for h in result.hosts for p in h.ports for f in p.findings]
    return sorted(rows, key=lambda row: SEV.index(row[1].severity) if row[1].severity in SEV else 4)


def _finding(f, st, index):
    col = COL.get(f.severity, MUTED).hexval().replace('0x', '#')
    return [Paragraph('<font color="%s">%s</font> / F-%03d' % (col, _t(f.severity.upper()), index), st['h3']),
            Paragraph('<b>' + _t(f.title) + '</b>', st['findingtitle']),
            Paragraph(_t(f.detail) or 'No additional evidence was recorded.', st['body']),
            Paragraph('RECOMMENDED ACTION', st['label']),
            Paragraph(_t(f.remediation) or 'Review this observation in the context of the application.', st['body']), Spacer(1, 7)]


def _cve(v, st):
    return [Paragraph(_t(v.cve_id) + ' / ' + _t(v.severity.upper()) + (' / CVSS %.1f' % v.cvss if v.cvss is not None else ''), st['h3']),
            Paragraph(_t(v.description) or 'No description recorded.', st['body']),
            Paragraph('Source: ' + _t(v.source) + ('. Reference: ' + _t(v.url) if v.url else ''), st['small']),
            Paragraph('Version-based match. Verify affected versions and vendor advisories, account for back-ported fixes, then patch or mitigate and re-test.', st['small'])]


def write_pdf(result: ScanResult, path: str) -> str:
    st, s = _styles(), summarize(result)
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=20*mm, rightMargin=20*mm, topMargin=24*mm, bottomMargin=23*mm,
                            title='VulnScan | Security Assessment', author='VulnScan', subject='Evidence, remediation and assessment scope')
    width = doc.width
    incomplete = bool(result.meta.get('interrupted') or result.meta.get('error') or any(w.error for w in result.webs) or not s['assets'])
    findings = _all_findings(result)
    all_cves = [(w.url, v) for w in result.webs for v in w.vulns] + [(h.ip + ':' + str(p.port), v) for h in result.hosts for p in h.ports for v in p.vulns]
    all_cves.sort(key=lambda row: -(row[1].cvss or 0))
    worst = next((lv for lv in SEV if s['finding_severity'].get(lv) or s['cve_severity'].get(lv)), 'info')
    risk_score = max([0] + [h.risk_score for h in result.hosts] + [w.risk_score for w in result.webs])
    story = [Cover(result, s, width, doc.height - 14, incomplete), PageBreak()]
    def section(number, title):
        story.extend([Paragraph(number + ' / ASSESSMENT', st['label']), Paragraph(title, st['h1'])])
    section('01', 'The executive view.')
    if result.meta.get('sample'):
        story.append(Paragraph('<b>ILLUSTRATIVE SAMPLE.</b> This report uses a synthetic fixture. No assessment of a real website is represented.', st['callout']))
    if incomplete:
        verdict = 'Assessment incomplete. Missing or failed checks prevent a reliable overall conclusion. An empty findings list does not mean the target is secure.'
    else:
        verdict = {'critical': 'Critical observations require immediate review and containment.', 'high': 'High-priority observations require prompt validation and remediation.',
                   'medium': 'Moderate observations identify defenses to strengthen.', 'low': 'Lower-risk observations identify opportunities for hardening.',
                   'info': 'No significant issues were observed in this scope. This is not proof that the target is secure.'}[worst]
    story.append(Paragraph(_t(verdict), st['callout']))
    metrics = [['OBSERVED RISK', 'SCOPE ASSETS', 'FINDINGS', 'CVE MATCHES'],
               ['N/A' if incomplete else '%d / 100' % risk_score, str(s['assets']), str(sum(1 for _, f in findings if f.severity != 'info')), str(s['cves'])]]
    story.extend([_table(metrics, [width/4]*4, st), Spacer(1, 17), Paragraph('Observation distribution', st['h2'])])
    rows = [['SEVERITY', 'CONFIGURATION / EXPOSURE', 'CVE VERSION MATCHES']]
    rows += [[lv.upper(), str(s['finding_severity'].get(lv, 0)), str(s['cve_severity'].get(lv, 0))] for lv in SEV]
    story.append(_table(rows, [width*.24, width*.40, width*.36], st))
    story.append(Paragraph('Higher scores indicate greater observed risk, not exploit probability. Findings and CVEs are counted separately. Informational notes are included in the technical evidence.', st['small']))
    story.append(Paragraph('Read this report in three passes', st['h2']))
    for text in ('Prioritize: review the action plan and validate high-impact observations first.', 'Verify: use technical evidence and vendor guidance to establish applicability.', 'Improve: apply changes, re-test the same scope and document remaining risk.'):
        story.append(Paragraph(_t(text), st['body']))
    story.append(PageBreak()); section('02', 'Your remediation plan.')
    actionable = [(asset, f) for asset, f in findings if f.severity != 'info']
    if not actionable and not all_cves:
        story.append(Paragraph('No actionable findings were recorded.' if not incomplete else 'Resolve assessment errors before drawing a remediation conclusion.', st['body']))
    seen = set()
    for asset, f in actionable:
        key = (f.title, f.remediation)
        if key in seen: continue
        seen.add(key)
        story.append(Paragraph(_t(f.severity.upper()) + ' / ' + _t(f.title), st['h3']))
        story.append(Paragraph('Where: ' + _t(asset), st['small']))
        story.append(Paragraph(_t(f.remediation) or 'Review and validate the finding before making a change.', st['body']))
    if all_cves:
        story.append(Paragraph('Validate and address version-based CVE matches', st['h2']))
        story.append(Paragraph('Confirm the installed product and exact build against vendor advisories. Prioritize higher CVSS/severity matches; apply supported updates or mitigations, then verify the finding is resolved. Matching a version does not prove exploitability.', st['body']))
    story.append(Paragraph('Close the loop', st['h2']))
    story.append(Paragraph('Assign an owner to each validated issue. Test changes in a safe environment, deploy the fix, repeat the assessment and retain evidence of the outcome. Risk acceptance and remediation deadlines depend on business impact and exposure.', st['body']))
    story.append(PageBreak()); section('03', 'The technical evidence.')
    finding_index = 0
    for web in result.webs:
        story.append(Paragraph(_t(web.url), st['h2']))
        if web.error:
            story.append(Paragraph('<b>NOT ASSESSED:</b> ' + _t(web.error), st['callout']))
        for label, value in webview.summary_rows(web):
            story.append(Paragraph('<b>' + _t(label) + ':</b> ' + _t(value), st['small']))
        for f in sorted(web.findings, key=lambda x: SEV.index(x.severity) if x.severity in SEV else 4):
            finding_index += 1; story.extend(_finding(f, st, finding_index))
        for v in sorted(web.vulns, key=lambda x: -(x.cvss or 0)):
            story.extend(_cve(v, st))
        if not web.findings and not web.vulns and not web.error:
            story.append(Paragraph('No findings recorded for the checks performed. This is not a guarantee of security.', st['body']))
    for host in sorted(result.hosts, key=lambda h: -h.risk_score):
        story.append(Paragraph(_t(host.ip) + (' / ' + _t(host.hostname) if host.hostname else ''), st['h2']))
        story.append(Paragraph('OS guess: ' + _t(host.os_guess) + '. Source: ' + _t(host.os_source) + '. Open ports: ' + str(len(host.ports)), st['small']))
        if not host.ports: story.append(Paragraph('No open ports found in the scanned range.', st['body']))
        for port in host.ports:
            story.append(Paragraph('%d/%s - %s' % (port.port, _t(port.protocol), _t(port.service)), st['h3']))
            story.append(Paragraph('Product / version: ' + _t((port.product or '') + ' ' + (port.version or '')) + '. TLS: ' + str(port.tls), st['small']))
            if port.banner: story.append(Paragraph('<b>Banner:</b> ' + _t(port.banner), st['small']))
            for f in sorted(port.findings, key=lambda x: SEV.index(x.severity) if x.severity in SEV else 4):
                finding_index += 1; story.extend(_finding(f, st, finding_index))
            for v in sorted(port.vulns, key=lambda x: -(x.cvss or 0)): story.extend(_cve(v, st))
    story.append(PageBreak()); section('04', 'Scope, method & limits.')
    for label, value in [('Full target scope', result.targets), ('Scan identifier', result.scan_id), ('Tool version', result.tool_version), ('Started', result.started), ('Finished', result.finished), ('Duration', '%.2f seconds' % result.duration_s)]:
        story.append(Paragraph('<b>' + _t(label) + ':</b> ' + _t(value), st['body']))
    hosted = result.meta.get('mode') == 'serverless'
    method = ('Hosted website mode performs read-only HTTP requests for TLS, headers, cookie flags, version disclosures and a fixed set of known exposure paths. It accepts one public HTTP(S) website on port 80 or 443. Private, loopback, reserved and metadata addresses are blocked at connection time. Email DNS, network port scans and live NVD queries are not performed. CVE correlation uses the built-in offline database.' if hosted else
              'Local mode supports host discovery, TCP connect scans, banner fingerprinting and website checks. Nmap and live NVD enrichment depend on scan configuration and availability. Only the configured and reachable scope is represented in the evidence above.')
    story.append(Paragraph('Methodology', st['h2'])); story.append(Paragraph(_t(method), st['body']))
    story.append(Paragraph('Limitations and interpretation', st['h2']))
    for text in ('This is a baseline, point-in-time assessment. It does not include authenticated application testing, exploitation, business-logic testing or a comprehensive penetration test.',
                 'Version-based CVE correlation can produce false positives when vendors back-port fixes. Hidden versions and incomplete detection can produce false negatives. Confirm every match with vendor guidance.',
                 'A failed, blocked, unreachable or interrupted check is not evidence of safety. The report does not certify compliance or guarantee that all vulnerabilities have been found.',
                 'Risk scores summarize observed signals. They are not industry certifications, exploit likelihood estimates or a replacement for a qualified assessment.',
                 'Hosted report files are generated temporarily and returned to the requesting browser. Browser history is device- and origin-specific, can be cleared or evicted, and is not a cloud backup.',
                 'Only test systems you own or have written permission to assess. Share this report only with authorized recipients.'):
        story.append(Paragraph(_t(text), st['body']))
    if result.meta.get('interrupted') or result.meta.get('error'):
        story.append(Paragraph('Execution notes: ' + _t(result.meta.get('error') or 'Scan interrupted; only partial evidence is available.'), st['callout']))
    doc.build(story, onFirstPage=_page, onLaterPages=_page)
    return os.path.abspath(path)

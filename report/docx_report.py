"""Word (.docx) report written directly as OOXML - zero dependencies, opens in Microsoft Word, WPS Office,
LibreOffice and Google Docs."""
from __future__ import annotations

import datetime as dt
import os
import re
import zipfile
from typing import List, Optional
from xml.sax.saxutils import escape

from models import ScanResult
from report import webview
from report.scoring import summarize
from report.insights import assessment

NAVY = "0D1B2A"
SEVCOL = {"critical": "7B1FA2", "high": "D32F2F", "medium": "F57C00", "low": "0288D1", "info": "757575"}
SEV = ["critical", "high", "medium", "low", "info"]
PAGE_W, MARGIN = 11906, 900
W = PAGE_W - 2 * MARGIN          # 10106 dxa content width
_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
NS = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
      'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"')


def _x(s) -> str:
    return escape(_BAD.sub("", "" if s is None else str(s)))


def _t(s, limit: Optional[int] = None) -> str:
    s = _BAD.sub("", "" if s is None else str(s))
    if limit and len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


# ------------------------------------------------------------------ primitives
def run(text, b=False, i=False, color=None, size=None) -> str:
    rpr = ""
    if b:
        rpr += "<w:b/><w:bCs/>"
    if i:
        rpr += "<w:i/>"
    if color:
        rpr += '<w:color w:val="%s"/>' % color
    if size:
        rpr += '<w:sz w:val="%d"/><w:szCs w:val="%d"/>' % (size, size)
    segs = _BAD.sub("", "" if text is None else str(text)).split("\n")
    inner = "<w:br/>".join('<w:t xml:space="preserve">%s</w:t>' % escape(s) for s in segs)
    return "<w:r>%s%s</w:r>" % (("<w:rPr>%s</w:rPr>" % rpr) if rpr else "", inner)


def para(content, style=None, align=None, before=None, after=None, keep_next=False) -> str:
    if isinstance(content, str) and not content.startswith("<w:r>"):
        content = run(content)
    if isinstance(content, (list, tuple)):
        content = "".join(content)
    ppr = ""
    if style:
        ppr += '<w:pStyle w:val="%s"/>' % style
    if keep_next:
        ppr += "<w:keepNext/>"
    if before is not None or after is not None:
        ppr += "<w:spacing%s%s/>" % (' w:before="%d"' % before if before is not None else "",
                                     ' w:after="%d"' % after if after is not None else "")
    if align:
        ppr += '<w:jc w:val="%s"/>' % align
    return "<w:p>%s%s</w:p>" % (("<w:pPr>%s</w:pPr>" % ppr) if ppr else "", content)


def h(level: int, text: str) -> str:
    return para(run(text), style="Heading%d" % level)


def page_break() -> str:
    return '<w:p><w:r><w:br w:type="page"/></w:r></w:p>'


class Cell:
    def __init__(self, text="", fill=None, color=None, bold=False, align=None, size=None, raw=None, span=1):
        self.text, self.fill, self.color, self.bold, self.align, self.size, self.raw, self.span = \
            text, fill, color, bold, align, size, raw, span


def table(rows: List[List], widths: List[int], header: bool = True, zebra: bool = True) -> str:
    total = sum(widths)
    out = ['<w:tbl><w:tblPr><w:tblW w:w="%d" w:type="dxa"/><w:tblBorders>' % total]
    for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
        out.append('<w:%s w:val="single" w:sz="4" w:space="0" w:color="CFD8DC"/>' % side)
    out.append('</w:tblBorders><w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="50" w:type="dxa"/>'
               '<w:left w:w="90" w:type="dxa"/><w:bottom w:w="50" w:type="dxa"/><w:right w:w="90" w:type="dxa"/>'
               '</w:tblCellMar></w:tblPr><w:tblGrid>')
    out.extend('<w:gridCol w:w="%d"/>' % w for w in widths)
    out.append("</w:tblGrid>")
    for ri, row in enumerate(rows):
        is_head = header and ri == 0
        out.append("<w:tr><w:trPr><w:cantSplit/>%s</w:trPr>" % ("<w:tblHeader/>" if is_head else ""))
        ci = 0
        for cell in row:
            if not isinstance(cell, Cell):
                cell = Cell(cell)
            span = max(1, cell.span)
            width = sum(widths[ci:ci + span])
            fill = cell.fill
            color, bold = cell.color, cell.bold
            if is_head:
                fill, color, bold = NAVY, "FFFFFF", True
            elif fill is None and zebra and ri % 2 == 0:
                fill = "F5F7F9"
            tcpr = '<w:tcW w:w="%d" w:type="dxa"/>' % width
            if span > 1:
                tcpr += '<w:gridSpan w:val="%d"/>' % span
            if fill:
                tcpr += '<w:shd w:val="clear" w:color="auto" w:fill="%s"/>' % fill
            if cell.raw is not None:
                body = cell.raw
            else:
                body = para(run(cell.text, b=bold, color=color, size=cell.size or 16), align=cell.align, after=0)
            out.append("<w:tc><w:tcPr>%s</w:tcPr>%s</w:tc>" % (tcpr, body))
            ci += span
        out.append("</w:tr>")
    out.append("</w:tbl>")
    return "".join(out) + para("", after=60)


def sev_cell(sev: str) -> Cell:
    return Cell(sev.upper(), color=SEVCOL.get(sev, "757575"), bold=True)


def _chart_rows(chart):
    """Native Word table bars; numeric labels remain the authoritative data."""
    out = h(2, chart['title']) + para(chart['description'])
    maximum = max([1]+[n for row in chart['rows'] for n in row['values']])
    plot = 4900
    for row in chart['rows']:
        for index, value in enumerate(row['values']):
            filled = int(plot*value/maximum)
            label = row['label'] + (' / ' + chart['series'][index] if len(chart['series'])>1 else '')
            if filled == 0:
                bar = table([[Cell(' ',fill='EDF2E6')]], [plot], header=False, zebra=False)
            elif filled == plot:
                bar = table([[Cell(' ',fill='244C39' if index==0 else '88AC52')]], [plot], header=False, zebra=False)
            else:
                bar = table([[Cell(' ',fill='244C39' if index==0 else '88AC52'),Cell(' ',fill='EDF2E6')]], [filled,plot-filled],header=False,zebra=False)
            out += table([[Cell(label),Cell(raw=bar),Cell(str(value),bold=True)]],[W-plot-650,plot,650],header=False,zebra=False)
    if not chart['rows']: out += para('No observations recorded.')
    return out + para('Unit: '+chart['unit']+'. Source: this scan only.')


def build_body(result: ScanResult) -> str:
    a, s = assessment(result), summarize(result)
    B = [table([[Cell(raw=para(run('vulnscan.',b=True,color='D0F58A',size=32)) + para(run('Security assessment, explained.',b=True,color='FFFFFF',size=40)),fill='162219')]], [W],header=False,zebra=False)]
    if result.meta.get('sample'): B.append(para('ILLUSTRATIVE SAMPLE. Synthetic fixture; no real assessment is represented.'))
    B += [para('Scan: '+result.scan_id),para('Scope: '+result.targets),para('Started: '+result.started),
          h(1,'1. Understand the result'),para(a['conclusion']),
          para('Weighted risk indicator: '+('N/A' if a['aggregate_risk_indicator'] is None else str(a['aggregate_risk_indicator'])+'/100')),
          para('Highest individual observation severity: '+a['highest_observation_severity']),
          para('The indicator is not an exploit probability or a percentage of security. Missing responses do not establish safety.'),
          table([['Scope assets','Non-info observations','Informational notes','CVE matches'],[str(s['assets']),str(a['non_informational_observations']),str(a['informational_observations']),str(s['cves'])]],[W//4]*3+[W-3*(W//4)])]
    B += [para(step) for step in a['reading_order']]
    B += [page_break(),h(1,'2. Read the charts')]
    B += [_chart_rows(chart) for chart in a['charts']]
    B += [page_break(),h(1,'3. Your prioritized action plan')]
    if not a['actions']: B.append(para('No non-informational action is recorded. Resolve any assessment errors before interpreting an empty result.'))
    for action in a['actions']:
        B += [h(2,action['severity'].upper()+' / '+action['title']),para('Priority: '+action['priority']),
              para('Where: '+', '.join(action['assets'])),para('Recommended action: '+action['action']),para('Verify the change: '+action['verify'])]
    B += [page_break(),h(1,'4. Evidence and explanations')]
    for obs in a['observations']:
        B += [h(2,obs['id']+' / '+obs['severity'].upper()+' / '+obs['title']),para('Asset: '+obs['asset']),para(obs['validation'])]
        for label,value in [('Observed evidence',obs['evidence'] or 'No additional evidence recorded.'),('Why it matters',obs['why_it_matters']),('Recommended action',obs['recommended_action']),('How to verify',obs['how_to_verify']),('Source',obs['source'])]:
            B += [para(run(label,b=True),keep_next=True),para(value)]
        if obs['reference']: B.append(para('Reference: '+obs['reference']))
    B += [page_break(),h(1,'5. Scope, method and interpretation')]
    for web in result.webs:
        B.append(h(2,web.url))
        if web.error: B.append(para('NOT ASSESSED: '+web.error))
        for label,value in webview.summary_rows(web): B.append(para(label+': '+str(value)))
    for host in result.hosts:
        B += [h(2,host.ip),para('OS guess: '+host.os_guess)]
        for port in host.ports:
            B += [para('%d/%s %s - %s %s'%(port.port,port.protocol,port.service,port.product or '',port.version or '')),para('Banner: '+port.banner)]
    B += [h(2,'Understand the terms')]
    for term in a['glossary']: B.append(para(run(term['term']+': ',b=True)+run(term['meaning'])))
    B += [h(2,'Limitations')]+[para(item) for item in a['limitations']]
    B += [para('Finished: '+result.finished),para('Duration: %.2fs'%result.duration_s),para('Private assessment data. Share only with authorized recipients.')]
    return ''.join(B)


_STYLES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles %s>'
           '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:eastAsia="Arial" w:cs="Arial"/>'
           '<w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="en-US"/></w:rPr></w:rPrDefault>'
           '<w:pPrDefault><w:pPr><w:spacing w:after="80" w:line="259" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
           '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>'
           '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
           '<w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="320" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr>'
           '<w:rPr><w:b/><w:bCs/><w:color w:val="0D1B2A"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style>'
           '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
           '<w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr>'
           '<w:rPr><w:b/><w:bCs/><w:color w:val="0D1B2A"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style>'
           '<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
           '<w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr>'
           '<w:rPr><w:b/><w:bCs/><w:color w:val="37474F"/><w:sz w:val="22"/><w:szCs w:val="22"/></w:rPr></w:style>'
           '<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/>'
           '<w:pPr><w:tabs><w:tab w:val="right" w:pos="%d"/></w:tabs><w:spacing w:after="0"/></w:pPr></w:style></w:styles>') % (NS, W)

_FOOTER = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr %s><w:p><w:pPr><w:pStyle w:val="Footer"/></w:pPr>'
           '<w:r><w:rPr><w:color w:val="808080"/><w:sz w:val="16"/></w:rPr><w:t>CONFIDENTIAL - Security Assessment Report</w:t></w:r>'
           '<w:r><w:rPr><w:color w:val="808080"/><w:sz w:val="16"/></w:rPr><w:tab/><w:t xml:space="preserve">Page </w:t></w:r>'
           '<w:fldSimple w:instr=" PAGE "><w:r><w:rPr><w:color w:val="808080"/><w:sz w:val="16"/></w:rPr><w:t>1</w:t></w:r></w:fldSimple></w:p></w:ftr>') % NS

_CT = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
       '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
       '<Default Extension="xml" ContentType="application/xml"/>'
       '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
       '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>'
       '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>'
       '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
       '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')

_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
         '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
         '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
         '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>')

_DOC_RELS = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
             '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
             '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>')

_APP = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        '<Application>VulnScan</Application></Properties>')


def write_docx(result: ScanResult, path: str) -> str:
    created = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    core = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:title>Security Assessment Report</dc:title><dc:creator>VulnScan</dc:creator>'
            '<dcterms:created xsi:type="dcterms:W3CDTF">%s</dcterms:created></cp:coreProperties>') % created
    sect = ('<w:sectPr><w:footerReference w:type="default" r:id="rId2"/><w:pgSz w:w="%d" w:h="16838"/>'
            '<w:pgMar w:top="%d" w:right="%d" w:bottom="%d" w:left="%d" w:header="400" w:footer="400" w:gutter="0"/></w:sectPr>'
            % (PAGE_W, MARGIN, MARGIN, MARGIN + 200, MARGIN))
    doc = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document %s><w:body>%s%s</w:body></w:document>' % (NS, build_body(result), sect)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _CT)
        z.writestr("_rels/.rels", _RELS)
        z.writestr("word/document.xml", doc)
        z.writestr("word/_rels/document.xml.rels", _DOC_RELS)
        z.writestr("word/styles.xml", _STYLES)
        z.writestr("word/footer1.xml", _FOOTER)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", _APP)
    return os.path.abspath(path)

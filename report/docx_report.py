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


def stacked_bar(counts: dict, label: str) -> str:
    """One-row table whose cell widths are proportional to the counts - a chart that works in every editor."""
    items = [(s, counts.get(s, 0)) for s in SEV[:4] if counts.get(s, 0) > 0]
    out = para(run(label, b=True, size=18), after=40, keep_next=True)
    if not items:
        return out + para(run("None found", color="2E7D32", size=18), after=120)
    total = sum(n for _, n in items)
    widths = [max(700, int(W * n / total)) for _, n in items]
    scale = W / float(sum(widths))
    widths = [int(w * scale) for w in widths]
    widths[-1] += W - sum(widths)
    row = [Cell("%s %d" % (s.capitalize(), n), fill=SEVCOL[s], color="FFFFFF", bold=True, align="center", size=18) for s, n in items]
    return out + table([row], widths, header=False, zebra=False)


# ------------------------------------------------------------------ report body
def _kv_table(rows, label_w=2000) -> str:
    return table([[Cell(k, bold=True, fill="ECEFF1"), Cell(_t(v, 400))] for k, v in rows], [label_w, W - label_w],
                 header=False, zebra=False)


def _web_block(w, level: int) -> List[str]:
    out = [h(level, "Website: %s" % _t(w.url, 90))]
    if w.standalone is False:
        out[0] = h(level, "Web service: %s" % _t(w.url, 90))
    out.append(para(run("Risk: ", size=18) + run(w.risk_level.upper(), b=True, color=SEVCOL[w.risk_level], size=18)
                    + run("   Score %d/100" % w.risk_score, size=18), after=60))
    out.append(_kv_table(webview.summary_rows(w)))
    fl, info_n = webview.findings(w)
    if fl:
        out.append(para(run("Security findings", b=True, color="37474F", size=21), before=120, after=40, keep_next=True))
        rows = [["Severity", "Finding", "Recommended remediation"]]
        for f in fl:
            rows.append([sev_cell(f.severity),
                         Cell(raw=para(run(_t(f.title, 140), b=True, size=16), after=0) + para(run(_t(f.detail, 240), size=15, color="546E7A"), after=0)),
                         Cell(_t(f.remediation, 260))])
        out.append(table(rows, [1000, 5000, W - 6000]))
    elif not w.error:
        out.append(para(run("No security findings above informational level.", color="2E7D32", size=18)))
    if info_n:
        out.append(para(run("%d additional informational note(s) are included in the JSON report." % info_n, i=True, color="757575", size=16)))
    if w.exposed:
        out.append(para(run("Exposed paths detected: " + ", ".join(e["path"] for e in w.exposed), size=17), after=60))
    cves = webview.cve_rows(w)
    if cves:
        out.append(para(run("Known vulnerabilities (CVE)", b=True, color="37474F", size=21), before=120, after=40, keep_next=True))
        rows = [["CVE", "CVSS", "Description"]]
        for v in cves[:20]:
            rows.append([Cell("%s\n(%s)" % (v.cve_id, v.source)), Cell("%s %s" % (v.severity.upper(), "" if v.cvss is None else "%.1f" % v.cvss),
                                                                   color=SEVCOL.get(v.severity), bold=True), Cell(_t(v.description, 280))])
        out.append(table(rows, [1900, 1300, W - 3200]))
    return out


def build_body(result: ScanResult) -> str:
    s = summarize(result)
    hosts = sorted(result.hosts, key=lambda x: -x.risk_score)
    standalone = [w for w in result.webs if w.standalone]
    attached = {}
    for w in result.webs:
        if not w.standalone:
            attached.setdefault(w.host_ip, []).append(w)
    B: List[str] = []

    # --- cover
    cover = para(run("Security Assessment Report", b=True, color="FFFFFF", size=52), before=360, after=60) + \
        para(run("Network & website vulnerability assessment", color="CFD8DC", size=24), after=360)
    B.append(table([[Cell(raw=cover, fill=NAVY)]], [W], header=False, zebra=False))
    B.append(para("", after=120))
    status = "PARTIAL (interrupted)" if result.meta.get("interrupted") else "Complete"
    meta = [[Cell("Scan ID", bold=True, fill="ECEFF1"), result.scan_id, Cell("Started", bold=True, fill="ECEFF1"), result.started],
            [Cell("Targets", bold=True, fill="ECEFF1"), _t(result.targets, 120), Cell("Duration", bold=True, fill="ECEFF1"), "%.1f s" % result.duration_s],
            [Cell("Tool", bold=True, fill="ECEFF1"), "VulnScan v%s" % result.tool_version, Cell("Status", bold=True, fill="ECEFF1"), status]]
    B.append(table(meta, [1500, 3600, 1500, W - 6600], header=False, zebra=False))

    # --- executive summary
    B.append(h(1, "1. Executive Summary"))
    worst = next((lv for lv in SEV if s["host_levels"].get(lv)), "info")
    verdict = {"critical": "Immediate action required: critical risk was identified.",
               "high": "High-risk exposure identified; remediate promptly.",
               "medium": "Moderate risk identified; schedule remediation.",
               "low": "Low risk identified; follow best-practice hardening.",
               "info": "No significant risk identified in the scanned scope."}[worst]
    B.append(para(run("Overall posture: ", b=True) + run(verdict, color=SEVCOL[worst], b=True), after=120))
    k = [("%d" % s["assets"], "Assets assessed"), ("%d" % s["open_ports"], "Open ports"), ("%d" % s["cves"], "CVEs matched"),
         ("%d" % s["cve_severity"]["critical"], "Critical CVEs"), ("%d" % s["cve_severity"]["high"], "High CVEs")]
    kw = W // 5
    cells = [Cell(raw=para(run(n, b=True, size=40, color=NAVY), align="center", after=0) + para(run(lbl, size=16, color="546E7A"), align="center", after=0),
                  fill="F5F7F9") for n, lbl in k]
    B.append(table([cells], [kw] * 4 + [W - 4 * kw], header=False, zebra=False))
    B.append(para("", after=60))
    B.append(stacked_bar(s["cve_severity"], "Known vulnerabilities (CVE) by severity"))
    B.append(stacked_bar(s["finding_severity"], "Configuration & exposure findings by severity"))

    rows = [["Asset", "Type", "System / Server", "Open ports", "Score", "Risk"]]
    for hst in hosts:
        rows.append([_t(hst.ip + ((" (%s)" % hst.hostname) if hst.hostname else ""), 50), "Host", _t(hst.os_guess, 30),
                     str(len(hst.ports)), str(hst.risk_score), sev_cell(hst.risk_level)])
    for w in standalone:
        rows.append([_t(w.url, 60), "Website", _t(w.server or (w.error or "-"), 30), "-", str(w.risk_score), sev_cell(w.risk_level)])
    if len(rows) > 1:
        B.append(h(2, "Asset risk overview"))
        B.append(table(rows, [3300, 900, 2300, 1100, 800, W - 8400]))

    allv = [(hst.ip, p.port, v) for hst in hosts for p in hst.ports for v in p.vulns]
    allv += [(w.url, 0, v) for w in result.webs for v in w.vulns]
    allv.sort(key=lambda t: -(t[2].cvss or 0))
    if allv:
        B.append(h(2, "Top vulnerabilities"))
        rows = [["CVE", "CVSS", "Where", "Summary"]]
        for where, port, v in allv[:10]:
            rows.append([_t(v.cve_id), Cell("%s %s" % (v.severity.upper(), "" if v.cvss is None else "%.1f" % v.cvss), color=SEVCOL.get(v.severity), bold=True),
                         _t("%s:%d" % (where, port) if port else where, 40), _t(v.description, 170)])
        B.append(table(rows, [1600, 1300, 2300, W - 5200]))

    # --- details
    B.append(page_break())
    B.append(h(1, "2. Detailed Findings"))
    for hst in hosts:
        B.append(h(2, "%s%s" % (hst.ip, (" (%s)" % _t(hst.hostname, 40)) if hst.hostname else "")))
        B.append(para(run("Risk: ", size=18) + run(hst.risk_level.upper(), b=True, color=SEVCOL[hst.risk_level], size=18)
                      + run("   Score %d/100   |   OS: %s%s" % (hst.risk_score, _t(hst.os_guess), (" (%s)" % hst.os_source) if hst.os_source else ""), size=18), after=80))
        if not hst.ports:
            B.append(para("No open ports found in the scanned range."))
        else:
            rows = [["Port", "Service", "Product / Version", "Banner"]]
            for p in hst.ports:
                pv = ("%s %s" % (p.product or "", p.version or "")).strip() or "-"
                rows.append(["%d/tcp" % p.port, _t(p.service + (" (TLS)" if p.tls else "")), _t(pv, 40), _t(p.banner.replace("\n", " "), 100)])
            B.append(table(rows, [900, 1700, 2800, W - 5400]))
            fr = sorted([(p, f) for p in hst.ports for f in p.findings if f.severity != "info"], key=lambda t: SEV.index(t[1].severity))
            if fr:
                B.append(para(run("Exposure & configuration findings", b=True, color="37474F", size=21), before=120, after=40, keep_next=True))
                rows = [["Severity", "Finding", "Recommended remediation"]]
                for p, f in fr:
                    rows.append([sev_cell(f.severity),
                                 Cell(raw=para(run(_t(f.title, 140), b=True, size=16), after=0) + para(run(_t(f.detail, 220), size=15, color="546E7A"), after=0)),
                                 Cell(_t(f.remediation, 240))])
                B.append(table(rows, [1000, 5000, W - 6000]))
            vr = sorted([(p, v) for p in hst.ports for v in p.vulns], key=lambda t: -(t[1].cvss or 0))
            if vr:
                B.append(para(run("Known vulnerabilities (CVE)%s" % (" - top 25 shown" if len(vr) > 25 else ""), b=True, color="37474F", size=21),
                              before=120, after=40, keep_next=True))
                rows = [["CVE", "CVSS", "Port", "Description"]]
                for p, v in vr[:25]:
                    rows.append([Cell("%s\n(%s)" % (v.cve_id, v.source)), Cell("%s %s" % (v.severity.upper(), "" if v.cvss is None else "%.1f" % v.cvss),
                                                                               color=SEVCOL.get(v.severity), bold=True), str(p.port), _t(v.description, 260)])
                B.append(table(rows, [1900, 1300, 700, W - 3900]))
        for w in attached.get(hst.ip, []):
            B.extend(_web_block(w, 3))
    for w in standalone:
        B.extend(_web_block(w, 2))

    # --- recommendations + method
    B.append(page_break())
    B.append(h(1, "3. General Recommendations"))
    for t in ["Patch or upgrade every product listed under known vulnerabilities, starting with Critical and High.",
              "Close or firewall every port that is not required; expose management services only through a VPN.",
              "Replace cleartext protocols (Telnet, FTP, HTTP) with encrypted equivalents (SSH, SFTP, HTTPS).",
              "Enforce HTTPS with valid certificates and add the missing browser security headers.",
              "Remove exposed sensitive files (.env, .git) and rotate any secrets that may have been reachable.",
              "Disable legacy protocols (SMBv1, TLS 1.0/1.1) and enforce strong authentication / MFA.",
              "Re-scan after remediation to verify fixes and schedule recurring assessments."]:
        B.append(para(run("-  " + t), after=60))
    B.append(h(1, "4. Methodology & Limitations"))
    B.append(para("Hosts were discovered with ICMP and TCP probes. Open TCP ports were found with a connect scan and services were fingerprinted "
                  "via banners (and Nmap when available). Web origins were analysed passively: TLS certificate, redirects, security headers, cookies, "
                  "a small set of well-known exposure paths and email-security DNS records. CVEs were correlated from detected product versions "
                  "using the NIST NVD and a built-in database. The assessment is non-intrusive and point-in-time: results may include false positives "
                  "(for example distributions that back-port fixes without changing version numbers) and may miss issues in services that hide their "
                  "version. No exploitation, brute-forcing or authentication attempts were made. Only assess systems you are authorised to test."))
    return "".join(B)


# ------------------------------------------------------------------ package
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

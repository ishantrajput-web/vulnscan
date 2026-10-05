"""Professional PDF report (reportlab). Raises ImportError if reportlab is missing -> caller falls back to HTML."""
from __future__ import annotations

import os
import re
from xml.sax.saxutils import escape as xesc

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from models import ScanResult
from report.scoring import summarize

SEV = ["critical", "high", "medium", "low", "info"]
COL = {"critical": colors.HexColor("#7b1fa2"), "high": colors.HexColor("#d32f2f"),
       "medium": colors.HexColor("#f57c00"), "low": colors.HexColor("#0288d1"),
       "info": colors.HexColor("#757575")}
NAVY = colors.HexColor("#0d1b2a")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _t(s, limit=None) -> str:
    """Make arbitrary text safe for reportlab Paragraphs (XML-escape, latin-1, no control chars)."""
    s = "" if s is None else str(s)
    s = _CTRL.sub("", s).encode("latin-1", "replace").decode("latin-1")
    if limit and len(s) > limit:
        s = s[: limit - 3] + "..."
    return xesc(s)


def _styles():
    ss = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=ss["Title"], textColor=colors.white, fontSize=26, leading=30, alignment=0),
        "sub": ParagraphStyle("s", parent=ss["Normal"], textColor=colors.HexColor("#cfd8dc"), fontSize=11),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], textColor=NAVY, fontSize=17, spaceBefore=6, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], textColor=NAVY, fontSize=13, spaceBefore=8, spaceAfter=4),
        "h3": ParagraphStyle("h3", parent=ss["Heading3"], textColor=colors.HexColor("#37474f"), fontSize=10.5, spaceBefore=6, spaceAfter=3),
        "body": ParagraphStyle("b", parent=ss["Normal"], fontSize=9.5, leading=13),
        "cell": ParagraphStyle("c", parent=ss["Normal"], fontSize=8, leading=10),
        "cellb": ParagraphStyle("cb", parent=ss["Normal"], fontSize=8, leading=10, fontName="Helvetica-Bold"),
        "head": ParagraphStyle("hd", parent=ss["Normal"], fontSize=8, leading=10, fontName="Helvetica-Bold", textColor=colors.white),
        "kpi": ParagraphStyle("k", parent=ss["Normal"], fontSize=9.5, leading=13, alignment=1),
        "small": ParagraphStyle("sm", parent=ss["Normal"], fontSize=8, textColor=colors.grey, leading=10),
    }


def _table(rows, widths, st, header=True, extra=None):
    data = []
    for i, r in enumerate(rows):
        data.append([c if not isinstance(c, str) else Paragraph(c, st["head"] if (header and i == 0) else st["cell"]) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8dc")),
             ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7f9")]),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), NAVY))
    if extra:
        style.extend(extra)
    t.setStyle(TableStyle(style))
    return t


def _sev_cell(sev, st):
    return Paragraph('<font color="%s"><b>%s</b></font>' % (COL.get(sev, colors.grey).hexval().replace("0x", "#"), _t(sev.upper())), st["cell"])


def _pie(levels):
    vals = [levels.get(s, 0) for s in SEV]
    d = Drawing(240, 150)
    d.add(String(0, 138, "Hosts by risk level", fontSize=10, fontName="Helvetica-Bold"))
    if sum(vals) == 0:
        d.add(String(10, 70, "No data", fontSize=9))
        return d
    p = Pie()
    p.x, p.y, p.width, p.height = 20, 15, 105, 105
    p.data = [v for v in vals if v > 0]
    present = [s for s, v in zip(SEV, vals) if v > 0]
    p.labels = ["%d" % v for v in p.data]
    for i, s in enumerate(present):
        p.slices[i].fillColor = COL[s]
    d.add(p)
    y = 110
    for s in present:
        d.add(String(145, y, "%s (%d)" % (s.capitalize(), levels[s]), fontSize=8))
        y -= 13
    return d


def _bars(cve_sev):
    d = Drawing(270, 150)
    d.add(String(0, 138, "CVEs by severity", fontSize=10, fontName="Helvetica-Bold"))
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 28, 22, 220, 100
    bc.data = [[cve_sev.get(s, 0) for s in SEV[:4]]]
    bc.categoryAxis.categoryNames = [s.capitalize() for s in SEV[:4]]
    bc.categoryAxis.labels.fontSize = 8
    bc.valueAxis.labels.fontSize = 8
    bc.valueAxis.valueMin = 0
    top = max(bc.data[0]) if bc.data[0] else 0
    bc.valueAxis.valueMax = max(4, top + max(1, top // 5))
    bc.valueAxis.valueStep = max(1, int(bc.valueAxis.valueMax // 5) or 1)
    bc.bars.strokeColor = None
    for i, s in enumerate(SEV[:4]):
        bc.bars[(0, i)].fillColor = COL[s]
    d.add(bc)
    return d


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.grey)
    canvas.drawString(15 * mm, 9 * mm, "CONFIDENTIAL - Vulnerability Assessment Report")
    canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def write_pdf(result: ScanResult, path: str) -> str:
    st = _styles()
    s = summarize(result)
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                            topMargin=15 * mm, bottomMargin=16 * mm,
                            title="Network Vulnerability Assessment", author="VulnScan")
    W = A4[0] - 30 * mm
    story = []

    # --- cover banner
    cover = Table([[Paragraph("Network Vulnerability<br/>Assessment Report", st["title"])],
                   [Paragraph("Automated discovery, service fingerprinting and CVE correlation", st["sub"])]],
                  colWidths=[W])
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), NAVY), ("LEFTPADDING", (0, 0), (-1, -1), 14),
                               ("TOPPADDING", (0, 0), (0, 0), 22), ("BOTTOMPADDING", (0, -1), (-1, -1), 20)]))
    story += [cover, Spacer(1, 10)]
    meta = [["Scan ID", _t(result.scan_id), "Started", _t(result.started)],
            ["Targets", _t(result.targets, 90), "Duration", "%.1f s" % result.duration_s],
            ["Tool version", _t(result.tool_version), "Status", "PARTIAL (interrupted)" if result.meta.get("interrupted") else "Complete"]]
    story.append(_table([[Paragraph("<b>%s</b>" % a, st["cell"]) if i % 2 == 0 else a for i, a in enumerate(r)] for r in meta],
                        [W * .15, W * .38, W * .15, W * .32], st, header=False))
    story.append(Spacer(1, 10))

    # --- executive summary
    story.append(Paragraph("1. Executive Summary", st["h1"]))
    worst = next((lv for lv in SEV if s["host_levels"].get(lv)), "info")
    verdict = {"critical": "Immediate action required: critical risk was identified.",
               "high": "High-risk exposure identified; remediate promptly.",
               "medium": "Moderate risk identified; schedule remediation.",
               "low": "Low risk identified; follow best-practice hardening.",
               "info": "No significant risk identified in the scanned scope."}[worst]
    story.append(Paragraph("<b>Overall posture:</b> %s" % _t(verdict), st["body"]))
    story.append(Spacer(1, 6))
    kp = [[Paragraph("<b>%d</b><br/>Hosts assessed" % s["hosts"], st["kpi"]),
           Paragraph("<b>%d</b><br/>Open ports" % s["open_ports"], st["kpi"]),
           Paragraph("<b>%d</b><br/>CVEs matched" % s["cves"], st["kpi"]),
           Paragraph('<font color="#7b1fa2"><b>%d</b></font><br/>Critical CVEs' % s["cve_severity"]["critical"], st["kpi"]),
           Paragraph('<font color="#d32f2f"><b>%d</b></font><br/>High CVEs' % s["cve_severity"]["high"], st["kpi"])]]
    k = Table(kp, colWidths=[W / 5] * 5)
    k.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8dc")),
                           ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cfd8dc")),
                           ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 8),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 8), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f5f7f9"))]))
    story += [k, Spacer(1, 8)]
    ch = Table([[_pie(s["host_levels"]), _bars(s["cve_severity"])]], colWidths=[W * .45, W * .55])
    story += [ch, Spacer(1, 6)]

    # --- host overview
    hosts = sorted(result.hosts, key=lambda h: -h.risk_score)
    story.append(Paragraph("Host risk overview", st["h2"]))
    rows = [["Host", "Hostname", "OS (guess)", "Open ports", "Score", "Risk"]]
    for h in hosts:
        rows.append([_t(h.ip), _t(h.hostname or "-", 30), _t(h.os_guess, 28), str(len(h.ports)), str(h.risk_score), _sev_cell(h.risk_level, st)])
    story.append(_table(rows, [W * .18, W * .24, W * .24, W * .12, W * .09, W * .13], st))

    # --- top CVEs
    allv = [(h, p, v) for h in hosts for p in h.ports for v in p.vulns]
    allv.sort(key=lambda t: -(t[2].cvss or 0))
    if allv:
        story.append(Paragraph("Top vulnerabilities", st["h2"]))
        rows = [["CVE", "CVSS", "Host:Port", "Product", "Summary"]]
        for h, p, v in allv[:10]:
            rows.append([_t(v.cve_id), "%s %s" % (_t(v.severity.upper()), "" if v.cvss is None else "%.1f" % v.cvss),
                         "%s:%d" % (_t(h.ip), p.port), _t(("%s %s" % (p.product or "", p.version or "")).strip(), 28),
                         _t(v.description, 150)])
        story.append(_table(rows, [W * .14, W * .12, W * .17, W * .17, W * .40], st))

    # --- per-host
    story.append(PageBreak())
    story.append(Paragraph("2. Detailed Findings by Host", st["h1"]))
    for idx, h in enumerate(hosts):
        head = "%s%s" % (_t(h.ip), (" (%s)" % _t(h.hostname, 40)) if h.hostname else "")
        story.append(Paragraph('%s &nbsp; <font color="%s">[%s - %d/100]</font>' % (
            head, COL[h.risk_level].hexval().replace("0x", "#"), _t(h.risk_level.upper()), h.risk_score), st["h2"]))
        story.append(Paragraph("Operating system: %s %s" % (_t(h.os_guess), ("(%s)" % _t(h.os_source)) if h.os_source else ""), st["small"]))
        if not h.ports:
            story.append(Paragraph("No open ports found in the scanned range.", st["body"]))
            continue
        rows = [["Port", "Service", "Product / Version", "Banner"]]
        for p in h.ports:
            pv = ("%s %s" % (p.product or "", p.version or "")).strip() or "-"
            rows.append(["%d/tcp" % p.port, _t(p.service + (" (TLS)" if p.tls else "")), _t(pv, 40),
                         _t(p.banner.replace("\n", " "), 90)])
        story.append(_table(rows, [W * .11, W * .17, W * .27, W * .45], st))
        fr = [(p, f) for p in h.ports for f in p.findings if f.severity != "info"]
        fr.sort(key=lambda t: SEV.index(t[1].severity))
        if fr:
            story.append(Paragraph("Exposure & configuration findings", st["h3"]))
            rows = [["Severity", "Finding", "Recommended remediation"]]
            for p, f in fr:
                rows.append([_sev_cell(f.severity, st), "<b>%s</b><br/>%s" % (_t(f.title, 100), _t(f.detail, 200)), _t(f.remediation, 220)])
            story.append(_table(rows, [W * .11, W * .50, W * .39], st))
        vr = [(p, v) for p in h.ports for v in p.vulns]
        vr.sort(key=lambda t: -(t[1].cvss or 0))
        if vr:
            story.append(Paragraph("Known vulnerabilities (CVE)%s" % (" - top 25 shown" if len(vr) > 25 else ""), st["h3"]))
            rows = [["CVE", "CVSS", "Port", "Description"]]
            for p, v in vr[:25]:
                rows.append(["%s<br/>(%s)" % (_t(v.cve_id), _t(v.source)),
                             "%s %s" % (_t(v.severity.upper()), "" if v.cvss is None else "%.1f" % v.cvss),
                             str(p.port), _t(v.description, 260)])
            story.append(_table(rows, [W * .17, W * .13, W * .08, W * .62], st))
        story.append(Spacer(1, 10))

    # --- recommendations & method
    story.append(PageBreak())
    story.append(Paragraph("3. General Recommendations", st["h1"]))
    for t in ["Patch or upgrade every service listed under Known vulnerabilities, starting with Critical and High.",
              "Close or firewall every port that is not required; expose management services only through a VPN.",
              "Replace cleartext protocols (Telnet, FTP, HTTP) with encrypted equivalents (SSH, SFTP, HTTPS).",
              "Disable legacy protocols (SMBv1, TLS 1.0/1.1) and enforce strong authentication / MFA.",
              "Re-scan after remediation to verify fixes and schedule recurring assessments."]:
        story.append(Paragraph("&bull; " + _t(t), st["body"]))
    story.append(Paragraph("4. Methodology & Limitations", st["h1"]))
    story.append(Paragraph(_t("Hosts were discovered with ICMP and TCP probes. Open TCP ports were identified with a connect scan; "
                              "services were fingerprinted via banners and, when available, Nmap. CVEs were correlated from "
                              "detected product versions using the NIST NVD and a built-in database. The assessment is "
                              "non-intrusive and point-in-time: findings may include false positives (for example distributions "
                              "that back-port security fixes without changing version numbers) and may miss vulnerabilities in "
                              "services that hide their version. Only scan systems you are authorised to test."), st["body"]))
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return os.path.abspath(path)

"""Format-neutral view of a WebResult so PDF / DOCX / HTML render identical content."""
from __future__ import annotations

from typing import List, Tuple

from models import WebResult

SEV = ["critical", "high", "medium", "low", "info"]


def summary_rows(w: WebResult) -> List[Tuple[str, str]]:
    rows = [("URL", w.url)]
    if w.error:
        rows.append(("Result", "Could not analyse: " + w.error))
        return rows
    if w.final_url and w.final_url != w.url:
        rows.append(("Final URL", w.final_url))
    rows.append(("HTTP status", str(w.status) if w.status is not None else "-"))
    if w.title:
        rows.append(("Page title", w.title))
    if w.server:
        rows.append(("Server header", w.server))
    if w.host_ip:
        rows.append(("Resolved IP", w.host_ip))
    if w.techs:
        rows.append(("Technologies", ", ".join(("%s %s" % (t["product"], t.get("version") or "")).strip() for t in w.techs)))
    if w.redirects:
        rows.append(("Redirects", " | ".join(w.redirects)[:300]))
    t = w.tls
    if t:
        if t.get("error") and not t.get("version"):
            rows.append(("TLS", "Handshake failed: " + t["error"]))
        else:
            rows.append(("TLS", "%s  %s" % (t.get("version") or "-", t.get("cipher") or "")))
            cert = []
            if t.get("subject"):
                cert.append("CN=" + t["subject"])
            if t.get("issuer"):
                cert.append("issuer " + t["issuer"])
            if t.get("not_after"):
                cert.append("expires %s (%s days)" % (t["not_after"], t.get("days_left")))
            cert.append("trusted: " + ("yes" if t.get("valid") else "NO (%s)" % (t.get("error") or "unknown")))
            rows.append(("Certificate", "; ".join(cert)))
    if w.dns:
        rows.append(("Email security", "SPF: %s, DMARC: %s" % ("yes" if w.dns.get("spf") else "NO", "yes" if w.dns.get("dmarc") else "NO")))
    if w.cookies:
        rows.append(("Cookies", ", ".join(c["name"] for c in w.cookies)[:200]))
    return rows


def findings(w: WebResult):
    """(non-info findings sorted by severity, number of informational notes)"""
    real = sorted([f for f in w.findings if f.severity != "info"], key=lambda f: SEV.index(f.severity))
    return real, sum(1 for f in w.findings if f.severity == "info")


def cve_rows(w: WebResult):
    return sorted(w.vulns, key=lambda v: -(v.cvss or 0))

"""Risk scoring: converts vulnerabilities + findings into a 0-100 score and a level (hosts and web origins)."""
from __future__ import annotations

from typing import Dict, Iterable, Tuple

from models import HostResult, ScanResult, WebResult

ORDER = ["critical", "high", "medium", "low", "info"]
_VULN_W = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}
_FIND_W = {"critical": 20, "high": 8, "medium": 3, "low": 1, "info": 0}


def level_for(score: int, worst: str) -> str:
    if worst == "critical" or score >= 70:
        return "critical"
    if worst == "high" or score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _points(vulns, findings) -> Tuple[int, int]:
    # cap CVE contribution so one old Apache with 300 CVEs doesn't hide everything else
    pts = min(sum(_VULN_W.get(v.severity, 0) for v in vulns), 60)
    pts += sum(_FIND_W.get(f.severity, 0) for f in findings)
    worst = len(ORDER) - 1
    for s in [v.severity for v in vulns] + [f.severity for f in findings if f.severity != "info"]:
        if s in ORDER:
            worst = min(worst, ORDER.index(s))
    return pts, worst


def score_web(w: WebResult) -> None:
    pts, worst = _points(w.vulns, w.findings)
    w.risk_score = int(min(100, pts))
    w.risk_level = level_for(w.risk_score, ORDER[worst])


def score_host(h: HostResult, webs: Iterable[WebResult] = ()) -> None:
    total, worst_rank = 0, len(ORDER) - 1
    for p in h.ports:
        pts, wr = _points(p.vulns, p.findings)
        total += pts
        worst_rank = min(worst_rank, wr)
    for w in webs:
        pts, wr = _points(w.vulns, w.findings)
        total += pts
        worst_rank = min(worst_rank, wr)
    h.risk_score = int(min(100, total))
    h.risk_level = level_for(h.risk_score, ORDER[worst_rank])


def summarize(result: ScanResult) -> Dict:
    zero = lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cve_sev, find_sev, levels = zero(), zero(), zero()
    open_ports = cves = 0
    for h in result.hosts:
        levels[h.risk_level] = levels.get(h.risk_level, 0) + 1
        open_ports += len(h.ports)
        for p in h.ports:
            for v in p.vulns:
                cves += 1
                cve_sev[v.severity] = cve_sev.get(v.severity, 0) + 1
            for f in p.findings:
                find_sev[f.severity] = find_sev.get(f.severity, 0) + 1
    standalone = 0
    for w in result.webs:
        if w.standalone:
            standalone += 1
            levels[w.risk_level] = levels.get(w.risk_level, 0) + 1
        for v in w.vulns:
            cves += 1
            cve_sev[v.severity] = cve_sev.get(v.severity, 0) + 1
        for f in w.findings:
            find_sev[f.severity] = find_sev.get(f.severity, 0) + 1
    return {"assets": len(result.hosts) + standalone, "hosts": len(result.hosts), "webs": len(result.webs),
            "open_ports": open_ports, "cves": cves, "cve_severity": cve_sev,
            "finding_severity": find_sev, "host_levels": levels}

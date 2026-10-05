"""Risk scoring: converts vulnerabilities + findings into a 0-100 host score and a level."""
from __future__ import annotations

from typing import Dict

from models import HostResult, ScanResult

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


def score_host(h: HostResult) -> None:
    total = 0
    worst_rank = 4
    order = ["critical", "high", "medium", "low", "info"]
    for p in h.ports:
        # cap per-port CVE contribution so one old Apache with 300 CVEs doesn't hide everything else
        port_pts = 0
        for v in p.vulns:
            port_pts += _VULN_W.get(v.severity, 0)
            worst_rank = min(worst_rank, order.index(v.severity) if v.severity in order else 4)
        total += min(port_pts, 60)
        for f in p.findings:
            total += _FIND_W.get(f.severity, 0)
            if f.severity in order and f.severity != "info":
                worst_rank = min(worst_rank, order.index(f.severity))
    h.risk_score = int(min(100, total))
    worst = order[worst_rank]
    h.risk_level = level_for(h.risk_score, worst)


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
    return {"hosts": len(result.hosts), "open_ports": open_ports, "cves": cves,
            "cve_severity": cve_sev, "finding_severity": find_sev, "host_levels": levels}

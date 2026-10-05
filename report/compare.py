"""Diff two scan JSON files: new/gone hosts, opened/closed ports, version changes, new/fixed CVEs."""
from __future__ import annotations

import ipaddress
import json
from typing import Dict, List

from utils.ui import UI, c


def load(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or "hosts" not in data:
        raise ValueError("%s is not a VulnScan JSON report" % path)
    return data


def _ipkey(ip: str):
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def _index(scan: Dict) -> Dict[str, Dict[int, Dict]]:
    out: Dict[str, Dict[int, Dict]] = {}
    for h in scan.get("hosts", []):
        out[h["ip"]] = {p["port"]: p for p in h.get("ports", [])}
    return out


def compare_scans(old: Dict, new: Dict) -> Dict:
    o, n = _index(old), _index(new)
    diff: Dict = {"new_hosts": sorted(set(n) - set(o), key=_ipkey),
                  "gone_hosts": sorted(set(o) - set(n), key=_ipkey), "hosts": {}}
    for ip in sorted(set(o) & set(n), key=_ipkey):
        op, np_ = o[ip], n[ip]
        entry: Dict[str, List] = {"opened": sorted(set(np_) - set(op)), "closed": sorted(set(op) - set(np_)),
                                  "changed": [], "new_cves": [], "fixed_cves": []}
        for port in sorted(set(op) & set(np_)):
            a, b = op[port], np_[port]
            if (a.get("product"), a.get("version")) != (b.get("product"), b.get("version")):
                entry["changed"].append({"port": port,
                                         "from": ("%s %s" % (a.get("product") or "", a.get("version") or "")).strip() or "-",
                                         "to": ("%s %s" % (b.get("product") or "", b.get("version") or "")).strip() or "-"})
            ca = {v["cve_id"] for v in a.get("vulns", [])}
            cb = {v["cve_id"] for v in b.get("vulns", [])}
            entry["new_cves"] += [(port, x) for x in sorted(cb - ca)]
            entry["fixed_cves"] += [(port, x) for x in sorted(ca - cb)]
        for port in entry["opened"]:
            entry["new_cves"] += [(port, v["cve_id"]) for v in np_[port].get("vulns", [])]
        for port in entry["closed"]:
            entry["fixed_cves"] += [(port, v["cve_id"]) for v in op[port].get("vulns", [])]
        if any(entry[k] for k in entry):
            diff["hosts"][ip] = entry
    return diff


def print_diff(ui: UI, d: Dict) -> int:
    changes = len(d["new_hosts"]) + len(d["gone_hosts"]) + len(d["hosts"])
    ui._p(c("=" * 62, "bold"))
    ui._p(c(" SCAN COMPARISON", "bold"))
    ui._p(c("=" * 62, "bold"))
    for ip in d["new_hosts"]:
        ui._p(c(" + NEW HOST   %s" % ip, "yellow"))
    for ip in d["gone_hosts"]:
        ui._p(c(" - GONE HOST  %s" % ip, "dim"))
    for ip, e in d["hosts"].items():
        ui._p(" %s" % ip)
        for p in e["opened"]:
            ui._p(c("     + port %d/tcp now OPEN" % p, "red"))
        for p in e["closed"]:
            ui._p(c("     - port %d/tcp now closed" % p, "green"))
        for ch in e["changed"]:
            ui._p("     ~ port %d: %s -> %s" % (ch["port"], ch["from"], ch["to"]))
        for port, cve in e["new_cves"]:
            ui._p(c("     + NEW  %s (port %d)" % (cve, port), "red"))
        for port, cve in e["fixed_cves"]:
            ui._p(c("     - FIXED %s (port %d)" % (cve, port), "green"))
    if not changes:
        ui._p(" No differences between the two scans.")
    ui._p(c("=" * 62, "bold"))
    return changes

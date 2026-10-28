"""Lightweight OS fingerprinting: ICMP TTL + open-port hints + banner keywords. Nmap -O overrides when available."""
from __future__ import annotations

from typing import Tuple

from models import HostResult

_WIN_PORTS = {135, 139, 445, 3389, 5985, 5986}


def guess(host: HostResult) -> Tuple[str, str]:
    banners = " ".join(p.banner for p in host.ports).lower()
    ports = {p.port for p in host.ports}
    products = " ".join((p.product or "") for p in host.ports).lower()

    if "microsoft" in banners or "microsoft" in products or "win32" in banners or "win64" in banners:
        return "Windows", "banner"
    for kw, name in (("ubuntu", "Linux (Ubuntu)"), ("debian", "Linux (Debian)"),
                     ("centos", "Linux (CentOS)"), ("red hat", "Linux (RHEL)"),
                     ("fedora", "Linux (Fedora)"), ("raspbian", "Linux (Raspbian)"),
                     ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD")):
        if kw in banners:
            return name, "banner"

    ttl = host.ttl
    if ttl is not None:
        if ttl <= 64:
            base = "Linux/Unix/macOS"
        elif ttl <= 128:
            base = "Windows"
        else:
            base = "Network device / Solaris"
        if base == "Linux/Unix/macOS" and len(ports & _WIN_PORTS) >= 2:
            return "Windows (port profile)", "ports"
        return base, "ttl=%d" % ttl
    if len(ports & _WIN_PORTS) >= 2:
        return "Windows (port profile)", "ports"
    if 22 in ports and not (ports & _WIN_PORTS):
        return "Linux/Unix (likely)", "ports"
    return "Unknown", ""

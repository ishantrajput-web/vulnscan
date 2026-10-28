"""Optional Nmap integration (no python-nmap needed). Parses nmap's XML. Silent fallback if anything fails."""
from __future__ import annotations

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from utils.net import is_admin

_WIN_PATHS = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]


def find_nmap() -> Optional[str]:
    p = shutil.which("nmap")
    if p:
        return p
    if os.name == "nt":
        for cand in _WIN_PATHS:
            if os.path.isfile(cand):
                return cand
    return None


def version() -> str:
    exe = find_nmap()
    if not exe:
        return ""
    try:
        cp = subprocess.run([exe, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, timeout=10)
        return cp.stdout.decode("utf-8", "replace").splitlines()[0].strip()
    except Exception:
        return ""


def _run(cmd: List[str], timeout: int):
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL, timeout=timeout, **kw)


def scan(ip: str, ports: List[int], os_detect: bool = True, timeout: int = 300) -> Optional[Dict]:
    """Returns {'ports': {port: {...}}, 'os': str|None, 'os_accuracy': int} or None on any failure."""
    exe = find_nmap()
    if not exe or not ports:
        return None
    base = [exe, "-Pn", "-n", "-sV", "--version-light", "-T4", "-p", ",".join(str(p) for p in ports),
            "--host-timeout", "%ds" % max(30, timeout - 10), "-oX", "-"]
    if ":" in ip:
        base.append("-6")
    attempts = []
    if os_detect and is_admin():
        attempts.append(base + ["-O", "--osscan-guess", ip])
    attempts.append(base + [ip])
    for cmd in attempts:
        try:
            cp = _run(cmd, timeout)
            if not cp.stdout.strip():
                continue
            parsed = _parse(cp.stdout)
            if parsed is not None:
                return parsed
        except (subprocess.TimeoutExpired, OSError, ET.ParseError, ValueError):
            continue
    return None


def _parse(xml_bytes: bytes) -> Optional[Dict]:
    root = ET.fromstring(xml_bytes)
    host = root.find("host")
    if host is None:
        return None
    out: Dict = {"ports": {}, "os": None, "os_accuracy": 0}
    for p in host.findall("./ports/port"):
        st = p.find("state")
        if st is None or st.get("state") != "open":
            continue
        svc = p.find("service")
        d = {"service": None, "product": None, "version": None, "extrainfo": None}
        if svc is not None:
            d["service"] = svc.get("name")
            d["product"] = svc.get("product")
            d["version"] = svc.get("version")
            d["extrainfo"] = svc.get("extrainfo")
        out["ports"][int(p.get("portid"))] = d
    best = None
    for m in host.findall("./os/osmatch"):
        acc = int(m.get("accuracy", "0") or 0)
        if best is None or acc > best[1]:
            best = (m.get("name"), acc)
    if best:
        out["os"], out["os_accuracy"] = best
    return out

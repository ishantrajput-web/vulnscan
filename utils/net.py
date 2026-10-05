"""Target / port parsing and validation. Only ever raises TargetError."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from typing import List


class TargetError(ValueError):
    pass


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 119, 123, 135, 137, 139, 143, 161,
    179, 389, 443, 445, 465, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 636, 873, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049,
    2082, 2083, 2181, 2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4443, 4848,
    5000, 5060, 5432, 5601, 5672, 5900, 5901, 5985, 5986, 6000, 6379, 6443, 7001,
    7077, 8000, 8008, 8080, 8081, 8088, 8443, 8444, 8500, 8888, 9000, 9042, 9090,
    9092, 9200, 9300, 9418, 9443, 9999, 10000, 11211, 15672, 27017, 27018, 50000,
]


def _check_size(n: int, max_hosts: int) -> None:
    if n > max_hosts:
        raise TargetError(
            "Target expands to %d hosts (limit %d). Use a smaller range or raise --max-hosts."
            % (n, max_hosts))


def _expand_token(tok: str, max_hosts: int) -> List[str]:
    tok = tok.strip()
    if not tok:
        return []
    if "/" in tok:  # CIDR
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError as e:
            raise TargetError("Invalid CIDR '%s': %s" % (tok, e))
        _check_size(net.num_addresses, max_hosts + 2)
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        return [str(h) for h in hosts]
    if "-" in tok and ":" not in tok:  # range a.b.c.d-e  or  a.b.c.d-w.x.y.z
        left, right = tok.split("-", 1)
        try:
            start = ipaddress.ip_address(left.strip())
            if re.fullmatch(r"\d{1,3}", right.strip()):
                base = left.strip().rsplit(".", 1)[0]
                end = ipaddress.ip_address("%s.%s" % (base, right.strip()))
            else:
                end = ipaddress.ip_address(right.strip())
        except ValueError:
            # could still be a hostname containing '-'
            return _resolve(tok)
        if int(end) < int(start):
            start, end = end, start
        _check_size(int(end) - int(start) + 1, max_hosts)
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
    try:
        return [str(ipaddress.ip_address(tok))]
    except ValueError:
        return _resolve(tok)


def _resolve(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        raise TargetError("Cannot resolve host '%s'" % host)
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
    chosen = v4[:1] or v6[:1]
    if not chosen:
        raise TargetError("Cannot resolve host '%s'" % host)
    return chosen


def parse_targets(spec: str, max_hosts: int = 4096) -> List[str]:
    """'10.0.0.0/24,host.local,192.168.1.5-20' -> unique ordered list of IPs."""
    if not spec or not spec.strip():
        raise TargetError("No target given.")
    seen, out = set(), []
    for tok in re.split(r"[,\s]+", spec.strip()):
        for ip in _expand_token(tok, max_hosts):
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        _check_size(len(out), max_hosts)
    if not out:
        raise TargetError("Target produced no hosts.")
    return out


def parse_ports(spec: str) -> List[int]:
    s = (spec or "").strip().lower()
    if s in ("top", "default", "common"):
        return sorted(set(TOP_PORTS))
    if s in ("all", "full"):
        return list(range(1, 65536))
    if s in ("well-known", "wellknown"):
        return list(range(1, 1025))
    ports = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                a, b = int(a), int(b)
                if a > b:
                    a, b = b, a
                rng = range(a, b + 1)
            else:
                rng = range(int(part), int(part) + 1)
        except ValueError:
            raise TargetError("Invalid port spec '%s'" % part)
        for p in rng:
            if not 1 <= p <= 65535:
                raise TargetError("Port %d out of range 1-65535" % p)
            ports.add(p)
    if not ports:
        raise TargetError("No ports selected.")
    return sorted(ports)


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


def is_admin() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return False

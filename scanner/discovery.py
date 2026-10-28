"""Host discovery: ICMP ping (via system ping, no admin needed) + TCP probes, run together.
A TCP RST (connection refused) also proves a host is up, so firewalled-ICMP hosts are still found."""
from __future__ import annotations

import asyncio
import ipaddress
import math
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, Optional, Tuple

from models import HostResult

PROBE_PORTS = (80, 443, 22, 445, 135, 3389, 21, 8080)
_TTL_RE = re.compile(r"ttl[=:\s]*(\d+)", re.I)
_RTT_RE = re.compile(r"(?:time|zeit|temps|tiempo|tempo)\s*[=<]\s*([\d.,]+)\s*ms", re.I)


def _ping_blocking(ip: str, timeout: float) -> Tuple[bool, Optional[float], Optional[int]]:
    is_win = os.name == "nt"
    if is_win:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif sys.platform == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(math.ceil(timeout)))), ip]
    kwargs = {}
    if is_win:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, timeout=timeout + 3, **kwargs)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError, ValueError):
        return False, None, None
    out = cp.stdout.decode("utf-8", "replace")
    m = _TTL_RE.search(out)
    ttl = int(m.group(1)) if m else None
    rtt = None
    r = _RTT_RE.search(out)
    if r:
        try:
            rtt = float(r.group(1).replace(",", "."))
        except ValueError:
            rtt = None
    # Windows returns 0 even for "Destination host unreachable" -> demand a TTL there.
    alive = ttl is not None or (cp.returncode == 0 and not is_win)
    return alive, rtt, ttl


async def _tcp_alive(ip: str, timeout: float) -> bool:
    async def one(port: int) -> bool:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
            try:
                w.close()
            except Exception:
                pass
            return True
        except (ConnectionRefusedError, ConnectionResetError):
            return True  # RST => something is there
        except Exception:
            return False

    results = await asyncio.gather(*(one(p) for p in PROBE_PORTS))
    return any(results)


async def discover(ips: List[str], timeout: float = 1.5, concurrency: int = 32,
                   progress: Optional[Callable[[int, int], None]] = None) -> List[HostResult]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(max(1, min(concurrency, 32)))  # 32*8 probes stays under Windows' 512 FD select limit
    executor = ThreadPoolExecutor(max_workers=32)
    total, done = len(ips), 0
    alive: List[HostResult] = []

    async def check(ip: str) -> None:
        nonlocal done
        async with sem:
            ping_f = loop.run_in_executor(executor, _ping_blocking, ip, timeout)
            tcp_f = _tcp_alive(ip, timeout)
            (p_alive, rtt, ttl), t_alive = await asyncio.gather(ping_f, tcp_f)
        done += 1
        if progress:
            progress(done, total)
        if p_alive or t_alive:
            alive.append(HostResult(ip=ip, alive=True, rtt_ms=rtt, ttl=ttl))

    try:
        await asyncio.gather(*(check(ip) for ip in ips))
    finally:
        executor.shutdown(wait=False)
    alive.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return alive

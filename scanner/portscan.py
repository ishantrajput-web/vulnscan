"""Async TCP connect scanner with FD-exhaustion protection (the #1 cause of false 'closed' results)."""
from __future__ import annotations

import asyncio
import os
from typing import Callable, List, Optional

_RETRY_ERRNOS = {24, 23, 105, 10055, 10024}  # EMFILE, ENFILE, ENOBUFS, WSAENOBUFS, WSAEMFILE


def safe_concurrency(requested: int) -> int:
    """Clamp concurrency to what the OS can really handle."""
    cap = 400 if os.name == "nt" else 1000   # Windows select() loop limit is 512 sockets
    if os.name != "nt":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            want = 4096 if hard == resource.RLIM_INFINITY else min(4096, hard)
            if soft < want:
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
                    soft = want
                except (ValueError, OSError):
                    pass
            cap = max(50, min(cap, soft - 150))
        except Exception:
            cap = 300
    return max(1, min(int(requested), cap))


async def probe(ip: str, port: int, timeout: float) -> str:
    """Returns 'open', 'closed' or 'filtered'."""
    for attempt in range(4):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except (asyncio.TimeoutError, TimeoutError):
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError as e:
            if e.errno in _RETRY_ERRNOS:        # we ran out of sockets: back off, never misreport
                await asyncio.sleep(0.25 * (attempt + 1))
                continue
            if isinstance(e, ConnectionError):
                return "closed"
            return "filtered"
        else:
            try:
                w.close()
                await asyncio.wait_for(w.wait_closed(), 0.5)
            except Exception:
                pass
            return "open"
    return "filtered"


async def scan_host(ip: str, ports: List[int], sem: asyncio.Semaphore, timeout: float,
                    on_done: Optional[Callable[[], None]] = None, chunk: int = 2000) -> List[int]:
    open_ports: List[int] = []

    async def one(p: int) -> None:
        async with sem:
            state = await probe(ip, p, timeout)
        if state == "open":
            open_ports.append(p)
        if on_done:
            on_done()

    for i in range(0, len(ports), chunk):
        await asyncio.gather(*(one(p) for p in ports[i:i + chunk]))
    open_ports.sort()
    return open_ports

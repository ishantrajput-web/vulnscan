"""Scan pipeline: discovery -> port scan -> banners/services -> (nmap) -> CVE -> findings & scoring."""
from __future__ import annotations

import asyncio
import logging
import socket
import threading
from dataclasses import dataclass, field
from typing import List, Optional

from models import HostResult, PortResult, ScanResult
from report import scoring
from scanner import banner as bannermod
from scanner import checks, discovery, nmap_engine, osdetect, portscan, services
from scanner.cve import CVEResolver
from utils.ui import UI


@dataclass
class ScanConfig:
    ips: List[str]
    ports: List[int]
    timeout: float = 1.5
    concurrency: int = 300
    skip_discovery: bool = False
    use_nmap: bool = False
    cve: bool = True
    online: bool = True
    nvd_key: Optional[str] = None
    grab_banners: bool = True
    cache_dir: Optional[str] = None


def _rdns_blocking(ip: str, timeout: float = 2.0) -> Optional[str]:
    res: List[Optional[str]] = [None]

    def work() -> None:
        try:
            res[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=work, daemon=True)   # daemon: a hung DNS lookup can never block exit
    t.start()
    t.join(timeout)
    return res[0]


def finalize(result: ScanResult) -> None:
    """Idempotent: recompute findings + scores from current data (also used for partial results)."""
    for h in result.hosts:
        for p in h.ports:
            p.findings = checks.evaluate(p)
        scoring.score_host(h)


async def run_scan(cfg: ScanConfig, result: ScanResult, ui: UI) -> None:
    loop = asyncio.get_running_loop()
    conc = portscan.safe_concurrency(cfg.concurrency)
    if conc != cfg.concurrency:
        ui.info("Concurrency adjusted to %d (OS limit)." % conc)
    total_phases = 5 if cfg.cve else 4

    # ---------- 1. discovery
    ui.phase(1, total_phases, "Host discovery (%d address%s)" % (len(cfg.ips), "" if len(cfg.ips) == 1 else "es"))
    if cfg.skip_discovery:
        hosts = [HostResult(ip=ip) for ip in cfg.ips]
    else:
        hosts = await discovery.discover(cfg.ips, cfg.timeout, 32, lambda d, t: ui.progress(d, t, "hosts"))
        if not hosts and len(cfg.ips) <= 4:
            ui.warn("No ping/TCP response - host may block probes. Scanning ports anyway.")
            hosts = [HostResult(ip=ip, alive=False) for ip in cfg.ips]
    result.hosts = hosts
    result.meta["addresses_scanned"] = len(cfg.ips)
    ui.ok("%d live host(s)" % len(hosts))
    if not hosts:
        return
    names = await asyncio.gather(*(loop.run_in_executor(None, _rdns_blocking, h.ip) for h in hosts[:256]))
    for h, n in zip(hosts, names):
        h.hostname = n

    # ---------- 2. port scan
    ui.phase(2, total_phases, "Port scan (%d ports x %d host(s))" % (len(cfg.ports), len(hosts)))
    sem = asyncio.Semaphore(conc)
    host_sem = asyncio.Semaphore(8)
    total = len(cfg.ports) * len(hosts)
    counter = [0]

    def tick() -> None:
        counter[0] += 1
        ui.progress(counter[0], total, "probes")

    async def scan_one(h: HostResult) -> None:
        async with host_sem:
            op = await portscan.scan_host(h.ip, cfg.ports, sem, cfg.timeout, tick)
            h.ports = [PortResult(port=p) for p in op]
            if op:
                h.alive = True

    await asyncio.gather(*(scan_one(h) for h in hosts))
    n_open = sum(len(h.ports) for h in hosts)
    ui.ok("%d open port(s)" % n_open)

    # ---------- 3. banners + services
    ui.phase(3, total_phases, "Banner grabbing & service detection")
    jobs = [(h, p) for h in hosts for p in h.ports]
    done = [0]

    async def banner_job(h: HostResult, p: PortResult) -> None:
        async with sem:
            try:
                if cfg.grab_banners:
                    info = await bannermod.grab(h.ip, p.port, max(cfg.timeout, 2.0), h.hostname)
                    p.banner, p.tls, p.tls_version = info.banner, info.tls, info.tls_version
                    p.tls_error = None if info.tls else info.tls_error
                    if p.tls_error:
                        logging.getLogger("vulnscan").info("TLS handshake failed %s:%d %s", h.ip, p.port, p.tls_error)
            except Exception:
                pass
        p.service, p.product, p.version = services.identify(p.port, p.banner, p.tls)
        done[0] += 1
        ui.progress(done[0], len(jobs), "ports")

    if jobs:
        await asyncio.gather(*(banner_job(h, p) for h, p in jobs))
    for h in hosts:
        h.os_guess, h.os_source = osdetect.guess(h)

    # ---------- optional nmap enrichment
    if cfg.use_nmap:
        exe = nmap_engine.find_nmap()
        if not exe:
            ui.warn("Nmap not found - continuing with the built-in engine (install Nmap to enable --nmap).")
        else:
            ui.info("Enriching with Nmap (%s)..." % (nmap_engine.version() or exe))
            for h in hosts:
                if not h.ports:
                    continue
                data = await loop.run_in_executor(None, nmap_engine.scan, h.ip, [p.port for p in h.ports], True, 300)
                if not data:
                    ui.warn("Nmap returned no data for %s - keeping built-in results." % h.ip)
                    continue
                for p in h.ports:
                    d = data["ports"].get(p.port)
                    if not d:
                        continue
                    if d.get("service") and d["service"] not in ("unknown", "tcpwrapped"):
                        p.service = d["service"] if not p.tls else p.service
                    if d.get("product"):
                        p.product = d["product"]
                        ver = services.clean_version(d.get("version"))
                        if ver:
                            p.version = ver
                if data.get("os"):
                    h.os_guess, h.os_source = data["os"], "nmap (%d%%)" % data.get("os_accuracy", 0)

    # ---------- 4. CVE
    if cfg.cve:
        ui.phase(4, total_phases, "CVE correlation")
        resolver = CVEResolver(cfg.cache_dir, cfg.nvd_key, cfg.online, notify=ui.warn)
        uniq = sorted({(p.product, p.version) for h in hosts for p in h.ports if p.product and p.version})
        cache = {}
        if uniq and cfg.online and not resolver.api_key:
            ui.info("Querying NIST NVD for %d unique service version(s) (rate-limited, results are cached)..." % len(uniq))
        for i, (prod, ver) in enumerate(uniq, 1):
            cache[(prod, ver)] = await loop.run_in_executor(None, resolver.lookup, prod, ver)
            ui.progress(i, len(uniq), "lookups")
        for h in hosts:
            for p in h.ports:
                p.vulns = list(cache.get((p.product, p.version), []))
        result.meta["cve_sources"] = resolver.stats
        result.meta["nvd_online"] = resolver.online
        ui.ok("%d CVE match(es)" % sum(len(p.vulns) for h in hosts for p in h.ports))

    # ---------- last. findings + scoring
    ui.phase(total_phases, total_phases, "Risk analysis")
    finalize(result)

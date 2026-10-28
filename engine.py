"""Scan pipeline: [discovery -> port scan -> banners] -> web analysis -> CVE -> findings & scoring."""
from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import socket
import threading
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from models import HostResult, PortResult, ScanResult, WebResult
from report import scoring
from scanner import banner as bannermod
from scanner import checks, discovery, nmap_engine, osdetect, portscan, services, webcheck
from scanner.cve import CVEResolver
from utils.ui import UI

log = logging.getLogger("vulnscan")


@dataclass
class ScanConfig:
    ips: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)          # explicit website targets
    names: Dict[str, str] = field(default_factory=dict)    # ip -> hostname (for Host header / SNI)
    timeout: float = 1.5
    concurrency: int = 300
    skip_discovery: bool = False
    use_nmap: bool = False
    cve: bool = True
    online: bool = True
    nvd_key: Optional[str] = None
    grab_banners: bool = True
    web: bool = True                 # analyse every web service found (and explicit URLs)
    dns_checks: bool = True
    cache_dir: Optional[str] = None

    @property
    def web_only(self) -> bool:
        return not self.ips


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


def _port_of(url: str) -> int:
    p = urllib.parse.urlsplit(url)
    try:
        return p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return 0


def finalize(result: ScanResult) -> None:
    """Idempotent: recompute findings + scores from current data (also used for partial results)."""
    covered = {(w.host_ip, _port_of(w.url)) for w in result.webs if not w.standalone}
    for h in result.hosts:
        for p in h.ports:
            fl = checks.evaluate(p)
            if (h.ip, p.port) in covered:      # web analysis already covers headers / cleartext HTTP
                fl = [f for f in fl if not f.title.startswith(("Missing HTTP security headers", "Unencrypted HTTP service"))]
            p.findings = fl
    for w in result.webs:
        scoring.score_web(w)
    attached = {}
    for w in result.webs:
        if not w.standalone:
            attached.setdefault(w.host_ip, []).append(w)
    for h in result.hosts:
        scoring.score_host(h, attached.get(h.ip, []))


def _url_for(ip: str, name: Optional[str], p: PortResult) -> str:
    scheme = "https" if (p.tls or p.service == "https") else "http"
    host = name or (("[%s]" % ip) if ":" in ip else ip)
    default = 443 if scheme == "https" else 80
    return "%s://%s%s/" % (scheme, host, "" if p.port == default else ":%d" % p.port)


async def run_scan(cfg: ScanConfig, result: ScanResult, ui: UI) -> None:
    loop = asyncio.get_running_loop()
    conc = portscan.safe_concurrency(cfg.concurrency)
    if conc != cfg.concurrency and not cfg.web_only:
        ui.info("Concurrency adjusted to %d (OS limit)." % conc)

    steps = []
    if not cfg.web_only:
        steps += ["Host discovery", "Port scan", "Banner grabbing & service detection"]
    if cfg.web:
        steps.append("Web analysis")
    if cfg.cve:
        steps.append("CVE correlation")
    steps.append("Risk analysis")
    state = {"i": 0}

    def phase(title: str) -> None:
        state["i"] += 1
        ui.phase(state["i"], len(steps), title)

    hosts: List[HostResult] = []
    sem = asyncio.Semaphore(conc)

    # ================= network phases =================
    if not cfg.web_only:
        phase("Host discovery (%d address%s)" % (len(cfg.ips), "" if len(cfg.ips) == 1 else "es"))
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
        if hosts:
            names = await asyncio.gather(*(loop.run_in_executor(None, _rdns_blocking, h.ip) for h in hosts[:256]))
            for h, n in zip(hosts, names):
                h.hostname = n or cfg.names.get(h.ip)

        phase("Port scan (%d ports x %d host(s))" % (len(cfg.ports), len(hosts)))
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

        if hosts:
            await asyncio.gather(*(scan_one(h) for h in hosts))
        ui.ok("%d open port(s)" % sum(len(h.ports) for h in hosts))

        phase("Banner grabbing & service detection")
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
                            log.info("TLS handshake failed %s:%d %s", h.ip, p.port, p.tls_error)
                except Exception:
                    pass
            p.service, p.product, p.version = services.identify(p.port, p.banner, p.tls)
            done[0] += 1
            ui.progress(done[0], len(jobs), "ports")

        if jobs:
            await asyncio.gather(*(banner_job(h, p) for h, p in jobs))
        for h in hosts:
            h.os_guess, h.os_source = osdetect.guess(h)

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

    # ================= web analysis =================
    if cfg.web:
        phase("Web analysis")
        targets = [(u, True, "") for u in cfg.urls]
        for h in hosts:
            for p in h.ports:
                if p.service in ("http", "https") or (p.tls and p.banner.startswith("HTTP/")):
                    targets.append((_url_for(h.ip, cfg.names.get(h.ip), p), False, h.ip))
        seen, uniq = set(), []
        for u, standalone, ip in targets:
            if u not in seen:
                seen.add(u)
                uniq.append((u, standalone, ip))
        if not uniq:
            ui.ok("no web services to analyse")
        else:
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=8)
            done_w = [0]

            async def one(u: str, standalone: bool, ip: str) -> WebResult:
                try:
                    w = await asyncio.wait_for(
                        loop.run_in_executor(ex, webcheck.analyze, u, 6.0, cfg.dns_checks), 120)
                except Exception as e:                      # timeout or unexpected bug: never abort the scan
                    w = WebResult(url=u, error="%s: %s" % (type(e).__name__, e))
                w.standalone = standalone
                if ip:
                    w.host_ip = ip
                done_w[0] += 1
                ui.progress(done_w[0], len(uniq), "sites")
                return w

            try:
                result.webs = list(await asyncio.gather(*(one(*t) for t in uniq)))
            finally:
                ex.shutdown(wait=False)
            ui.ok("%d web origin(s) analysed, %d finding(s)" % (len(result.webs), sum(
                1 for w in result.webs for f in w.findings if f.severity != "info")))

    # ================= CVE =================
    if cfg.cve:
        phase("CVE correlation")
        resolver = CVEResolver(cfg.cache_dir, cfg.nvd_key, cfg.online, notify=ui.warn)
        keys = {(p.product, p.version) for h in hosts for p in h.ports if p.product and p.version}
        keys |= {(t["product"], t["version"]) for w in result.webs for t in w.techs if t.get("product") and t.get("version")}
        uniq_keys = sorted(keys)
        cache = {}
        if uniq_keys and cfg.online and not resolver.api_key:
            ui.info("Querying NIST NVD for %d unique version(s) (rate-limited, results are cached)..." % len(uniq_keys))
        for i, (prod, ver) in enumerate(uniq_keys, 1):
            cache[(prod, ver)] = await loop.run_in_executor(None, resolver.lookup, prod, ver)
            ui.progress(i, len(uniq_keys), "lookups")
        for h in hosts:
            for p in h.ports:
                p.vulns = list(cache.get((p.product, p.version), []))
        port_of = {(h.ip, p.port): p for h in hosts for p in h.ports}
        for w in result.webs:
            seen_ids, vl = set(), []
            owner = port_of.get((w.host_ip, _port_of(w.url))) if not w.standalone else None
            for t in w.techs:
                if owner is not None and (owner.product, owner.version) == (t.get("product"), t.get("version")):
                    continue            # same product already reported on the port: don't count CVEs twice
                for v in cache.get((t.get("product"), t.get("version")), []):
                    if v.cve_id not in seen_ids:
                        seen_ids.add(v.cve_id)
                        vl.append(v)
            w.vulns = vl
        result.meta["cve_sources"] = resolver.stats
        result.meta["nvd_online"] = resolver.online
        ui.ok("%d CVE match(es)" % (sum(len(p.vulns) for h in hosts for p in h.ports) + sum(len(w.vulns) for w in result.webs)))

    phase("Risk analysis")
    finalize(result)


def plan_targets(spec: str, ports_spec: str = "top", max_hosts: int = 4096, with_ports: bool = False):
    """Parse a mixed target string. Returns (ips, urls, names, gate_ips, ports); raises TargetError.
    gate_ips = every address that will be touched (used for the authorisation check)."""
    from utils.net import TargetError, name_map, parse_ports, parse_targets, split_targets, url_host
    nets, urls = split_targets(spec)
    ips = parse_targets(",".join(nets), max_hosts) if nets else []
    names = name_map(nets)
    gate = list(ips)
    for u in urls:
        host = url_host(u)
        if not host:
            raise TargetError("Invalid URL: %s" % u)
        resolved = parse_targets(host, 16)
        gate += [i for i in resolved if i not in gate]
        if with_ports:
            for i in resolved:
                if i not in ips:
                    ips.append(i)
                names.setdefault(i, host)
    if not ips and not urls:
        raise TargetError("No target given.")
    return ips, urls, names, gate, parse_ports(ports_spec)

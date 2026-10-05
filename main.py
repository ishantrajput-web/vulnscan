#!/usr/bin/env python3
"""VulnScan - Network Vulnerability Scanner. For authorised security assessments only."""
import sys

if sys.version_info < (3, 8):
    sys.exit("Python 3.8 or newer is required.")

import argparse
import asyncio
import datetime as dt
import json
import logging
import os
import platform
import time
import traceback
import urllib.request
import uuid
import warnings

from engine import ScanConfig, finalize, run_scan
from models import SEVERITY_ORDER, ScanResult
from report import scoring
from scanner import __version__, nmap_engine
from utils.net import TargetError, is_admin, is_private, parse_ports, parse_targets
from utils.ui import SEV_COLOR, UI, c

EPILOG = """examples:
  py main.py 192.168.1.0/24                       (Windows: use 'py'; Linux/Kali: 'python3')
  py main.py 192.168.1.10 -p 1-1024 --nmap
  py main.py 10.0.0.5-20 -p 22,80,443,3306 -o results --format pdf,json
  py main.py 192.168.1.10 --fail-on high           (exit code 4 if High/Critical found - for CI)
  py main.py --compare old_report.json new_report.json
  py main.py --doctor
"""
log = logging.getLogger("vulnscan")
_file_handler = None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnscan", description=__doc__, epilog=EPILOG,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", nargs="?", help="IP, CIDR, range (10.0.0.5-20), hostname, or comma-separated mix")
    p.add_argument("-p", "--ports", default="top",
                   help="'top' (default, ~100 common), 'well-known' (1-1024), 'all', or e.g. 22,80,8000-8100")
    p.add_argument("-t", "--timeout", type=float, default=1.5, help="per-connection timeout, seconds (default 1.5)")
    p.add_argument("-c", "--concurrency", type=int, default=300, help="parallel connections (auto-clamped to OS limits)")
    p.add_argument("-Pn", "--no-ping", action="store_true", help="skip host discovery, treat all targets as up")
    p.add_argument("--nmap", action="store_true", help="enrich service/OS detection with Nmap if installed")
    p.add_argument("--no-cve", action="store_true", help="skip CVE lookup")
    p.add_argument("--offline", action="store_true", help="don't call the NVD API; use cache + built-in CVE database")
    p.add_argument("--nvd-key", default=None, help="NVD API key (or env NVD_API_KEY) for faster lookups")
    p.add_argument("--no-banners", action="store_true", help="skip banner grabbing")
    p.add_argument("-o", "--output", default="reports", help="output directory (default: reports)")
    p.add_argument("--format", default="json,html,pdf", help="comma list of: json,html,pdf")
    p.add_argument("--max-hosts", type=int, default=4096, help="safety limit on expanded targets")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default=None,
                   help="exit with code 4 if anything at/above this severity is found (CI/CD gate)")
    p.add_argument("--compare", nargs=2, metavar=("OLD.json", "NEW.json"), help="show what changed between two scans")
    p.add_argument("-y", "--yes", action="store_true", help="confirm authorisation non-interactively (private ranges only)")
    p.add_argument("-q", "--quiet", action="store_true", help="minimal output")
    p.add_argument("--doctor", action="store_true", help="check environment & dependencies, then exit")
    p.add_argument("--version", action="version", version="vulnscan %s" % __version__)
    return p


# ------------------------------------------------------------------ helpers
def run_async(coro):
    """Run a coroutine on a Selector loop on Windows (no Proactor noise) without deprecated policy APIs."""
    if os.name == "nt":
        if sys.version_info >= (3, 11):
            with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
                return runner.run(coro)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            except Exception:
                pass
        return asyncio.run(coro)
    return asyncio.run(coro)


def setup_logging(outdir: str, scan_id: str):
    global _file_handler
    try:
        path = os.path.join(outdir, "scan_%s.log" % scan_id)
        _file_handler = logging.FileHandler(path, encoding="utf-8")
        _file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.setLevel(logging.INFO)
        log.propagate = False
        log.addHandler(_file_handler)
        return path
    except Exception:
        _file_handler = None
        return None


def teardown_logging() -> None:
    """Close the log file (Windows cannot delete/move a file that is still open)."""
    global _file_handler
    if _file_handler is not None:
        try:
            log.removeHandler(_file_handler)
            _file_handler.close()
        finally:
            _file_handler = None


def doctor(ui: UI) -> int:
    ui.banner(__version__)
    ui.info("Python        : %s (%s)" % (platform.python_version(), platform.platform()))
    ui.info("Privileges    : %s" % ("admin/root" if is_admin() else "standard user (fine; Nmap OS detection needs admin)"))
    nm = nmap_engine.find_nmap()
    if nm:
        ui.ok("Nmap          : %s" % (nmap_engine.version() or nm))
    else:
        ui.warn("Nmap          : not found (optional - built-in engine works without it)")
    try:
        import reportlab
        ui.ok("reportlab     : %s (PDF reports enabled)" % reportlab.Version)
    except ImportError:
        ui.warn("reportlab     : missing -> HTML report used instead. Fix: py -m pip install reportlab")
    try:
        req = urllib.request.Request("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                                     headers={"User-Agent": "VulnScan/1.0"})
        urllib.request.urlopen(req, timeout=8).read(100)
        ui.ok("NVD API       : reachable (live CVE lookups enabled)")
    except Exception as e:
        ui.warn("NVD API       : unreachable (%s) -> built-in CVE database will be used" % type(e).__name__)
    try:
        os.makedirs("reports", exist_ok=True)
        t = os.path.join("reports", ".w")
        open(t, "w").close()
        os.remove(t)
        ui.ok("Output folder : writable")
    except Exception as e:
        ui.err("Output folder not writable: %s" % e)
    return 0


def confirm_authorization(ui: UI, ips, assume_yes: bool) -> bool:
    public = [i for i in ips if not is_private(i)]
    ui.warn("You are about to actively scan %d address(es)." % len(ips))
    ui.warn("Scanning systems without written permission may be illegal.")
    try:
        interactive = sys.stdin is not None and sys.stdin.isatty()
    except Exception:
        interactive = False
    try:
        if public:
            ui.warn("%d target(s) are PUBLIC internet addresses (e.g. %s)." % (len(public), public[0]))
            if not interactive:
                ui.err("Public targets require interactive confirmation (--yes is not accepted for them).")
                return False
            return input('Type "I HAVE PERMISSION" to continue: ').strip().upper() == "I HAVE PERMISSION"
        if assume_yes:
            return True
        if not interactive:
            ui.err("Non-interactive session: pass --yes to confirm you are authorised.")
            return False
        return input("Do you own or have written authorisation to test these targets? [y/N]: ").strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def worst_severity(result: ScanResult) -> str:
    worst = len(SEVERITY_ORDER) - 1
    for h in result.hosts:
        for p in h.ports:
            for s in [v.severity for v in p.vulns] + [f.severity for f in p.findings]:
                if s in SEVERITY_ORDER:
                    worst = min(worst, SEVERITY_ORDER.index(s))
    return SEVERITY_ORDER[worst]


def print_summary(ui: UI, result: ScanResult) -> None:
    s = scoring.summarize(result)
    ui._p("")
    ui._p(c("=" * 62, "bold"))
    ui._p(c(" SCAN SUMMARY", "bold"))
    ui._p(c("=" * 62, "bold"))
    ui._p(" Hosts: %d   Open ports: %d   CVEs: %d   Duration: %.1fs" % (s["hosts"], s["open_ports"], s["cves"], result.duration_s))
    for h in sorted(result.hosts, key=lambda x: -x.risk_score):
        name = (" (%s)" % h.hostname) if h.hostname else ""
        ui._p(" %-16s %s score %3d   OS: %s%s" % (h.ip, c("%-8s" % h.risk_level.upper(), SEV_COLOR[h.risk_level]),
                                                  h.risk_score, h.os_guess, name))
        for p in h.ports:
            pv = ("%s %s" % (p.product or "", p.version or "")).strip()
            title = ""
            for line in p.banner.splitlines():
                if line.startswith("Title: "):
                    title = '  "%s"' % line[7:60]
            worst = max((v.cvss or 0 for v in p.vulns), default=0)
            tag = ("  [%d CVE, max CVSS %.1f]" % (len(p.vulns), worst)) if p.vulns else ""
            ui._p("     %5d/tcp  %-14s %s%s%s" % (p.port, p.service + ("*" if p.tls else ""), pv, title, tag))
    ui._p(c("=" * 62, "bold"))
    ui._p(" * = TLS/SSL")


# ------------------------------------------------------------------ main
def main(argv=None) -> int:
    try:
        return _main(argv)
    finally:
        teardown_logging()


def _main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ui = UI(args.quiet)
    if args.doctor:
        return doctor(ui)
    if args.compare:
        from report.compare import compare_scans, load, print_diff
        try:
            d = compare_scans(load(args.compare[0]), load(args.compare[1]))
        except (OSError, ValueError, KeyError) as e:
            ui.err("Cannot compare: %s" % e)
            return 2
        print_diff(ui, d)
        return 0
    if not args.target:
        parser.print_help()
        return 2

    ui.banner(__version__)
    try:
        ips = parse_targets(args.target, args.max_hosts)
        ports = parse_ports(args.ports)
    except TargetError as e:
        ui.err(str(e))
        return 2
    if args.timeout <= 0 or args.concurrency <= 0:
        ui.err("--timeout and --concurrency must be positive.")
        return 2
    fmts = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    bad = [f for f in fmts if f not in ("json", "html", "pdf")]
    if bad:
        ui.err("Unknown report format(s): %s (use json,html,pdf)" % ", ".join(bad))
        return 2

    scan_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    try:
        os.makedirs(args.output, exist_ok=True)
    except OSError as e:
        ui.err("Cannot create output directory '%s': %s" % (args.output, e))
        return 2

    if not confirm_authorization(ui, ips, args.yes):
        ui.err("Authorisation not confirmed. Aborting - nothing was scanned.")
        return 3
    logpath = setup_logging(args.output, scan_id)
    log.info("scan %s authorised by operator; targets=%s ports=%d", scan_id, args.target, len(ports))

    cfg = ScanConfig(ips=ips, ports=ports, timeout=args.timeout, concurrency=args.concurrency,
                     skip_discovery=args.no_ping, use_nmap=args.nmap, cve=not args.no_cve,
                     online=not args.offline, nvd_key=args.nvd_key, grab_banners=not args.no_banners)
    result = ScanResult(scan_id=scan_id, tool_version=__version__, targets=args.target,
                        started=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    t0 = time.time()
    rc = 0
    try:
        run_async(run_scan(cfg, result, ui))
    except KeyboardInterrupt:
        ui.warn("Interrupted - saving partial results.")
        result.meta["interrupted"] = True
        rc = 130
    except Exception as e:      # never crash without saving what we have
        ui.err("Scan error: %s: %s" % (type(e).__name__, e))
        log.error("scan error\n%s", traceback.format_exc())
        result.meta["error"] = "%s: %s" % (type(e).__name__, e)
        rc = 1
    result.duration_s = round(time.time() - t0, 2)
    result.finished = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    finalize(result)

    if not result.hosts:
        ui.warn("No live hosts found. Try -Pn (skip discovery) if the target blocks ping.")
    print_summary(ui, result)

    base = os.path.join(args.output, "report_%s" % scan_id)
    written = []
    for fmt in fmts:
        try:
            if fmt == "json":
                from report.json_export import write_json
                written.append(write_json(result, base + ".json"))
            elif fmt == "html":
                from report.html_report import write_html
                written.append(write_html(result, base + ".html"))
            elif fmt == "pdf":
                try:
                    from report.pdf_report import write_pdf
                except ImportError:
                    ui.warn("reportlab not installed -> writing HTML instead (py -m pip install reportlab for PDF).")
                    if "html" not in fmts:
                        from report.html_report import write_html
                        written.append(write_html(result, base + ".html"))
                    continue
                written.append(write_pdf(result, base + ".pdf"))
        except Exception as e:
            ui.err("Could not write %s report: %s: %s" % (fmt, type(e).__name__, e))
            log.error("report %s failed\n%s", fmt, traceback.format_exc())
            if rc == 0:
                rc = 1
    for w in written:
        ui.ok("Report: " + w)
    if logpath:
        ui.info("Audit log: " + os.path.abspath(logpath))

    if args.fail_on and rc == 0:
        worst = worst_severity(result)
        if SEVERITY_ORDER.index(worst) <= SEVERITY_ORDER.index(args.fail_on):
            ui.err("Policy gate: found %s severity (threshold: %s). Exit code 4." % (worst.upper(), args.fail_on.upper()))
            rc = 4
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

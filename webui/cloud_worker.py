"""One bounded scan per child process, terminated by the HTTP handler on timeout."""
import base64
import datetime as dt
import json
import os
import sys
import time

from engine import finalize
from models import ScanResult
from report.scoring import summarize
from report.writer import FORMATS, write_reports
from scanner import __version__, webcheck
from scanner.cve import CVEResolver


def scan(target, outdir, scan_id):
    started = time.monotonic()
    result = ScanResult(scan_id=scan_id, tool_version=__version__, targets=target,
                        started=dt.datetime.now(dt.timezone.utc).isoformat())
    web = webcheck.analyze(target, timeout=3.0, do_dns=False, public_only=True)
    result.webs = [web]
    resolver = CVEResolver(cache_dir=outdir, online=False)
    for tech in web.techs:
        web.vulns.extend(resolver.lookup(tech["product"], tech.get("version")))
    result.finished = dt.datetime.now(dt.timezone.utc).isoformat()
    result.duration_s = round(time.monotonic() - started, 2)
    result.meta = {"mode": "serverless", "cve_source": "built-in offline database",
                   "dns_checks": False, "history": "this browser only"}
    finalize(result)
    files, notes = write_reports(result, outdir, list(FORMATS))
    data = result.to_dict()
    data["summary"] = summarize(result)
    reports = {}
    for fmt, path in files.items():
        with open(path, "rb") as stream:
            reports[fmt] = base64.b64encode(stream.read()).decode("ascii")
    return {"id": scan_id, "result": data, "reports": reports, "files": sorted(reports), "notes": notes}


if __name__ == "__main__":
    target, outdir, scan_id = sys.argv[1:]
    payload = scan(target, outdir, scan_id)
    with open(os.path.join(outdir, "response.json"), "w", encoding="utf-8") as stream:
        json.dump(payload, stream)

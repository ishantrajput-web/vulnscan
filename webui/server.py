"""Local web dashboard (standard library only).

Security model - this tool can scan networks, so the UI is locked down:
  * listens on 127.0.0.1 only
  * every API call needs a random per-run token (delivered in the URL #fragment, never sent to any server)
  * Host header must be localhost/127.0.0.1  (blocks DNS-rebinding)
  * no CORS headers, strict Content-Security-Policy, no inline scripts
  * the authorisation gate is enforced HERE on the server, not just in the browser
  * one scan at a time
"""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import os
import re
import secrets
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional
from urllib.parse import parse_qs, urlsplit

from engine import ScanConfig, finalize, plan_targets, run_scan
from models import ScanResult
from report.scoring import summarize
from report.writer import FORMATS, write_reports
from scanner import __version__, nmap_engine
from utils.net import TargetError, is_private
from utils.ui import UI

log = logging.getLogger("vulnscan")
HERE = os.path.dirname(os.path.abspath(__file__))
ID_RE = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{4}$")
PHRASE = "I HAVE PERMISSION"
MIME = {"json": "application/json", "html": "text/html; charset=utf-8", "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
STATIC = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "application/javascript; charset=utf-8"),
          "/app.css": ("app.css", "text/css; charset=utf-8")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src data:; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class ApiError(Exception):
    def __init__(self, status: int, message: str, code: str = "error"):
        super().__init__(message)
        self.status, self.message, self.code = status, message, code


# ------------------------------------------------------------------ job handling
class Job:
    def __init__(self, scan_id: str, target: str):
        self.id, self.target = scan_id, target
        self.status = "running"            # running | done | cancelled | error
        self.phase = (0, 0, "Starting")
        self.progress = (0, 0, "")
        self.logs = []
        self.lock = threading.Lock()
        self.result: Optional[ScanResult] = None
        self.files: Dict[str, str] = {}
        self.error: Optional[str] = None
        self.loop = None
        self.task = None
        self.started = time.time()
        self.cancelled = False

    def log(self, level: str, msg: str) -> None:
        with self.lock:
            if len(self.logs) < 5000:
                self.logs.append({"t": round(time.time() - self.started, 1), "l": level, "m": str(msg)[:500]})

    def cancel(self) -> None:
        self.cancelled = True
        if self.loop is not None and self.task is not None:
            try:
                self.loop.call_soon_threadsafe(self.task.cancel)
            except RuntimeError:
                pass


class LiveUI(UI):
    """Same interface as the console UI, but feeds the Job so the browser can show live progress."""

    def __init__(self, job: Job):
        super().__init__(False)
        self.job = job

    def _p(self, msg: str = "") -> None:
        pass

    def banner(self, version: str) -> None:
        pass

    def phase(self, i: int, n: int, name: str) -> None:
        self.job.phase = (i, n, name)
        self.job.progress = (0, 0, "")
        self.job.log("phase", "[%d/%d] %s" % (i, n, name))

    def info(self, msg: str) -> None:
        self.job.log("info", msg)

    def ok(self, msg: str) -> None:
        self.job.log("ok", msg)

    def warn(self, msg: str) -> None:
        self.job.log("warn", msg)

    def err(self, msg: str) -> None:
        self.job.log("error", msg)

    def progress(self, done: int, total: int, label: str = "") -> None:
        self.job.progress = (done, total, label)

    def progress_end(self) -> None:
        pass


def _run_job(job: Job, cfg: ScanConfig, result: ScanResult, outdir: str, fmts) -> None:
    ui = LiveUI(job)
    t0 = time.time()
    loop = asyncio.SelectorEventLoop() if os.name == "nt" else asyncio.new_event_loop()
    job.loop = loop
    try:
        asyncio.set_event_loop(loop)
        task = loop.create_task(run_scan(cfg, result, ui))
        job.task = task
        try:
            loop.run_until_complete(task)
        except asyncio.CancelledError:
            result.meta["interrupted"] = True
            job.log("warn", "Scan cancelled - saving partial results.")
        except Exception as e:
            result.meta["error"] = "%s: %s" % (type(e).__name__, e)
            job.log("error", "Scan error: %s" % result.meta["error"])
            log.error("job error\n%s", traceback.format_exc())
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()
    result.duration_s = round(time.time() - t0, 2)
    result.finished = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        finalize(result)
        job.phase = (job.phase[1], job.phase[1], "Writing reports")
        written, notes = write_reports(result, outdir, fmts)
        job.files = written
        for n in notes:
            job.log("warn", n)
    except Exception as e:
        job.error = "%s: %s" % (type(e).__name__, e)
        job.log("error", "Report error: " + job.error)
    job.result = result
    job.status = "cancelled" if job.cancelled else ("error" if result.meta.get("error") else "done")
    job.log("ok" if job.status == "done" else "warn", "Finished (%s) in %.1fs" % (job.status, result.duration_s))


# ------------------------------------------------------------------ server
class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, addr, token: str, outdir: str):
        super().__init__(addr, Handler)
        self.token, self.outdir = token, outdir
        self.jobs: Dict[str, Job] = {}
        self.jobs_lock = threading.Lock()
        self._static = {}
        for path, (fname, _) in STATIC.items():
            with open(os.path.join(HERE, fname), "rb") as f:
                self._static[path] = f.read()

    def running_job(self) -> Optional[Job]:
        with self.jobs_lock:
            for j in self.jobs.values():
                if j.status == "running":
                    return j
        return None

    # ---- API actions
    def start_scan(self, body: dict) -> dict:
        target = str(body.get("target", "")).strip()
        if not target or len(target) > 2000:
            raise ApiError(400, "Enter a target (IP, range, hostname or URL).", "bad_target")
        ports_spec = str(body.get("ports") or "top").strip()[:200]
        try:
            ips, urls, names, gate, ports = plan_targets(target, ports_spec, 1024, bool(body.get("with_ports")))
        except TargetError as e:
            raise ApiError(400, str(e), "bad_target")
        if not body.get("authorized"):
            raise ApiError(400, "Tick the box confirming you are authorised to test this target.", "not_authorized")
        public = [i for i in gate if not is_private(i)]
        if public and str(body.get("phrase", "")).strip().upper() != PHRASE:
            raise ApiError(400, 'This target is on the public internet (%s). Type "%s" to confirm written permission.'
                           % (public[0], PHRASE), "phrase_required")
        fmts = [f for f in (body.get("formats") or ["json", "html", "pdf", "docx"]) if f in FORMATS] or ["json", "docx"]
        if "json" not in fmts:
            fmts.append("json")           # history needs the JSON
        with self.jobs_lock:
            if any(j.status == "running" for j in self.jobs.values()):
                raise ApiError(409, "A scan is already running. Wait for it or cancel it.", "busy")
            scan_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
            job = Job(scan_id, target)
            self.jobs[scan_id] = job
        cfg = ScanConfig(ips=ips, ports=ports, urls=urls, names=names,
                         timeout=1.5, concurrency=300, skip_discovery=bool(body.get("no_ping")),
                         use_nmap=bool(body.get("nmap")), cve=body.get("cve", True) is not False,
                         online=not body.get("offline"), web=body.get("web", True) is not False)
        result = ScanResult(scan_id=scan_id, tool_version=__version__, targets=target,
                            started=dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        job.log("info", "Scan %s started: %s" % (scan_id, target))
        log.info("UI scan %s authorised by operator; targets=%s", scan_id, target)
        threading.Thread(target=_run_job, args=(job, cfg, result, self.outdir, fmts), daemon=True).start()
        return {"id": scan_id}

    def job_status(self, scan_id: str, since: int) -> dict:
        job = self.jobs.get(scan_id)
        if not job:
            raise ApiError(404, "Unknown scan.", "not_found")
        with job.lock:
            logs = job.logs[since:]
            n = len(job.logs)
        return {"id": job.id, "status": job.status, "phase": list(job.phase), "progress": list(job.progress),
                "logs": logs, "n_logs": n, "elapsed": round(time.time() - job.started, 1),
                "files": sorted(job.files), "error": job.error}

    def result_json(self, scan_id: str) -> dict:
        if not ID_RE.match(scan_id):
            raise ApiError(404, "Unknown scan.", "not_found")
        path = os.path.join(self.outdir, "report_%s.json" % scan_id)
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        job = self.jobs.get(scan_id)
        if job and job.result:
            d = job.result.to_dict()
            d["summary"] = summarize(job.result)
            return d
        raise ApiError(404, "Result not ready.", "not_found")

    def history(self) -> list:
        out = []
        try:
            names = [n for n in os.listdir(self.outdir) if n.startswith("report_") and n.endswith(".json")]
        except OSError:
            names = []
        for name in sorted(names, reverse=True)[:40]:
            sid = name[len("report_"):-len(".json")]
            if not ID_RE.match(sid):
                continue
            try:
                with open(os.path.join(self.outdir, name), "r", encoding="utf-8") as f:
                    d = json.load(f)
                s = d.get("summary", {})
                files = [fm for fm in FORMATS if os.path.isfile(os.path.join(self.outdir, "report_%s.%s" % (sid, fm)))]
                out.append({"id": sid, "targets": d.get("targets", ""), "started": d.get("started", ""),
                            "assets": s.get("assets", 0), "cves": s.get("cves", 0),
                            "levels": s.get("host_levels", {}), "files": files})
            except (OSError, ValueError):
                continue
        return out


class Handler(BaseHTTPRequestHandler):
    server_version = "VulnScanUI"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):      # silence default logging
        pass

    # ---- helpers
    def _host_ok(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host", "").lower() in ("127.0.0.1:%d" % port, "localhost:%d" % port)

    def _send(self, status: int, body: bytes, ctype: str, extra: Optional[dict] = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj) -> None:
        self._send(status, json.dumps(obj, default=str).encode("utf-8"), "application/json; charset=utf-8")

    def _auth(self, qs) -> bool:
        tok = self.headers.get("X-Token") or (qs.get("t") or [""])[0]
        return secrets.compare_digest(tok.encode(), self.server.token.encode())

    def _dispatch(self, method: str) -> None:
        try:
            if not self._host_ok():
                return self._send(403, b"Forbidden host", "text/plain")
            u = urlsplit(self.path)
            qs = parse_qs(u.query)
            path = u.path
            if method == "GET" and path in STATIC:
                return self._send(200, self.server._static[path], STATIC[path][1])
            if not path.startswith("/api/"):
                return self._send(404, b"Not found", "text/plain")
            if not self._auth(qs):
                return self._json(401, {"error": "Missing or invalid token. Open the URL printed by the launcher.", "code": "auth"})
            parts = path[5:].strip("/").split("/")
            S: Server = self.server
            if method == "GET" and parts == ["info"]:
                try:
                    import reportlab  # noqa: F401
                    pdf = True
                except ImportError:
                    pdf = False
                return self._json(200, {"version": __version__, "nmap": bool(nmap_engine.find_nmap()), "pdf": pdf,
                                        "outdir": os.path.abspath(S.outdir), "phrase": PHRASE})
            if method == "POST" and parts == ["scan"]:
                n = int(self.headers.get("Content-Length") or 0)
                if n <= 0 or n > 20000:
                    raise ApiError(400, "Bad request body.", "bad_body")
                try:
                    body = json.loads(self.rfile.read(n).decode("utf-8"))
                    if not isinstance(body, dict):
                        raise ValueError
                except ValueError:
                    raise ApiError(400, "Body must be a JSON object.", "bad_body")
                return self._json(200, S.start_scan(body))
            if method == "GET" and parts == ["scans"]:
                return self._json(200, {"scans": S.history()})
            if method == "GET" and len(parts) == 2 and parts[0] == "jobs":
                since = int((qs.get("since") or ["0"])[0] or 0)
                return self._json(200, S.job_status(parts[1], max(0, since)))
            if method == "POST" and len(parts) == 3 and parts[0] == "jobs" and parts[2] == "cancel":
                job = S.jobs.get(parts[1])
                if not job:
                    raise ApiError(404, "Unknown scan.", "not_found")
                job.cancel()
                return self._json(200, {"ok": True})
            if method == "GET" and len(parts) == 2 and parts[0] == "scans":
                return self._json(200, S.result_json(parts[1]))
            if method == "GET" and len(parts) == 4 and parts[0] == "scans" and parts[2] == "download":
                sid, fmt = parts[1], parts[3]
                if not ID_RE.match(sid) or fmt not in FORMATS:
                    raise ApiError(404, "Unknown report.", "not_found")
                fpath = os.path.join(S.outdir, "report_%s.%s" % (sid, fmt))
                if not os.path.isfile(fpath):
                    raise ApiError(404, "That report format was not generated (PDF needs: py -m pip install reportlab).", "not_found")
                with open(fpath, "rb") as f:
                    data = f.read()
                return self._send(200, data, MIME[fmt], {"Content-Disposition": 'attachment; filename="VulnScan_Report_%s.%s"' % (sid, fmt)})
            raise ApiError(404, "Unknown endpoint.", "not_found")
        except ApiError as e:
            self._json(e.status, {"error": e.message, "code": e.code})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            log.error("UI error\n%s", traceback.format_exc())
            try:
                self._json(500, {"error": "Internal error: %s" % type(e).__name__, "code": "internal"})
            except Exception:
                pass

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def make_server(port: int, outdir: str, token: str) -> Server:
    os.makedirs(outdir, exist_ok=True)
    last = None
    for p in ([port] if port == 0 else range(port, port + 20)):
        try:
            return Server(("127.0.0.1", p), token, outdir)
        except OSError as e:
            last = e
    raise last  # type: ignore[misc]


def serve(port: int = 8765, outdir: str = "reports", open_browser: bool = True) -> int:
    token = secrets.token_urlsafe(24)
    try:
        srv = make_server(port, outdir, token)
    except OSError as e:
        print("[x] Cannot start the dashboard: %s" % e)
        return 1
    url = "http://127.0.0.1:%d/#t=%s" % (srv.server_address[1], token)
    print("\n  VulnScan dashboard v%s" % __version__)
    print("  Open this link (only works on this computer):\n\n    %s\n" % url)
    print("  Reports are saved in: %s" % os.path.abspath(outdir))
    print("  Press Ctrl+C to stop.\n")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        srv.server_close()
    return 0

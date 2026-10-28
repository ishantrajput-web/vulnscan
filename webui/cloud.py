"""Stateless Vercel website scanner. No background jobs or persistent local disk."""
import datetime as dt
from collections import deque
import hashlib
import http
import json
import logging
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

from scanner import __version__
from scanner.webcheck import public_url
from webui.server import CSP, PHRASE, STATIC

ROOT = Path(__file__).resolve().parent.parent
MAX_BODY = 20000
MAX_RESPONSE = 3 * 1024 * 1024
log = logging.getLogger(__name__)


class ScanLimits:
    """Per-instance limits; platform firewall rules are needed for global limits."""
    def __init__(self):
        self.lock = threading.Lock()
        self.clients = {}
        self.active = 0

    def acquire(self, client):
        now = time.monotonic()
        key = hashlib.sha256(client.encode()).hexdigest()
        with self.lock:
            self.clients = {k: deque(t for t in v if now - t < 600) for k, v in self.clients.items() if v and now - v[-1] < 600}
            visits = self.clients.get(key, deque())
            if len(visits) >= 5:
                return "You've reached the scan limit. Please try again in 10 minutes.", 600
            if self.active >= 2:
                return "The scanner is busy. Please try again in a moment.", 15
            if key not in self.clients and len(self.clients) >= 4096:
                return "The scanner is busy. Please try again later.", 60
            visits.append(now)
            self.clients[key] = visits
            self.active += 1
        return None, 0

    def release(self):
        with self.lock:
            self.active = max(0, self.active - 1)


LIMITS = ScanLimits()


def execute_scan(body):
    target = str(body.get("target", "")).strip()
    public_url(target)
    if body.get("authorized") is not True:
        return 400, {"error": "Confirm that you own the website or have written permission.", "code": "not_authorized"}
    if str(body.get("phrase", "")).strip().upper() != PHRASE:
        return 400, {"error": 'Type "%s" to confirm permission.' % PHRASE, "code": "phrase_required"}
    if body.get("with_ports") or body.get("nmap"):
        return 400, {"error": "Network scanning and Nmap are available in local mode only.", "code": "local_only"}
    scan_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
    with tempfile.TemporaryDirectory(prefix="vulnscan-") as outdir:
        try:
            subprocess.run([sys.executable, "-m", "webui.cloud_worker", target, outdir, scan_id],
                           cwd=str(ROOT), check=True, timeout=90,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired:
            return 504, {"error": "Website scan exceeded 90 seconds. Try again or use local mode.", "code": "timeout"}
        except subprocess.CalledProcessError:
            log.exception("Hosted scan worker failed")
            return 500, {"error": "Scan could not complete. Check deployment runtime logs.", "code": "scan_failed"}
        response = Path(outdir, "response.json")
        if response.stat().st_size > MAX_RESPONSE:
            return 413, {"error": "Report exceeds the hosted response limit. Use local mode.", "code": "too_large"}
        return 200, json.loads(response.read_text(encoding="utf-8"))


def app(environ, start_response):
    """Standard WSGI callable recognised by Vercel's Python runtime."""
    def send(status, payload, ctype="application/json; charset=utf-8"):
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
        headers = [
            ("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
            ("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"), ("Cross-Origin-Resource-Policy", "same-origin")]
        if status == 429:
            headers.append(("Retry-After", str(payload.get("retry_after", 60))))
        start_response("%d %s" % (status, http.HTTPStatus(status).phrase), headers)
        return [data]

    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    try:
        if method == "GET" and path in STATIC:
            filename, ctype = STATIC[path]
            return send(200, Path(ROOT, "webui", filename).read_bytes(), ctype)
        if method == "GET" and path == "/healthz":
            return send(200, {"ok": True, "mode": "serverless"})
        if method == "GET" and path == "/api/info":
            return send(200, {"version": __version__, "mode": "serverless", "phrase": PHRASE,
                              "public": True, "nmap": False, "pdf": True,
                              "outdir": "Reports and history are saved in this browser only."})
        if not path.startswith("/api/"):
            return send(404, {"error": "Not found"})
        # Public access was requested by the owner. execute_scan still requires
        # authorized=True AND the exact typed PHRASE; neither gate is bypassed.
        if method == "POST" and path == "/api/scan":
            origin = environ.get("HTTP_ORIGIN")
            if origin and urlsplit(origin).netloc != environ.get("HTTP_HOST"):
                return send(403, {"error": "Cross-origin requests are not allowed.", "code": "origin"})
            if environ.get("HTTP_SEC_FETCH_SITE") == "cross-site":
                return send(403, {"error": "Open the scanner directly to start a scan.", "code": "origin"})
            if environ.get("CONTENT_TYPE", "").split(";")[0].strip().lower() != "application/json":
                return send(415, {"error": "Send a JSON request.", "code": "bad_body"})
            size = int(environ.get("CONTENT_LENGTH") or 0)
            if not 0 < size <= MAX_BODY:
                return send(400, {"error": "Invalid request size.", "code": "bad_body"})
            body = json.loads(environ["wsgi.input"].read(size))
            if not isinstance(body, dict):
                raise ValueError("Request body must be a JSON object.")
            client = environ.get("REMOTE_ADDR", "unknown")
            if os.environ.get("VERCEL") == "1":
                client = environ.get("HTTP_X_FORWARDED_FOR", client).split(",")[0].strip()
            error, retry = LIMITS.acquire(client)
            if error:
                return send(429, {"error": error, "code": "rate_limit", "retry_after": retry})
            try:
                status, payload = execute_scan(body)
                return send(status, payload)
            finally:
                LIMITS.release()
        return send(404, {"error": "Unknown endpoint.", "code": "not_found"})
    except (ValueError, UnicodeError) as exc:
        return send(400, {"error": str(exc)[:240], "code": "bad_request"})
    except Exception:
        log.exception("Hosted request failed")
        return send(500, {"error": "Internal error. Check deployment runtime logs.", "code": "internal"})

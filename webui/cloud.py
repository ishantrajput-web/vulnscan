"""Stateless Vercel website scanner. No background jobs or persistent local disk."""
import datetime as dt
import http
import json
import logging
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from scanner import __version__
from scanner.webcheck import public_url
from webui.server import CSP, PHRASE, STATIC

ROOT = Path(__file__).resolve().parent.parent
MAX_BODY = 20000
MAX_RESPONSE = 3 * 1024 * 1024
log = logging.getLogger(__name__)


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
        start_response("%d %s" % (status, http.HTTPStatus(status).phrase), [
            ("Content-Type", ctype), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
            ("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"), ("Cross-Origin-Resource-Policy", "same-origin")])
        return [data]

    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    try:
        if method == "GET" and path in STATIC:
            filename, ctype = STATIC[path]
            return send(200, Path(ROOT, "webui", filename).read_bytes(), ctype)
        if method == "GET" and path == "/healthz":
            return send(200, {"ok": True, "mode": "serverless"})
        key = os.environ.get("SCANNER_ACCESS_TOKEN", "")
        if method == "GET" and path == "/api/info":
            return send(200, {"version": __version__, "mode": "serverless", "phrase": PHRASE,
                              "configured": len(key) >= 32, "nmap": False, "pdf": True,
                              "outdir": "Reports and history are saved in this browser only."})
        if not path.startswith("/api/"):
            return send(404, {"error": "Not found"})
        if len(key) < 32:
            return send(503, {"error": "Set SCANNER_ACCESS_TOKEN (at least 32 characters) in Vercel Environment Variables, then redeploy.",
                              "code": "setup_required"})
        supplied = environ.get("HTTP_X_TOKEN", "")
        if not secrets.compare_digest(supplied.encode(), key.encode()):
            return send(401, {"error": "Enter the operator access key for this deployment.", "code": "auth"})
        if method == "GET" and path == "/api/session":
            return send(200, {"ok": True})
        if method == "POST" and path == "/api/scan":
            origin = environ.get("HTTP_ORIGIN")
            if origin and urlsplit(origin).netloc != environ.get("HTTP_HOST"):
                return send(403, {"error": "Cross-origin requests are not allowed.", "code": "origin"})
            size = int(environ.get("CONTENT_LENGTH") or 0)
            if not 0 < size <= MAX_BODY:
                return send(400, {"error": "Invalid request size.", "code": "bad_body"})
            body = json.loads(environ["wsgi.input"].read(size))
            if not isinstance(body, dict):
                raise ValueError("Request body must be a JSON object.")
            status, payload = execute_scan(body)
            return send(status, payload)
        return send(404, {"error": "Unknown endpoint.", "code": "not_found"})
    except (ValueError, UnicodeError) as exc:
        return send(400, {"error": str(exc)[:240], "code": "bad_request"})
    except Exception:
        log.exception("Hosted request failed")
        return send(500, {"error": "Internal error. Check deployment runtime logs.", "code": "internal"})

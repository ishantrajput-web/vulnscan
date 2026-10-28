"""Hosted-mode contracts, SSRF protection and real report generation; no public targets."""
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

from models import WebResult
from scanner import webcheck
from webui import cloud, cloud_worker

KEY = "test-only-operator-key-" + "x" * 32


def request(path, method="GET", body=None, token=KEY, **extra):
    raw = json.dumps(body).encode() if body is not None else b""
    env = {"PATH_INFO": path, "REQUEST_METHOD": method, "HTTP_X_TOKEN": token,
           "HTTP_HOST": "scanner.example", "CONTENT_TYPE": "application/json", "REMOTE_ADDR": "127.0.0.1", "CONTENT_LENGTH": str(len(raw)), "wsgi.input": io.BytesIO(raw)}
    env.update(extra)
    response = {}
    def start(status, headers):
        response.update(status=int(status.split()[0]), headers=dict(headers))
    response["body"] = b"".join(cloud.app(env, start))
    if "application/json" in response["headers"]["Content-Type"]:
        response["json"] = json.loads(response["body"])
    return response


class CloudTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"SCANNER_ACCESS_TOKEN": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.limits = mock.patch.object(cloud, "LIMITS", cloud.ScanLimits())
        self.limits.start()
        self.addCleanup(self.limits.stop)

    def test_static_routes_and_no_source_exposure(self):
        for path in ("/", "/app.js", "/app.css"):
            response = request(path)
            self.assertEqual(response["status"], 200)
            self.assertIn("Content-Security-Policy", response["headers"])
        for path in ("/main.py", "/.env", "/../README.md", "/api/index.py"):
            self.assertEqual(request(path)["status"], 404)

    def test_public_mode_needs_no_secret(self):
        self.assertEqual(request("/api/info", token="")["json"]["mode"], "serverless")
        self.assertTrue(request("/api/info")["json"]["public"])
        with mock.patch.object(cloud, "execute_scan", return_value=(200, {"id":"test"})):
            response = request("/api/scan", "POST", {}, token="")
        self.assertEqual(response["status"], 200)
        self.assertEqual(cloud.LIMITS.active, 0)

    def test_authorization_and_request_validation(self):
        base = {"target": "https://example.com", "authorized": True, "phrase": "I HAVE PERMISSION"}
        with mock.patch.object(cloud.subprocess, "run") as run:
            for change in ({"authorized": False}, {"phrase": ""}, {"nmap": True}, {"with_ports": True},
                           {"target": "file:///etc/passwd"}, {"target": "https://a:b@example.com"},
                           {"target": "https://example.com:22"}, {"target": "https://example.com https://other.com"}):
                with mock.patch.object(cloud, "LIMITS", cloud.ScanLimits()):
                    self.assertEqual(request("/api/scan", "POST", dict(base, **change))["status"], 400)
            self.assertEqual(request("/api/scan", "POST", base, HTTP_ORIGIN="https://evil.example")["status"], 403)
            self.assertEqual(request("/api/scan", "POST", ["not-an-object"])["status"], 400)
            run.assert_not_called()

    def test_rate_limits_and_concurrency(self):
        with mock.patch.object(cloud, "execute_scan", return_value=(200, {"ok":True})):
            for _ in range(5):
                self.assertEqual(request("/api/scan", "POST", {})["status"], 200)
            blocked = request("/api/scan", "POST", {})
            self.assertEqual(blocked["status"], 429)
            self.assertEqual(blocked["headers"]["Retry-After"], "600")
        limits = cloud.ScanLimits()
        self.assertEqual(limits.acquire('a'), (None,0))
        self.assertEqual(limits.acquire('b'), (None,0))
        self.assertIsNotNone(limits.acquire('c')[0])
        limits.release()
        self.assertEqual(limits.acquire('c'), (None,0))

    def test_cross_site_and_form_requests_blocked(self):
        self.assertEqual(request('/api/scan', 'POST', {}, HTTP_SEC_FETCH_SITE='cross-site')['status'], 403)
        self.assertEqual(request('/api/scan', 'POST', {}, CONTENT_TYPE='text/plain')['status'], 415)

    def test_limits_release_after_failure_and_expire(self):
        with mock.patch.object(cloud, "execute_scan", side_effect=ValueError('invalid')):
            self.assertEqual(request('/api/scan', 'POST', {})['status'], 400)
        self.assertEqual(cloud.LIMITS.active, 0)
        limits = cloud.ScanLimits()
        with mock.patch.object(cloud.time, 'monotonic', return_value=0):
            for _ in range(5): limits.acquire('client'); limits.release()
        with mock.patch.object(cloud.time, 'monotonic', return_value=601):
            self.assertEqual(limits.acquire('client'), (None,0))

    def test_worker_timeout_is_reported(self):
        with mock.patch.object(cloud.subprocess, "run", side_effect=subprocess.TimeoutExpired("worker", 90)):
            status, payload = cloud.execute_scan({"target":"https://example.com", "authorized":True, "phrase":"I HAVE PERMISSION"})
        self.assertEqual(status, 504)
        self.assertEqual(payload["code"], "timeout")

    def test_worker_generates_real_downloads(self):
        web = WebResult(url="https://example.com", status=200, title="Test website", host_ip="93.184.216.34")
        with tempfile.TemporaryDirectory() as out, mock.patch.object(webcheck, "analyze", return_value=web) as analyze:
            payload = cloud_worker.scan(web.url, out, "20261028-123000-abcd")
            analyze.assert_called_once_with(web.url, timeout=3.0, do_dns=False, public_only=True)
            self.assertEqual(payload["result"]["summary"]["assets"], 1)
            self.assertTrue({"json", "html", "docx"}.issubset(payload["reports"]))
            import base64
            self.assertTrue(base64.b64decode(payload["reports"]["docx"]).startswith(b"PK"))
            self.assertEqual(json.loads(base64.b64decode(payload["reports"]["json"]))["scan_id"], payload["id"])
            if "pdf" in payload["reports"]:
                self.assertTrue(base64.b64decode(payload["reports"]["pdf"]).startswith(b"%PDF"))

    def test_private_and_rebinding_answers_never_connect(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "100.64.0.1", "::1", "::ffff:127.0.0.1"):
            answer = (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
            with mock.patch.object(socket, "getaddrinfo", return_value=[public, answer]), mock.patch.object(socket, "socket") as sock:
                with self.assertRaises(OSError):
                    webcheck._public_connection(("public-looking.example", 443))
                sock.assert_not_called()

    def test_connection_uses_validated_numeric_address(self):
        answer = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
        with mock.patch.object(socket, "getaddrinfo", return_value=[answer]) as dns, mock.patch.object(socket, "socket") as factory:
            self.assertIs(webcheck._public_connection(("example.com", 443)), factory.return_value)
            factory.return_value.connect.assert_called_once_with(answer[4])
            self.assertEqual(dns.call_count, 1)

    def test_redirect_cannot_change_to_non_web_port(self):
        webcheck.public_url("https://example.com")
        for url in ("http://example.com:6379", "http://example.com/\r\nX-Test:x", "ftp://example.com"):
            with self.assertRaises(ValueError):
                webcheck.fetch(url, public_only=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

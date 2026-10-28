"""Self-contained tests: spins up fake services on localhost and scans them end-to-end."""
import asyncio
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from report.compare import compare_scans                          # noqa: E402
from scanner.cve import CVEResolver, vtuple, _kb_lookup          # noqa: E402
from scanner.services import identify, clean_version              # noqa: E402
from utils.net import TargetError, parse_ports, parse_targets     # noqa: E402
import main as vmain                                              # noqa: E402


class FakeServers:
    """Runs fake banner services in a background asyncio loop."""

    def __init__(self, spec):
        self.spec = spec          # {name: (bytes_greeting_or_None, http_response_or_None)}
        self.ports = {}
        self.loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._servers = []

    def _handler(self, greeting, http_resp):
        async def h(reader, writer):
            try:
                if greeting:
                    writer.write(greeting)
                    await writer.drain()
                    await asyncio.sleep(0.3)
                else:
                    await asyncio.wait_for(reader.read(1024), 2)
                    if http_resp:
                        writer.write(http_resp)
                        await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()
        return h

    async def _start(self):
        for name, (greet, http) in self.spec.items():
            s = await asyncio.start_server(self._handler(greet, http), "127.0.0.1", 0)
            self.ports[name] = s.sockets[0].getsockname()[1]
            self._servers.append(s)
        self._ready.set()

    def __enter__(self):
        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self._start())
            self.loop.run_forever()
            self.loop.close()
        self.t = threading.Thread(target=run, daemon=True)
        self.t.start()
        self._ready.wait(5)
        return self

    def __exit__(self, *a):
        async def shutdown():
            for s in self._servers:
                s.close()
                await s.wait_closed()
        try:
            asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(5)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.t.join(5)


class UnitTests(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(len(parse_targets("10.0.0.0/24")), 254)
        self.assertEqual(parse_targets("192.168.1.5-7"), ["192.168.1.5", "192.168.1.6", "192.168.1.7"])
        self.assertEqual(parse_targets("1.1.1.1,1.1.1.1"), ["1.1.1.1"])
        with self.assertRaises(TargetError):
            parse_targets("10.0.0.0/8")
        with self.assertRaises(TargetError):
            parse_targets("")
        with self.assertRaises(TargetError):
            parse_targets("this-host-does-not-exist.invalid")

    def test_ports(self):
        self.assertEqual(parse_ports("22,80-82"), [22, 80, 81, 82])
        self.assertEqual(len(parse_ports("all")), 65535)
        for bad in ("0", "70000", "abc", "1-"):
            with self.assertRaises(TargetError):
                parse_ports(bad)

    def test_identify(self):
        self.assertEqual(identify(22, "SSH-2.0-OpenSSH_8.2p1 Ubuntu"), ("ssh", "OpenSSH", "8.2p1"))
        self.assertEqual(identify(21, "220 (vsFTPd 2.3.4)")[1:], ("vsftpd", "2.3.4"))
        self.assertEqual(identify(80, "HTTP/1.1 200 OK\nServer: nginx/1.18.0")[1:], ("nginx", "1.18.0"))
        self.assertEqual(identify(443, "HTTP/1.1 200 OK", tls=True)[0], "https")
        self.assertEqual(identify(443, "HTTP/1.1 400 Bad Request")[0], "https")   # TLS handshake failed but 443 is HTTPS
        self.assertEqual(identify(8080, "HTTP/1.1 200 OK")[0], "http")
        self.assertEqual(identify(9999, "")[0], "unknown")
        self.assertEqual(clean_version("2.4.41 ((Ubuntu))"), "2.4.41")

    def test_version_logic(self):
        self.assertEqual(vtuple("8.2p1"), (8, 2, 1))
        ids = [v.cve_id for v in _kb_lookup("Apache httpd", "2.4.49")]
        self.assertIn("CVE-2021-41773", ids)
        self.assertEqual(_kb_lookup("OpenSSH", ""), [])

    def test_cve_offline_never_raises(self):
        with tempfile.TemporaryDirectory() as d:
            r = CVEResolver(cache_dir=d, online=False)
            self.assertTrue(r.lookup("vsftpd", "2.3.4"))
            self.assertEqual(r.lookup(None, None), [])
            self.assertEqual(r.lookup("unknownthing", "1.0"), [])


class TLSTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "openssl CLI not available")
    def test_tls_server_detected(self):
        import ssl
        from scanner.banner import grab
        with tempfile.TemporaryDirectory() as d:
            key, crt = os.path.join(d, "k.pem"), os.path.join(d, "c.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                            "-days", "1", "-subj", "/CN=test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(crt, key)

            async def handler(r, w):
                await r.read(1024)
                w.write(b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<title>Secure Router</title>")
                await w.drain()
                w.close()

            async def go():
                srv = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ctx)
                port = srv.sockets[0].getsockname()[1]
                info = await grab("127.0.0.1", port, 3)
                srv.close()
                await srv.wait_closed()
                return port, info
            port, info = asyncio.run(go())
            self.assertTrue(info.tls)
            self.assertIn("Title: Secure Router", info.banner)
            self.assertEqual(identify(port, info.banner, info.tls)[0:3], ("https", "nginx", "1.18.0"))


class WeakSite:
    """A deliberately insecure local website for testing web analysis."""

    def __enter__(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/.env":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"DB_PASSWORD=supersecret\nAPI_KEY=abc\n")
                elif self.path == "/.git/HEAD":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ref: refs/heads/main\n")
                elif self.path == "/old":
                    self.send_response(301)
                    self.send_header("Location", "/")
                    self.end_headers()
                elif self.path == "/":
                    self.send_response(200)
                    self.send_header("X-Powered-By", "PHP/7.4.3")
                    self.send_header("Set-Cookie", "PHPSESSID=abc123; Path=/")
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self.wfile.write(b'<html><head><title>Demo Shop</title><meta name="generator" content="WordPress 6.4.2"></head>'
                                     b'<body><input type="password"></body></html>')
                else:
                    self.send_response(404)
                    self.end_headers()

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()


class WebTests(unittest.TestCase):
    def test_analyze_weak_site(self):
        from scanner.webcheck import analyze, parse_txt_records, _same_site
        with WeakSite() as site:
            w = analyze("http://127.0.0.1:%d/old" % site.port, timeout=3, do_dns=False)
        titles = [f.title for f in w.findings]
        self.assertEqual(w.status, 200)
        self.assertEqual(w.title, "Demo Shop")
        self.assertEqual(len(w.redirects), 1)
        self.assertTrue(any(".env" in t for t in titles))
        self.assertTrue(any(".git" in t for t in titles))
        self.assertTrue(any("Login form served over HTTP" in t for t in titles))
        self.assertTrue(any("PHPSESSID" in t for t in titles))
        self.assertIn(("WordPress", "6.4.2"), [(t["product"], t["version"]) for t in w.techs])
        self.assertNotIn("supersecret", json.dumps([w.exposed, [f.__dict__ for f in w.findings]]))   # never store secrets
        self.assertEqual(parse_txt_records('x text = "v=spf1 -all"'), ["v=spf1 -all"])
        self.assertTrue(_same_site("www.example.com", "example.com"))
        self.assertFalse(_same_site("a.com", "b.com"))

    def test_unresolvable_host_is_handled(self):
        from scanner.webcheck import analyze
        w = analyze("http://no-such-host-xyz.invalid/", timeout=2, do_dns=False)
        self.assertIn("resolve", w.error)

    def test_cli_website_scan_and_docx(self):
        import zipfile
        import xml.etree.ElementTree as ET
        with WeakSite() as site, tempfile.TemporaryDirectory() as out:
            rc = vmain.main(["http://127.0.0.1:%d/" % site.port, "-y", "-q", "--offline", "-o", out, "--format", "json,docx,html"])
            self.assertEqual(rc, 0)
            docx = [f for f in os.listdir(out) if f.endswith(".docx")][0]
            with zipfile.ZipFile(os.path.join(out, docx)) as z:
                for name in z.namelist():                      # every part must be well-formed XML
                    ET.fromstring(z.read(name))
                body = z.read("word/document.xml").decode("utf-8")
            self.assertIn("Environment file", body)
            self.assertNotIn("supersecret", body)

    def test_docx_survives_hostile_text(self):
        import zipfile
        import xml.etree.ElementTree as ET
        from models import HostResult, PortResult, ScanResult
        from report.docx_report import write_docx
        r = ScanResult("T", "2.0.0", "x<>&\x00", "now")
        h = HostResult(ip="10.0.0.1", hostname="<b>evil</b>\x07")
        h.ports = [PortResult(port=80, service="http", banner="\x00\x01<script>alert(1)</script>&amp;\ud800".encode("utf-8", "ignore").decode("utf-8", "ignore"))]
        r.hosts = [h]
        with tempfile.TemporaryDirectory() as d:
            p = write_docx(r, os.path.join(d, "t.docx"))
            with zipfile.ZipFile(p) as z:
                ET.fromstring(z.read("word/document.xml"))


class DashboardTests(unittest.TestCase):
    TOKEN = "unit-test-token"

    def setUp(self):
        from webui.server import make_server
        self.out = tempfile.mkdtemp()
        self.srv = make_server(0, self.out, self.TOKEN)
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def call(self, path, body=None, token=TOKEN, host=None):
        import urllib.request
        import urllib.error
        headers = {"X-Token": token} if token else {}
        if host:
            headers["Host"] = host
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def test_security(self):
        self.assertEqual(self.call("/api/scans", token=None)[0], 401)
        self.assertEqual(self.call("/api/scans", token="wrong")[0], 401)
        self.assertEqual(self.call("/api/scans", host="evil.example")[0], 403)
        self.assertEqual(self.call("/api/scans/..%2f..%2fetc%2fpasswd/download/json")[0], 404)
        self.assertEqual(self.call("/api/scans/20260101-000000-abcd/download/exe")[0], 404)
        st, body = self.call("/")
        self.assertEqual(st, 200)
        self.assertIn(b"VulnScan", body)

    def test_authorisation_gate_is_server_side(self):
        st, b = self.call("/api/scan", {"target": "127.0.0.1", "authorized": False})
        self.assertEqual((st, json.loads(b)["code"]), (400, "not_authorized"))
        st, b = self.call("/api/scan", {"target": "8.8.8.8", "authorized": True, "phrase": ""})
        self.assertEqual((st, json.loads(b)["code"]), (400, "phrase_required"))
        st, b = self.call("/api/scan", {"target": "!!bad!!", "authorized": True})
        self.assertEqual(st, 400)
        st, b = self.call("/api/scan", {"target": ""})
        self.assertEqual(st, 400)

    def test_full_scan_through_api(self):
        import time
        with WeakSite() as site:
            st, b = self.call("/api/scan", {"target": "http://127.0.0.1:%d/" % site.port, "authorized": True,
                                            "offline": True, "formats": ["json", "docx"]})
            self.assertEqual(st, 200)
            sid = json.loads(b)["id"]
            for _ in range(100):
                st, b = self.call("/api/jobs/" + sid)
                s = json.loads(b)
                if s["status"] != "running":
                    break
                time.sleep(0.2)
            self.assertEqual(s["status"], "done")
            self.assertIn("docx", s["files"])
            st, b = self.call("/api/scans/" + sid)
            self.assertEqual(st, 200)
            self.assertEqual(len(json.loads(b)["webs"]), 1)
            st, b = self.call("/api/scans/%s/download/docx?t=%s" % (sid, self.TOKEN), token=None)
            self.assertEqual((st, b[:2]), (200, b"PK"))
            self.assertEqual(len(json.loads(self.call("/api/scans")[1])["scans"]), 1)


class EndToEnd(unittest.TestCase):
    def test_full_scan(self):
        spec = {
            "ssh": (b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n", None),
            "ftp": (b"220 (vsFTPd 2.3.4)\r\n", None),
            "http": (None, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n"),
            "weird": (b"\x00\x01\xff<script>&%$ bad bytes \x80\r\n", None),
        }
        with FakeServers(spec) as fs, tempfile.TemporaryDirectory() as out:
            ports = ",".join(str(p) for p in fs.ports.values())
            rc = vmain.main(["127.0.0.1", "-p", ports + ",1", "--offline", "-y", "-q", "-o", out,
                             "--format", "json,html,pdf", "-t", "1.0"])
            self.assertEqual(rc, 0)
            files = os.listdir(out)
            self.assertTrue(any(f.endswith(".json") for f in files))
            self.assertTrue(any(f.endswith(".html") for f in files))
            self.assertTrue(any(f.endswith(".pdf") for f in files))
            jf = os.path.join(out, [f for f in files if f.endswith(".json")][0])
            with open(jf, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            host = data["hosts"][0]
            by_port = {p["port"]: p for p in host["ports"]}
            self.assertEqual(len(by_port), 4)
            self.assertEqual(by_port[fs.ports["ssh"]]["product"], "OpenSSH")
            self.assertEqual(by_port[fs.ports["ftp"]]["version"], "2.3.4")
            self.assertEqual(by_port[fs.ports["http"]]["product"], "Apache httpd")
            cves = {v["cve_id"] for p in host["ports"] for v in p["vulns"]}
            self.assertIn("CVE-2011-2523", cves)
            self.assertIn("CVE-2021-41773", cves)
            self.assertEqual(host["risk_level"], "critical")
            pdf = [f for f in files if f.endswith(".pdf")][0]
            self.assertGreater(os.path.getsize(os.path.join(out, pdf)), 3000)

    def test_bad_inputs_exit_cleanly(self):
        self.assertEqual(vmain.main(["not a target!!", "-y", "-q"]), 2)
        self.assertEqual(vmain.main(["127.0.0.1", "-p", "99999", "-y", "-q"]), 2)
        self.assertEqual(vmain.main(["127.0.0.1", "--format", "exe", "-y", "-q"]), 2)

    def test_no_authorisation_aborts(self):
        class NoTTY(io.StringIO):
            def isatty(self):
                return False
        with mock.patch("sys.stdin", NoTTY()):            # independent of the real terminal
            self.assertEqual(vmain.main(["127.0.0.1", "-q", "-o", tempfile.mkdtemp()]), 3)

    def test_user_declines_prompt(self):
        class TTY(io.StringIO):
            def isatty(self):
                return True
        with mock.patch("sys.stdin", TTY()), mock.patch("builtins.input", return_value="n"):
            self.assertEqual(vmain.main(["127.0.0.1", "-q", "-o", tempfile.mkdtemp()]), 3)

    def test_closed_host_no_crash(self):
        with tempfile.TemporaryDirectory() as out:
            rc = vmain.main(["127.0.0.1", "-p", "1", "--offline", "-y", "-q", "-o", out, "-t", "0.5"])
            self.assertEqual(rc, 0)
            # Windows can't delete a still-open log file: the handler must be released
            self.assertEqual(logging.getLogger("vulnscan").handlers, [])

    def test_fail_on_gate_and_http_details(self):
        spec = {"ftp": (b"220 (vsFTPd 2.3.4)\r\n", None),
                "http": (None, b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n<html><title>Router Login</title></html>")}
        with FakeServers(spec) as fs, tempfile.TemporaryDirectory() as out:
            ports = ",".join(str(p) for p in fs.ports.values())
            rc = vmain.main(["127.0.0.1", "-p", ports, "--offline", "-y", "-q", "-o", out,
                             "--format", "json", "--fail-on", "high", "-t", "1.0"])
            self.assertEqual(rc, 4)
            jf = os.path.join(out, [f for f in os.listdir(out) if f.endswith(".json")][0])
            with open(jf, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            web = [p for p in data["hosts"][0]["ports"] if p["port"] == fs.ports["http"]][0]
            self.assertIn("Title: Router Login", web["banner"])
            self.assertEqual(len(data["webs"]), 1)
            self.assertFalse(data["webs"][0]["standalone"])
            self.assertTrue(any("Content-Security-Policy" in f["title"] for f in data["webs"][0]["findings"]))
            # header findings live in the web analysis only (no duplicate on the port)
            self.assertFalse(any("security headers" in f["title"] for f in web["findings"]))
            rc2 = vmain.main(["127.0.0.1", "-p", "1", "--offline", "-y", "-q", "-o", out,
                              "--format", "json", "--fail-on", "high", "-t", "0.5"])
            self.assertEqual(rc2, 0)

    def test_compare(self):
        old = {"hosts": [{"ip": "10.0.0.1", "ports": [{"port": 22, "product": "OpenSSH", "version": "7.0", "vulns": [{"cve_id": "CVE-A"}]}]}]}
        new = {"hosts": [{"ip": "10.0.0.1", "ports": [{"port": 22, "product": "OpenSSH", "version": "9.0", "vulns": []},
                                                      {"port": 3389, "vulns": [{"cve_id": "CVE-B"}]}]},
                         {"ip": "10.0.0.9", "ports": []}]}
        d = compare_scans(old, new)
        self.assertEqual(d["new_hosts"], ["10.0.0.9"])
        e = d["hosts"]["10.0.0.1"]
        self.assertEqual(e["opened"], [3389])
        self.assertEqual(e["changed"][0]["to"], "OpenSSH 9.0")
        self.assertIn((22, "CVE-A"), e["fixed_cves"])
        self.assertIn((3389, "CVE-B"), e["new_cves"])

    def test_compare_cli_bad_file(self):
        self.assertEqual(vmain.main(["--compare", "nope1.json", "nope2.json", "-q"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)

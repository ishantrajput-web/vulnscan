"""Passive web-origin analysis (no exploitation, no fuzzing, no logins).

Looks at what any browser would see: TLS certificate, redirects, security headers, cookies, a handful of
well-known exposure paths (/.env, /.git/HEAD ...), tech/version banners, and email-security DNS records.
Only same-host redirects are followed, so we never wander onto third-party infrastructure."""
from __future__ import annotations

import concurrent.futures
import http.client
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from models import Finding, WebResult
from scanner import services
from utils.net import is_private

UA = "Mozilla/5.0 (compatible; VulnScan/1.1; security-assessment)"
MAX_BODY = 131072
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(rb"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)[\"']", re.I)
_GENERATOR2 = re.compile(rb"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]*name=[\"']generator[\"']", re.I)
_PASSWORD_INPUT = re.compile(rb"<input[^>]+type=[\"']?password", re.I)
_MIXED = re.compile(rb"<(?:script|iframe)[^>]+src=[\"']http://", re.I)
_SESSIONY = re.compile(r"(sess|sid|auth|token|jwt|login|csrf|xsrf)", re.I)

# (path, regex on first bytes, severity, title, remediation)
EXPOSURE_PROBES = [
    ("/.git/HEAD", rb"^ref:\s*refs/", "high", "Git repository exposed",
     "Block access to /.git, remove it from the web root; rotate any secrets it contains."),
    ("/.env", rb"(?m)^[A-Z][A-Z0-9_]{2,}\s*=", "critical", "Environment file (.env) exposed",
     "Remove .env from the web root immediately and rotate every credential it held."),
    ("/.DS_Store", rb"^\x00\x00\x00\x01Bud1", "low", "macOS .DS_Store file exposed",
     "Delete .DS_Store files from the web root and block them in the server config."),
    ("/server-status", rb"Apache Server Status", "medium", "Apache server-status page exposed",
     "Restrict /server-status to localhost or trusted IPs."),
    ("/phpinfo.php", rb"phpinfo\(\)|PHP Version", "medium", "phpinfo() page exposed",
     "Remove phpinfo files from production."),
    ("/actuator/env", rb"propertySources", "high", "Spring Boot actuator /env exposed",
     "Disable or authenticate actuator endpoints."),
    ("/actuator/health", rb"\"status\"\s*:", "low", "Spring Boot actuator /health exposed",
     "Limit actuator endpoints to internal networks."),
    ("/wp-login.php", rb"wp-login|WordPress", "info", "WordPress login page present",
     "Protect with MFA / IP allow-list and keep WordPress core + plugins updated."),
    ("/.well-known/security.txt", rb"(?i)contact\s*:", "info", "security.txt present", ""),
    ("/robots.txt", rb"(?i)user-agent\s*:", "info", "robots.txt present", ""),
]


# --------------------------------------------------------------------------- low-level HTTP
def _ctx_unverified() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except Exception:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except Exception:
        pass
    return ctx


def fetch(url: str, timeout: float = 6.0, max_body: int = MAX_BODY) -> Dict:
    """One GET, no redirect following. Returns dict(status, headers[list of tuples], body, reason)."""
    parts = urllib.parse.urlsplit(url)
    https = parts.scheme == "https"
    host = parts.hostname or ""
    port = parts.port or (443 if https else 80)
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    if https:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_ctx_unverified())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"Host": parts.netloc, "User-Agent": UA, "Accept": "*/*",
                                           "Accept-Encoding": "identity", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(max_body)
        return {"status": resp.status, "reason": resp.reason, "headers": resp.getheaders(), "body": body}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _hmap(headers: List[Tuple[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in headers:
        out.setdefault(k.lower(), v)
    return out


def _same_site(a: str, b: str) -> bool:
    """example.com and www.example.com count as the same site."""
    norm = lambda h: (h or "").lower().rstrip(".")
    norm2 = lambda h: norm(h)[4:] if norm(h).startswith("www.") else norm(h)
    return norm2(a) == norm2(b)


# --------------------------------------------------------------------------- TLS
def tls_info(host: str, port: int = 443, timeout: float = 6.0) -> Dict:
    info: Dict = {"checked": True, "valid": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                info["valid"] = True
                info["version"] = s.version()
                ci = s.cipher()
                info["cipher"] = ci[0] if ci else None
                cert = s.getpeercert() or {}
    except ssl.SSLCertVerificationError as e:
        info["valid"] = False
        info["error"] = (getattr(e, "verify_message", None) or str(e))[:160]
        cert = {}
    except (ssl.SSLError, OSError) as e:
        info["error"] = ("%s: %s" % (type(e).__name__, e))[:160]
        return info
    if info["valid"] is False:   # still learn protocol/cipher from an unverified handshake
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with _ctx_unverified().wrap_socket(sock, server_hostname=host) as s:
                    info["version"] = s.version()
                    ci = s.cipher()
                    info["cipher"] = ci[0] if ci else None
        except Exception:
            pass
    if cert:
        def flat(rdns):
            d = {}
            for rdn in rdns or ():
                for k, v in rdn:
                    d[k] = v
            return d
        subj, iss = flat(cert.get("subject")), flat(cert.get("issuer"))
        info["subject"] = subj.get("commonName", "")
        info["issuer"] = iss.get("organizationName") or iss.get("commonName", "")
        info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:12]
        try:
            exp = ssl.cert_time_to_seconds(cert["notAfter"])
            info["not_after"] = datetime.fromtimestamp(exp, timezone.utc).strftime("%Y-%m-%d")
            info["days_left"] = int((exp - time.time()) // 86400)
        except Exception:
            pass
    # Do we still accept ancient protocol versions?
    legacy = []
    for name, ver in (("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)), ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if ver is None:
            continue
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.set_ciphers("ALL:@SECLEVEL=0")
            c.minimum_version = ver
            c.maximum_version = ver
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with c.wrap_socket(sock, server_hostname=host):
                    legacy.append(name)
        except Exception:
            continue
    info["legacy_protocols"] = legacy
    return info


# --------------------------------------------------------------------------- DNS (email security)
def _nslookup_txt(name: str, timeout: int = 8) -> Optional[List[str]]:
    exe = shutil.which("nslookup")
    if not exe:
        return None
    try:
        cp = subprocess.run([exe, "-type=TXT", name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return None
    return parse_txt_records(cp.stdout.decode("utf-8", "replace"))


def parse_txt_records(output: str) -> List[str]:
    return [m for m in re.findall(r'"([^"]*)"', output)]


def dns_security(host: str) -> Dict:
    """SPF / DMARC presence. Returns {} when it cannot be determined (no nslookup, IP target...)."""
    if not host or re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", host) or "." not in host or is_private(host):
        return {}
    labels = host.split(".")
    candidates = [host] + ([".".join(labels[1:])] if len(labels) > 2 else [])
    res: Dict = {"spf": None, "dmarc": None}
    for dom in candidates:
        txt = _nslookup_txt(dom)
        if txt is None:
            return {}
        if res["spf"] is None and any(t.lower().startswith("v=spf1") for t in txt):
            res["spf"] = dom
        dm = _nslookup_txt("_dmarc." + dom)
        if res["dmarc"] is None and dm and any(t.lower().startswith("v=dmarc1") for t in dm):
            res["dmarc"] = dom
        if res["spf"] and res["dmarc"]:
            break
    res["domain"] = candidates[-1] if res["spf"] is None and res["dmarc"] is None else (res["spf"] or res["dmarc"])
    return res


# --------------------------------------------------------------------------- analysis
def _cookies(headers: List[Tuple[str, str]], https: bool) -> List[Dict]:
    out = []
    for k, v in headers:
        if k.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in v.split(";")]
        name = parts[0].split("=", 1)[0][:60]
        attrs = [p.lower() for p in parts[1:]]
        out.append({"name": name,
                    "secure": "secure" in attrs,
                    "httponly": "httponly" in attrs,
                    "samesite": next((a.split("=", 1)[1] for a in attrs if a.startswith("samesite=")), None)})
    return out


def _extract_techs(status_line: str, hmap: Dict[str, str], body: bytes, port: int, tls: bool) -> List[Dict]:
    techs, seen = [], set()

    def add(prod, ver, src):
        if prod and (prod, ver) not in seen:
            seen.add((prod, ver))
            techs.append({"product": prod, "version": ver, "source": src})

    text = "%s\nServer: %s" % (status_line, hmap.get("server", ""))
    _, prod, ver = services.identify(port, text, tls)
    if prod and not prod.startswith("Apache Tomcat"):
        add(prod, services.clean_version(ver), "Server header")
    xp = hmap.get("x-powered-by", "")
    m = re.match(r"(PHP)/([\d.]+)", xp, re.I)
    if m:
        add("PHP", m.group(1 + 1), "X-Powered-By")
    g = _GENERATOR.search(body) or _GENERATOR2.search(body)
    if g:
        gen = g.group(1).decode("latin-1", "replace")
        m = re.match(r"(WordPress|Drupal|Joomla!?|Hugo|Jekyll|Ghost)\s*([\d.]+)?", gen, re.I)
        if m:
            add(m.group(1).capitalize() if m.group(1).lower() != "wordpress" else "WordPress",
                services.clean_version(m.group(2)), "meta generator")
    return techs


def analyze(url: str, timeout: float = 6.0, do_dns: bool = True) -> WebResult:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    w = WebResult(url=url)
    if parts.scheme not in ("http", "https") or not host:
        w.error = "Not a valid http(s) URL"
        return w
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
        w.host_ip = infos[0][4][0]
    except (socket.gaierror, OSError, UnicodeError):
        w.error = "Cannot resolve %s" % host
        w.findings.append(Finding("info", "Host does not resolve", w.error, "Check the hostname / DNS."))
        return w
    public = not is_private(w.host_ip)

    # ---- fetch (follow same-site redirects only)
    cur, resp = url, None
    try:
        for _ in range(6):
            resp = fetch(cur, timeout)
            loc = _hmap(resp["headers"]).get("location")
            if resp["status"] in (301, 302, 303, 307, 308) and loc:
                nxt = urllib.parse.urljoin(cur, loc)
                w.redirects.append("%d %s -> %s" % (resp["status"], cur, nxt))
                if _same_site(urllib.parse.urlsplit(nxt).hostname or "", host):
                    cur = nxt
                    continue
                w.redirects.append("(stopped: redirect leaves the target host)")
            break
    except (OSError, http.client.HTTPException, ssl.SSLError) as e:
        w.error = "%s: %s" % (type(e).__name__, e)
        w.findings.append(Finding("info", "Web service did not respond as HTTP(S)", w.error[:200],
                                  "Verify the URL/port and that the service speaks HTTP."))
        return w
    w.final_url = cur
    w.status = resp["status"]
    hm = _hmap(resp["headers"])
    body = resp["body"]
    fparts = urllib.parse.urlsplit(cur)
    is_https = fparts.scheme == "https"
    w.server = hm.get("server", "")
    t = _TITLE.search(body)
    if t:
        w.title = " ".join(t.group(1).decode("utf-8", "replace").split())[:160]
    port = fparts.port or (443 if is_https else 80)
    status_line = "HTTP/1.1 %d %s" % (resp["status"], resp["reason"])
    w.techs = _extract_techs(status_line, hm, body, port, is_https)
    F = w.findings

    # ---- transport security
    if is_https:
        w.tls = tls_info(host, port, timeout)
        tl = w.tls
        if tl.get("valid") is False:
            sev = "high" if public else "low"
            F.append(Finding(sev, "TLS certificate not trusted", tl.get("error") or "Certificate validation failed.",
                             "Install a certificate from a trusted CA that matches the hostname."))
        days = tl.get("days_left")
        if days is not None:
            if days < 0:
                F.append(Finding("high", "TLS certificate expired", "Expired %d day(s) ago." % -days, "Renew the certificate now."))
            elif days <= 14:
                F.append(Finding("high", "TLS certificate expires in %d day(s)" % days, "Expiry: %s" % tl.get("not_after"), "Renew the certificate."))
            elif days <= 30:
                F.append(Finding("medium", "TLS certificate expires in %d days" % days, "Expiry: %s" % tl.get("not_after"), "Schedule renewal / enable auto-renewal."))
        if tl.get("version") in ("TLSv1", "TLSv1.1", "SSLv3") or tl.get("legacy_protocols"):
            legacy = ", ".join(tl.get("legacy_protocols") or [tl.get("version")])
            F.append(Finding("medium", "Legacy TLS protocol accepted (%s)" % legacy, "TLS 1.0/1.1 are deprecated (RFC 8996).",
                             "Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only."))
        if public and "strict-transport-security" not in hm:
            F.append(Finding("medium", "HSTS header missing", "Browsers can be tricked into using plain HTTP (SSL-stripping).",
                             "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."))
    else:
        https_ok = None
        if (parts.port or 80) == 80 or parts.port is None:
            try:
                r2 = fetch("https://%s/" % host, timeout, max_body=2048)
                https_ok = r2["status"] is not None
            except Exception:
                https_ok = False
        sev = "high" if public else "low"
        if https_ok is False or https_ok is None:
            F.append(Finding(sev, "Site served over unencrypted HTTP", "No working HTTPS endpoint was found on port 443.",
                             "Enable HTTPS with a valid certificate and redirect all HTTP traffic to it."))
        else:
            F.append(Finding("medium" if public else "low", "HTTP does not redirect to HTTPS",
                             "HTTPS exists but the plain-HTTP site is served without redirecting.",
                             "Add a permanent (301) redirect from HTTP to HTTPS."))
        if _PASSWORD_INPUT.search(body):
            F.append(Finding("high", "Login form served over HTTP", "A password field is present on an unencrypted page.",
                             "Serve all pages containing credentials over HTTPS only."))

    # ---- security headers
    ok = 200 <= resp["status"] < 300
    if ok:
        if "content-security-policy" not in hm:
            F.append(Finding("low", "Content-Security-Policy missing", "No CSP reduces protection against XSS.",
                             "Define a restrictive Content-Security-Policy."))
        if "x-frame-options" not in hm and "frame-ancestors" not in hm.get("content-security-policy", ""):
            F.append(Finding("low", "Clickjacking protection missing", "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                             "Send X-Frame-Options: DENY (or CSP frame-ancestors 'none')."))
        if "x-content-type-options" not in hm:
            F.append(Finding("low", "X-Content-Type-Options missing", "Browsers may MIME-sniff responses.",
                             "Send X-Content-Type-Options: nosniff."))
        if "referrer-policy" not in hm:
            F.append(Finding("info", "Referrer-Policy missing", "Full URLs may leak via the Referer header.",
                             "Send Referrer-Policy: strict-origin-when-cross-origin."))
        if "permissions-policy" not in hm:
            F.append(Finding("info", "Permissions-Policy missing", "Browser features are not explicitly restricted.",
                             "Send a Permissions-Policy header limiting camera/mic/geolocation."))
    for hname in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        val = hm.get(hname, "")
        if val and re.search(r"\d+\.\d+", val):
            F.append(Finding("low", "Version disclosure in %s header" % hname, val[:100],
                             "Hide version details (e.g. server_tokens off / ServerTokens Prod / expose_php=Off)."))
    acao = hm.get("access-control-allow-origin", "")
    if acao == "*":
        if hm.get("access-control-allow-credentials", "").lower() == "true":
            F.append(Finding("medium", "CORS wildcard with credentials", "Access-Control-Allow-Origin: * combined with credentials.",
                             "Return explicit trusted origins, never a wildcard with credentials."))
        else:
            F.append(Finding("info", "CORS allows any origin", "Access-Control-Allow-Origin: *",
                             "Restrict to required origins if responses are not public."))
    if is_https and _MIXED.search(body):
        F.append(Finding("medium", "Mixed content (scripts/frames over HTTP)", "An HTTPS page loads active content over HTTP.",
                         "Load every script/iframe over HTTPS."))
    if b"<title>Index of /" in body[:2000] or b"Directory listing for" in body[:2000]:
        F.append(Finding("medium", "Directory listing enabled", "The server lists directory contents.",
                         "Disable autoindex / directory browsing."))

    # ---- cookies
    w.cookies = _cookies(resp["headers"], is_https)
    for ck in w.cookies:
        sessiony = bool(_SESSIONY.search(ck["name"]))
        problems = []
        if is_https and not ck["secure"]:
            problems.append("Secure")
        if not ck["httponly"]:
            problems.append("HttpOnly")
        if not ck["samesite"]:
            problems.append("SameSite")
        if problems:
            sev = "medium" if sessiony and ("Secure" in problems or "HttpOnly" in problems) else "low"
            F.append(Finding(sev, "Cookie '%s' missing %s" % (ck["name"], "/".join(problems)),
                             "Cookie flags protect against theft and CSRF.",
                             "Set Secure; HttpOnly; SameSite=Lax (or Strict) on cookies."))

    # ---- well-known exposure paths (read-only GETs, content is NOT stored)
    origin = "%s://%s" % (fparts.scheme, fparts.netloc)

    def probe(item):
        path, rx, sev, title, fix = item
        try:
            r = fetch(origin + path, timeout, max_body=4096)
        except Exception:
            return None
        if r["status"] == 200 and re.search(rx, r["body"][:4096]):
            return {"path": path, "status": 200, "title": title, "severity": sev, "fix": fix}
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        hits = [h for h in ex.map(probe, EXPOSURE_PROBES) if h]
    for h in hits:
        w.exposed.append({"path": h["path"], "status": h["status"], "title": h["title"]})
        if h["severity"] != "info" or h["path"] == "/.well-known/security.txt":
            if h["path"] == "/.well-known/security.txt":
                continue
            F.append(Finding(h["severity"], "%s (%s)" % (h["title"], h["path"]),
                             "A request to %s returned content matching a sensitive-file signature." % h["path"], h["fix"]))
    if public and not any(h["path"] == "/.well-known/security.txt" for h in hits):
        F.append(Finding("info", "No security.txt published", "Researchers have no official channel to report issues.",
                         "Publish /.well-known/security.txt (RFC 9116)."))

    # ---- email security (DNS)
    if do_dns:
        w.dns = dns_security(host)
        if w.dns:
            dom = w.dns.get("domain", host)
            if not w.dns.get("spf"):
                F.append(Finding("low", "No SPF record found for %s" % dom, "Without SPF anyone can more easily spoof email from this domain.",
                                 "Publish an SPF TXT record (v=spf1 ... -all)."))
            if not w.dns.get("dmarc"):
                F.append(Finding("low", "No DMARC record found for %s" % dom, "Spoofed email is not told how to be handled.",
                                 "Publish a DMARC TXT record at _dmarc.%s (start with p=none, then quarantine/reject)." % dom))
    return w

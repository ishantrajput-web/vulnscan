"""Non-exploitative web-origin analysis (no exploitation, no fuzzing, no logins).

Looks at what any browser would see: TLS certificate, redirects, security headers, cookies, a handful of
well-known exposure paths (/.env, /.git/HEAD ...), tech/version banners, and email-security DNS records.
Only same-host redirects are followed, so we never wander onto third-party infrastructure."""
from __future__ import annotations

import concurrent.futures
import http.client
import ipaddress
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


def public_url(url: str):
    """Validate the narrower URL surface accepted by the hosted scanner."""
    if len(url) > 2048 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("Enter one public HTTP(S) URL without spaces or control characters.")
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme not in ("http", "https") or not parts.hostname or
            parts.username is not None or parts.password is not None or
            parts.port not in (None, 80, 443)):
        raise ValueError("Hosted mode accepts one public HTTP(S) website on port 80 or 443, without credentials.")
    return parts


def _public_connection(address, timeout=3.0, source_address=None, **kwargs):
    """Validate every DNS answer and connect to that exact IP (no DNS rebind gap)."""
    host, port = address
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers:
        raise OSError("Host does not resolve")
    for answer in answers:
        ip = ipaddress.ip_address(answer[4][0])
        effective = getattr(ip, "ipv4_mapped", None) or ip
        if not effective.is_global:
            raise OSError("Hosted scans cannot connect to private, loopback, reserved or metadata addresses.")
    family, kind, proto, _, sockaddr = answers[0]
    sock = socket.socket(family, kind, proto)
    try:
        sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sock.connect(sockaddr)
        return sock
    except BaseException:
        sock.close()
        raise


def fetch(url: str, timeout: float = 6.0, max_body: int = MAX_BODY, public_only: bool = False) -> Dict:
    """One GET, no redirect following. Returns dict(status, headers[list of tuples], body, reason)."""
    parts = public_url(url) if public_only else urllib.parse.urlsplit(url)
    https = parts.scheme == "https"
    host = parts.hostname or ""
    port = parts.port or (443 if https else 80)
    path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
    if https:
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=_ctx_unverified())
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    if public_only:
        conn._create_connection = _public_connection
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
def tls_info(host: str, port: int = 443, timeout: float = 6.0, public_only: bool = False) -> Dict:
    info: Dict = {"checked": True, "valid": None, "error": None}
    connect = _public_connection if public_only else socket.create_connection
    try:
        ctx = ssl.create_default_context()
        with connect((host, port), timeout=timeout) as sock:
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
            with connect((host, port), timeout=timeout) as sock:
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
    failures = []
    for name, ver in (("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)), ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if ver is None:
            failures.append(name + ': unavailable in this Python TLS library')
            continue
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.set_ciphers("ALL:@SECLEVEL=0")
            c.minimum_version = ver
            c.maximum_version = ver
            with connect((host, port), timeout=timeout) as sock:
                with c.wrap_socket(sock, server_hostname=host):
                    legacy.append(name)
        except ssl.SSLError as exc:
            # A protocol-version alert is evidence of remote rejection. Local
            # crypto limitations, EOF and handshake failures are inconclusive.
            if 'PROTOCOL_VERSION' not in str(exc):
                failures.append(name + ': ' + str(exc)[:120])
            continue
        except Exception as exc:
            failures.append(name + ': ' + str(exc)[:120])
            continue
    info["legacy_protocols"] = legacy
    info["legacy_status"] = 'issue' if legacy else ('failed' if failures else 'no_issue')
    info["legacy_error"] = '; '.join(failures)
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
    output = cp.stdout.decode("utf-8", "replace")
    if any(x in output.lower() for x in ('nxdomain', 'non-existent domain', 'nonexistent domain')):
        return []
    if cp.returncode or any(x in output.lower() for x in ("timed out", "no servers could be reached", "servfail", "refused")):
        return None
    return parse_txt_records(cp.stdout.decode("utf-8", "replace"))


def parse_txt_records(output: str) -> List[str]:
    return [m for m in re.findall(r'"([^"]*)"', output)]


def dns_security(host: str) -> Dict:
    """SPF / DMARC presence. Returns {} when it cannot be determined (no nslookup, IP target...)."""
    if not host or re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", host) or "." not in host or is_private(host):
        return {}
    if not shutil.which('nslookup'):
        return {}
    # No public-suffix guessing: querying co.uk as a parent would be misleading.
    # Limit this presence check to the supplied host (www alias normalized).
    candidates = [host[4:] if host.lower().startswith('www.') else host]
    res: Dict = {"spf": None, "dmarc": None}
    for dom in candidates:
        txt = _nslookup_txt(dom)
        if txt is None:
            return dict(res, domain=dom, spf_error='TXT lookup failed', dmarc_error='TXT lookup failed')
        if res["spf"] is None and any(t.lower().startswith("v=spf1") for t in txt):
            res["spf"] = dom
        dm = _nslookup_txt("_dmarc." + dom)
        if dm is None:
            res['dmarc_error'] = 'TXT lookup failed; DMARC absence cannot be established'
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


def analyze(url: str, timeout: float = 6.0, do_dns: bool = True, public_only: bool = False) -> WebResult:
    """Collect bounded evidence. No-issue means only that this check observed no issue."""
    w = WebResult(url=url)

    def record(cid, label, status, evidence=None, error='', findings=()):
        stamp = datetime.now(timezone.utc).isoformat()
        proof = evidence or {}
        w.checks.append({'id': cid, 'label': label, 'status': status, 'observed_at': stamp,
                         'evidence': proof, 'error': error[:240]})
        for finding in findings:
            finding.check_id, finding.observed_at = cid, stamp
            finding.rule_id = re.sub(r'\d+', '#', finding.title).lower()
            finding.evidence = dict(proof)
            w.findings.append(finding)

    def finding(sev, title, detail, fix):
        return Finding(sev, title, detail, fix)

    try:
        parts = public_url(url) if public_only else urllib.parse.urlsplit(url)
        host = parts.hostname or ''
        port = parts.port or (443 if parts.scheme == 'https' else 80)
        if parts.scheme not in ('http', 'https') or not host:
            raise ValueError('Not a valid HTTP(S) URL')
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        w.host_ip = infos[0][4][0]
    except (OSError, ValueError, UnicodeError) as exc:
        w.error = 'Cannot resolve or validate target: %s' % exc
        record('http.response', 'HTTP response', 'failed', error=w.error)
        return w

    cur, resp, visited = url, None, set()
    try:
        for _ in range(6):
            if cur in visited:
                raise ValueError('Redirect loop detected')
            visited.add(cur)
            resp = fetch(cur, timeout, public_only=public_only)
            loc = _hmap(resp['headers']).get('location')
            if resp['status'] in (301, 302, 303, 307, 308) and loc:
                nxt = urllib.parse.urljoin(cur, loc)
                np = urllib.parse.urlsplit(nxt)
                if np.scheme not in ('http', 'https') or np.username is not None or np.password is not None:
                    raise ValueError('Redirect uses an unsupported URL or embedded credentials')
                w.redirects.append('%d %s -> %s' % (resp['status'], cur, nxt))
                if not _same_site(np.hostname or '', host):
                    raise ValueError('Redirect leaves the authorized target host; assessment stopped')
                cur = nxt
                continue
            break
        else:
            raise ValueError('Redirect limit exceeded (6 responses)')
    except (OSError, http.client.HTTPException, ValueError) as exc:
        w.error = '%s: %s' % (type(exc).__name__, exc)
        record('http.response', 'HTTP response', 'failed', {'url': cur}, w.error)
        return w

    w.final_url, w.status = cur, resp['status']
    hm, body = _hmap(resp['headers']), resp['body']
    fp = urllib.parse.urlsplit(cur)
    final_host = fp.hostname or host
    is_https = fp.scheme == 'https'
    public = public_only or not is_private(w.host_ip)
    port = fp.port or (443 if is_https else 80)
    w.server = hm.get('server', '')[:240]
    title = _TITLE.search(body)
    if title:
        w.title = ' '.join(title.group(1).decode('utf-8', 'replace').split())[:160]
    w.techs = _extract_techs('HTTP/1.1 %d %s' % (w.status, resp['reason']), hm, body, port, is_https)
    for tech in w.techs:
        tech['confidence'] = 'self-reported; not independently verified'
    usable = 200 <= w.status < 300
    record('http.response', 'HTTP response', 'no_issue' if usable else 'failed',
           {'url': cur, 'http_status': w.status}, '' if usable else 'Expected a 2xx page; browser checks are skipped')

    if is_https:
        w.tls = tls_info(final_host, port, timeout, public_only=public_only)
        tl, issues = w.tls, []
        if tl.get('valid') is False:
            issues.append(finding('high' if public else 'low', 'TLS certificate not trusted',
                                  tl.get('error') or 'Certificate validation failed.',
                                  'Install a trusted certificate matching the final hostname.'))
        days = tl.get('days_left')
        if days is not None and days <= 30:
            caption = 'TLS certificate expired' if days < 0 else 'TLS certificate expires in %d days' % days
            issues.append(finding('high' if days <= 14 else 'medium', caption,
                                  'Expiry: %s' % tl.get('not_after'), 'Renew the certificate and verify automatic renewal.'))
        record('tls.certificate', 'Certificate trust and expiry',
               'failed' if tl.get('valid') is None else ('issue' if issues else 'no_issue'),
               {'hostname': final_host, 'port': port, 'trusted': tl.get('valid'),
                'not_after': tl.get('not_after'), 'days_left': days}, tl.get('error') or '', issues)
        legacy = tl.get('legacy_protocols', [])
        issues = [finding('medium', 'Legacy TLS protocol accepted (%s)' % ', '.join(legacy),
                          'An explicit handshake negotiated an obsolete TLS version.',
                          'Disable TLS 1.0/1.1; allow TLS 1.2 and 1.3 only.')] if legacy else []
        record('tls.legacy', 'Legacy TLS negotiation', 'issue' if legacy else tl.get('legacy_status', 'failed'),
               {'accepted_protocols': legacy}, tl.get('legacy_error', ''), issues)
        record('http.transport', 'HTTPS transport', 'no_issue', {'url': cur})
    else:
        record('tls.certificate', 'Certificate trust and expiry', 'skipped', error='Final page uses HTTP')
        record('tls.legacy', 'Legacy TLS negotiation', 'skipped', error='Final page uses HTTP')
        record('http.transport', 'HTTPS transport', 'issue', {'url': cur}, findings=[finding(
            'high' if public else 'low', 'Site served over unencrypted HTTP',
            'The final response was served over HTTP; HTTPS availability is not implied.',
            'Serve the site over HTTPS with a trusted certificate and redirect HTTP to HTTPS.')])

    header_rules = [
        ('strict-transport-security', is_https, 'medium' if public else 'low', 'HSTS header missing', 'Enable HSTS after validating HTTPS coverage.'),
        ('content-security-policy', True, 'low', 'Content-Security-Policy missing', 'Define and test a restrictive Content-Security-Policy.'),
        ('x-content-type-options', True, 'low', 'X-Content-Type-Options missing', 'Send X-Content-Type-Options: nosniff.'),
        ('referrer-policy', True, 'info', 'Referrer-Policy missing', 'Send Referrer-Policy: strict-origin-when-cross-origin.'),
        ('permissions-policy', True, 'info', 'Permissions-Policy missing', 'Restrict unnecessary browser features.')]
    for name, applicable, severity, caption, fix in header_rules:
        present = name in hm
        issues = [finding(severity, caption, 'Response header %s was absent.' % name, fix)] if not present else []
        status = 'skipped' if not usable or not applicable else ('no_issue' if present else 'issue')
        record('header.' + name, caption.replace(' missing', ''), status,
               {'url': cur, 'http_status': w.status, 'header': name, 'present': present},
               'Requires a 2xx response and an applicable transport' if status == 'skipped' else '',
               issues if status == 'issue' else [])
    frame = 'x-frame-options' in hm or 'frame-ancestors' in hm.get('content-security-policy', '').lower()
    record('header.framing', 'Clickjacking protection presence', 'skipped' if not usable else ('no_issue' if frame else 'issue'),
           {'url': cur, 'x_frame_options': hm.get('x-frame-options', '')[:120],
            'csp_frame_ancestors_present': 'frame-ancestors' in hm.get('content-security-policy', '').lower()},
           findings=[finding('low', 'Clickjacking protection missing', 'No X-Frame-Options or CSP frame-ancestors was observed.',
                             "Send X-Frame-Options: DENY or an appropriate CSP frame-ancestors policy.")] if usable and not frame else [])

    for name in ('server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'):
        value = hm.get(name, '')[:240]
        disclosed = bool(re.search(r'\d+\.\d+', value))
        record('disclosure.' + name, 'Version disclosure: ' + name, 'issue' if disclosed else 'no_issue',
               {'url': cur, 'header': name, 'value': value}, findings=[finding('low', 'Version disclosure in %s header' % name,
               value, 'Remove unnecessary version details and keep the software patched.')] if disclosed else [])
    cors = hm.get('access-control-allow-origin', '') == '*'
    record('header.cors', 'CORS configuration', 'issue' if cors else 'no_issue',
           {'url': cur, 'allow_origin': hm.get('access-control-allow-origin', '')[:120],
            'allow_credentials': hm.get('access-control-allow-credentials', '')[:20]},
           findings=[finding('info', 'CORS allows any origin',
                             'Wildcard origin observed. Browsers reject wildcard origins with credentialed requests; this is not proof of data theft.',
                             'Confirm responses are intended to be public; use explicit trusted origins for private data.')] if cors else [])
    content_rules = [
        ('content.mixed', is_https, bool(_MIXED.search(body)), 'medium', 'Mixed content (scripts/frames over HTTP)', 'Load scripts and frames over HTTPS.'),
        ('content.password', not is_https, bool(_PASSWORD_INPUT.search(body)), 'high', 'Login form served over HTTP', 'Serve credential forms over HTTPS only.'),
        ('content.directory', True, b'<title>Index of /' in body[:2000] or b'Directory listing for' in body[:2000], 'medium', 'Directory listing enabled', 'Disable directory browsing.')]
    for cid, applicable, hit, severity, caption, fix in content_rules:
        status = 'skipped' if not usable or not applicable else ('issue' if hit else 'no_issue')
        record(cid, caption, status, {'url': cur, 'signature_matched': hit},
               findings=[finding(severity, caption, 'A matching signature was observed in the bounded page sample.', fix)] if status == 'issue' else [])
    w.cookies = _cookies(resp['headers'], is_https)
    cookie_ids = []
    for ck in w.cookies:
        cid = 'cookie.' + ck['name']
        cookie_ids.append(cid)
        problems = (["Secure"] if is_https and not ck['secure'] else [])
        if not ck['httponly']: problems.append('HttpOnly')
        if not ck['samesite']: problems.append('SameSite')
        severity = 'medium' if _SESSIONY.search(ck['name']) and any(p in problems for p in ('Secure', 'HttpOnly')) else 'low'
        record(cid, 'Cookie flags: ' + ck['name'], 'issue' if problems else 'no_issue',
               dict(ck, url=cur), findings=[finding(severity, "Cookie '%s' missing %s" % (ck['name'], '/'.join(problems)),
               'Cookie values are not retained. Required flags depend on the cookie purpose.',
               'Review the cookie purpose and set appropriate Secure, HttpOnly and SameSite flags.')] if problems else [])
    record('cookies.inventory', 'Response cookie inventory', 'no_issue', {'url': cur, 'cookie_check_ids': cookie_ids})

    origin = '%s://%s' % (fp.scheme, fp.netloc)
    def probe(item):
        path, rx, sev, caption, fix = item
        target = origin + path
        try:
            response = fetch(target, timeout, max_body=4096, public_only=public_only)
            status = response['status']
            hit = status == 200 and bool(re.search(rx, response['body'][:4096]))
            # Blocked, redirected and server-error responses do not verify exposure absence.
            outcome = 'issue' if hit and sev != 'info' else ('no_issue' if status in (200, 404, 410) else 'failed')
            return item, target, status, hit, outcome, '' if outcome != 'failed' else 'Response did not establish exposure status'
        except Exception as exc:
            return item, target, None, False, 'failed', '%s: %s' % (type(exc).__name__, exc)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        probes = list(ex.map(probe, EXPOSURE_PROBES))
    for item, target, status, hit, outcome, error in probes:
        path, _, sev, caption, fix = item
        if hit:
            w.exposed.append({'path': path, 'status': status, 'title': caption})
        issues = [finding(sev, '%s (%s)' % (caption, path),
                          'A bounded GET matched the sensitive-file signature. Response contents are not retained.', fix)] if outcome == 'issue' else []
        if path == '/.well-known/security.txt' and not hit and outcome != 'failed':
            issues = [finding('info', 'No security.txt published', 'No contact signature found at the standard path.',
                              'Publish a security.txt with a monitored contact.')]
            outcome = 'issue'
        record('exposure.' + path, caption, outcome,
               {'url': target, 'http_status': status, 'signature_matched': hit, 'sample_limit_bytes': 4096}, error, issues)

    if do_dns:
        w.dns = dns_security(final_host)
        for key in ('spf', 'dmarc'):
            cid = 'dns.' + key
            if not w.dns or w.dns.get(key + '_error'):
                record(cid, key.upper() + ' record presence', 'failed' if w.dns else 'skipped',
                       error=w.dns.get(key + '_error', '') or 'DNS tool unavailable or target not applicable')
                continue
            present = bool(w.dns.get(key))
            dom = w.dns.get('domain', final_host)
            record(cid, key.upper() + ' record presence', 'no_issue' if present else 'issue',
                   {'domain': dom, 'record_found_at': w.dns.get(key)}, findings=[] if present else [finding(
                       'low', 'No %s record found for %s' % (key.upper(), dom),
                       'No matching record was observed. Presence alone does not validate policy strength.',
                       'Review authoritative DNS and publish an appropriate %s policy.' % key.upper())])
    else:
        for key in ('spf', 'dmarc'):
            record('dns.' + key, key.upper() + ' record presence', 'skipped', error='DNS checks disabled in this mode')
    return w

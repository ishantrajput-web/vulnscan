"""CVE lookup: local cache -> NVD API 2.0 (CPE match, so results are version-accurate) -> built-in offline KB.
Uses only urllib (no 'requests' needed). Never raises: any failure degrades to the offline KB."""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from models import Vulnerability, cvss_to_severity

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL = 7 * 24 * 3600

# (substring in lowercase product, [(cpe vendor, cpe product), ...])  -- order matters (specific first)
CPE_MAP: List[Tuple[str, List[Tuple[str, str]]]] = [
    ("tomcat", [("apache", "tomcat")]),
    ("openssh", [("openbsd", "openssh")]),
    ("apache httpd", [("apache", "http_server")]),
    ("apache", [("apache", "http_server")]),
    ("nginx", [("f5", "nginx"), ("nginx", "nginx")]),
    ("iis", [("microsoft", "internet_information_services")]),
    ("proftpd", [("proftpd", "proftpd")]),
    ("vsftpd", [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")]),
    ("pure-ftpd", [("pureftpd", "pure-ftpd")]),
    ("filezilla", [("filezilla-project", "filezilla_server")]),
    ("postfix", [("postfix", "postfix")]),
    ("exim", [("exim", "exim")]),
    ("sendmail", [("sendmail", "sendmail")]),
    ("dovecot", [("dovecot", "dovecot")]),
    ("mariadb", [("mariadb", "mariadb")]),
    ("mysql", [("oracle", "mysql")]),
    ("postgresql", [("postgresql", "postgresql")]),
    ("lighttpd", [("lighttpd", "lighttpd")]),
    ("dropbear", [("dropbear_ssh_project", "dropbear_ssh")]),
    ("samba", [("samba", "samba")]),
    ("redis", [("redis", "redis")]),
    ("mongodb", [("mongodb", "mongodb")]),
    ("elasticsearch", [("elastic", "elasticsearch")]),
    ("memcached", [("memcached", "memcached")]),
    ("jetty", [("eclipse", "jetty")]),
    ("werkzeug", [("palletsprojects", "werkzeug")]),
]


def vtuple(v: Optional[str]) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))[:6]


def _lt(a: Tuple[int, ...], b: Tuple[int, ...]) -> bool:
    return a < b


# Built-in offline knowledge base: (product keyword, predicate on version-tuple, CVE, CVSS, description)
OFFLINE_KB = [
    ("vsftpd", lambda v: v == (2, 3, 4), "CVE-2011-2523", 9.8,
     "vsftpd 2.3.4 shipped with a backdoor that opens a root shell on port 6200."),
    ("openssh", lambda v: v < (7, 7), "CVE-2018-15473", 5.3,
     "OpenSSH before 7.7 allows remote username enumeration."),
    ("openssh", lambda v: v < (9, 3, 2), "CVE-2023-38408", 9.8,
     "OpenSSH ssh-agent PKCS#11 feature remote code execution (before 9.3p2)."),
    ("openssh", lambda v: (8, 5) <= v < (9, 8), "CVE-2024-6387", 8.1,
     "regreSSHion: unauthenticated race condition in sshd signal handling (8.5p1 to 9.7p1)."),
    ("apache httpd", lambda v: v == (2, 4, 49), "CVE-2021-41773", 7.5,
     "Apache 2.4.49 path traversal / file disclosure (RCE if CGI enabled)."),
    ("apache httpd", lambda v: v == (2, 4, 50), "CVE-2021-42013", 9.8,
     "Apache 2.4.50 incomplete fix: path traversal and remote code execution."),
    ("apache httpd", lambda v: (2, 4, 0) <= v < (2, 4, 54), "CVE-2022-31813", 9.8,
     "Apache httpd mod_proxy X-Forwarded-For hop-by-hop header handling bypass (before 2.4.54)."),
    ("nginx", lambda v: (0, 6, 18) <= v < (1, 20, 1), "CVE-2021-23017", 7.7,
     "nginx resolver off-by-one memory overwrite (before 1.20.1)."),
    ("proftpd", lambda v: v == (1, 3, 5), "CVE-2015-3306", 9.8,
     "ProFTPD 1.3.5 mod_copy allows unauthenticated remote file copy leading to code execution."),
    ("exim", lambda v: (4, 87) <= v <= (4, 91), "CVE-2019-10149", 9.8,
     "Exim 4.87-4.91 remote command execution via crafted recipient address."),
    ("samba", lambda v: (3, 5, 0) <= v < (4, 6, 4), "CVE-2017-7494", 9.8,
     "SambaCry: remote code execution via writable share (3.5.0 to 4.6.3)."),
    ("iis", lambda v: v == (6, 0), "CVE-2017-7269", 9.8,
     "IIS 6.0 WebDAV ScStoragePathFromUrl buffer overflow (remote code execution)."),
    ("dropbear", lambda v: v < (2016, 74), "CVE-2016-3116", 5.5,
     "Dropbear before 2016.74 allows bypass of shell restrictions via xauth injection."),
]


def _kb_lookup(product: str, version: str) -> List[Vulnerability]:
    vt = vtuple(version)
    if not vt:
        return []
    p = product.lower()
    out = []
    for kw, pred, cve, score, desc in OFFLINE_KB:
        if kw in p:
            try:
                hit = pred(vt)
            except TypeError:
                hit = False
            if hit:
                out.append(Vulnerability(cve, desc, score, cvss_to_severity(score), "built-in",
                                         "https://nvd.nist.gov/vuln/detail/" + cve))
    return out


def _cpe_candidates(product: str) -> List[Tuple[str, str]]:
    p = product.lower()
    for key, cands in CPE_MAP:
        if key in p:
            return cands
    return []


def _score_of(cve: dict) -> Optional[float]:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        lst = metrics.get(key)
        if lst:
            try:
                return float(lst[0]["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                continue
    return None


class CVEResolver:
    def __init__(self, cache_dir: Optional[str] = None, api_key: Optional[str] = None,
                 online: bool = True, max_per_service: int = 15,
                 notify: Optional[Callable[[str], None]] = None):
        base = Path(cache_dir) if cache_dir else Path.home() / ".vulnscanner"
        self.cache_path = base / "cve_cache.json"
        self.api_key = api_key or os.environ.get("NVD_API_KEY") or None
        self.online = online
        self.max = max_per_service
        self.notify = notify or (lambda m: None)
        self.stats = {"cache": 0, "nvd": 0, "offline_only": 0}
        self._last_call = 0.0
        self._interval = 0.7 if self.api_key else 6.5   # NVD public limit: 5 req / 30 s
        self._cache = self._load()

    # ---- cache ----
    def _load(self) -> Dict:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save(self) -> None:
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.cache_path.parent), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._cache, f)
            os.replace(tmp, self.cache_path)       # atomic on Windows + POSIX
        except Exception:
            pass

    # ---- NVD ----
    def _nvd_query(self, vendor: str, product: str, version: str) -> Optional[List[Vulnerability]]:
        m = re.match(r"\d+(?:\.\d+)*", version)
        ver = m.group(0) if m else version
        cpe = "cpe:2.3:a:%s:%s:%s" % (vendor, product, ver)
        url = NVD_URL + "?" + urllib.parse.urlencode(
            {"virtualMatchString": cpe, "resultsPerPage": 1000})
        headers = {"User-Agent": "VulnScan/1.0", "Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        for attempt in range(3):
            wait = self._interval - (time.time() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.time()
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=40) as resp:
                    data = json.loads(resp.read().decode("utf-8", "replace"))
                break
            except urllib.error.HTTPError as e:
                if e.code in (403, 429, 503) and attempt < 2:
                    time.sleep(10 * (attempt + 1))
                    continue
                if e.code == 404:
                    return []
                return None
            except (urllib.error.URLError, OSError, ValueError):
                return None
        else:
            return None
        out: List[Vulnerability] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score = _score_of(cve)
            out.append(Vulnerability(cid, desc[:600], score, cvss_to_severity(score), "nvd",
                                     "https://nvd.nist.gov/vuln/detail/" + cid))
        return out

    # ---- public ----
    def lookup(self, product: Optional[str], version: Optional[str]) -> List[Vulnerability]:
        if not product or not version:
            return []
        key = "%s|%s" % (product.lower(), version)
        results: Dict[str, Vulnerability] = {}
        cached = self._cache.get(key)
        if cached and time.time() - cached.get("t", 0) < CACHE_TTL:
            self.stats["cache"] += 1
            for d in cached.get("v", []):
                try:
                    results[d["cve_id"]] = Vulnerability(**d)
                except TypeError:
                    continue
        else:
            nvd_ok = False
            cands = _cpe_candidates(product)
            if self.online and cands:
                collected: List[Vulnerability] = []
                ok_any = False
                for vendor, prod in cands:
                    res = self._nvd_query(vendor, prod, version)
                    if res is None:
                        # network trouble -> stop trying NVD for this whole run
                        self.online = False
                        self.notify("NVD unreachable - falling back to built-in CVE database.")
                        break
                    ok_any = True
                    collected.extend(res)
                    if res:
                        break
                nvd_ok = ok_any
                for v in collected:
                    results[v.cve_id] = v
                if nvd_ok:
                    self.stats["nvd"] += 1
                    self._cache[key] = {"t": time.time(), "v": [v.__dict__ for v in collected]}
                    self._save()
            if not nvd_ok:
                self.stats["offline_only"] += 1
        for v in _kb_lookup(product, version):      # always merge the offline KB (cheap, authoritative)
            results.setdefault(v.cve_id, v)
        ranked = sorted(results.values(), key=lambda v: (v.cvss or 0.0), reverse=True)
        return ranked[: self.max]

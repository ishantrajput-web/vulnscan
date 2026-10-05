"""Banner grabbing: plain + TLS, passive-first (read greeting), then a harmless HTTP GET probe.
For web servers it captures the response headers and the page <title> (great for identifying routers/devices)."""
from __future__ import annotations

import asyncio
import re
import ssl
from dataclasses import dataclass
from typing import Optional

HTTP_PORTS = {80, 81, 443, 591, 2082, 2083, 3000, 3128, 4443, 5000, 5601, 7001, 8000, 8008,
              8080, 8081, 8088, 8443, 8444, 8500, 8888, 9000, 9090, 9200, 9443, 10000, 15672}
TLS_PORTS = {443, 465, 636, 990, 993, 995, 2376, 4443, 5986, 6443, 8443, 8444, 9443}
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass
class BannerInfo:
    banner: str = ""
    tls: bool = False
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    tls_error: Optional[str] = None


def clean(data: bytes, limit: int = 400) -> str:
    text = data.decode("latin-1", "replace")
    out = []
    for ch in text:
        o = ord(ch)
        if ch in "\r\n\t" or 32 <= o < 127:
            out.append(ch)
        else:
            out.append(".")
    s = "".join(out).replace("\r\n", "\n").replace("\r", "\n").strip()
    return s[:limit]


def format_response(data: bytes) -> str:
    """HTTP -> headers (+ 'Title: ...'); anything else -> cleaned raw text."""
    if data[:5] == b"HTTP/":
        head, sep, body = data.partition(b"\r\n\r\n")
        if not sep:
            head, sep, body = data.partition(b"\n\n")
        text = clean(head, 1500)
        m = _TITLE.search(body)
        if m:
            title = " ".join(clean(m.group(1), 160).split())
            if title:
                text += "\nTitle: " + title
        return text
    return clean(data)


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")       # accept weak/old devices (we are auditing, not trusting)
    except Exception:
        pass
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except Exception:
        pass
    try:
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    except Exception:
        pass
    return ctx


async def _read(reader: asyncio.StreamReader, timeout: float, n: int = 2048) -> bytes:
    try:
        return await asyncio.wait_for(reader.read(n), timeout)
    except Exception:
        return b""


async def _read_all(reader: asyncio.StreamReader, timeout: float, limit: int = 16384) -> bytes:
    buf = b""
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while len(buf) < limit:
        remaining = end - loop.time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(4096), remaining)
        except Exception:
            break
        if not chunk:
            break
        buf += chunk
    return buf


async def _close(w: asyncio.StreamWriter) -> None:
    try:
        w.close()
        await asyncio.wait_for(w.wait_closed(), 1.0)
    except Exception:
        pass


async def grab(ip: str, port: int, timeout: float = 3.0, hostname: Optional[str] = None) -> BannerInfo:
    info = BannerInfo()
    host_hdr = hostname or ip
    probe = ("GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: VulnScan/1.0\r\n"
             "Accept: */*\r\nConnection: close\r\n\r\n" % host_hdr).encode()
    order = [True, False] if port in TLS_PORTS else [False, True]
    for use_tls in order:
        try:
            if use_tls:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=_ssl_ctx()), timeout)
            else:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except Exception as e:
            if use_tls and not isinstance(e, (asyncio.TimeoutError, ConnectionError)):
                info.tls_error = ("%s: %s" % (type(e).__name__, e))[:120]
            continue
        try:
            data = await _read(r, 0.6 if use_tls else 1.2)   # SSH/FTP/SMTP speak first
            if not data:
                try:
                    w.write(probe)
                    await asyncio.wait_for(w.drain(), timeout)
                except Exception:
                    pass
                data = await _read_all(r, timeout)
            elif data[:5] == b"HTTP/" and b"\r\n\r\n" not in data:
                data += await _read_all(r, 0.5)
            if use_tls:
                info.tls = True
                info.tls_error = None
                try:
                    so = w.get_extra_info("ssl_object")
                    if so is not None:
                        info.tls_version = so.version()
                        ci = so.cipher()
                        info.cipher = ci[0] if ci else None
                except Exception:
                    pass
            if data:
                info.banner = format_response(data)
        except Exception:
            pass
        finally:
            await _close(w)
        if info.banner or info.tls:
            break
    return info

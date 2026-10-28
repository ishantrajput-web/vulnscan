"""Service + product/version identification from port number and banner text."""
from __future__ import annotations

import re
from typing import Optional, Tuple

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 500: "isakmp", 512: "rexec", 513: "rlogin",
    514: "rsh", 515: "printer", 543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql", 1434: "mssql-browser",
    1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3128: "squid-http", 3268: "ldap-gc", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4848: "glassfish-admin", 5060: "sip", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc", 5985: "winrm", 5986: "winrm-tls",
    6000: "x11", 6379: "redis", 6443: "kubernetes-api", 7001: "weblogic", 8000: "http",
    8008: "http", 8080: "http", 8081: "http", 8088: "http", 8443: "https", 8444: "https",
    8500: "consul", 8888: "http", 9000: "http", 9042: "cassandra", 9090: "http", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch-transport", 9418: "git", 9443: "https",
    10000: "http", 11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
    27018: "mongodb", 50000: "db2",
}

_F = re.I | re.S
# (regex, service, product, version-group)
_FINGERPRINTS = [
    (r"SSH-\d\.\d+-OpenSSH[_-]([\w.]+)", "ssh", "OpenSSH", 1),
    (r"SSH-\d\.\d+-dropbear[_-]?([\d.]+)", "ssh", "Dropbear", 1),
    (r"^SSH-", "ssh", None, 0),
    (r"vsFTPd ([\d.]+)", "ftp", "vsftpd", 1),
    (r"ProFTPD ([\d.]+)", "ftp", "ProFTPD", 1),
    (r"Pure-FTPd", "ftp", "Pure-FTPd", 0),
    (r"FileZilla Server(?: version)? ([\d.]+)", "ftp", "FileZilla Server", 1),
    (r"Microsoft FTP Service", "ftp", "Microsoft FTP Service", 0),
    (r"Exim ([\d.]+)", "smtp", "Exim", 1),
    (r"Sendmail ([\d.]+)", "smtp", "Sendmail", 1),
    (r"Postfix", "smtp", "Postfix", 0),
    (r"Dovecot", "imap", "Dovecot", 0),
    (r"Server:\s*Apache/([\d.]+)", "http", "Apache httpd", 1),
    (r"Server:\s*Apache", "http", "Apache httpd", 0),
    (r"Server:\s*nginx/([\d.]+)", "http", "nginx", 1),
    (r"Server:\s*nginx", "http", "nginx", 0),
    (r"Server:\s*Microsoft-IIS/([\d.]+)", "http", "Microsoft IIS", 1),
    (r"Server:\s*lighttpd/([\d.]+)", "http", "lighttpd", 1),
    (r"Server:\s*Jetty\(?([\d.]+)", "http", "Jetty", 1),
    (r"Server:\s*Werkzeug/([\d.]+)", "http", "Werkzeug", 1),
    (r"Server:\s*Apache-Coyote/([\d.]+)", "http", "Apache Tomcat (Coyote)", 0),
    (r"^HTTP/\d", "http", None, 0),
    (r"^RFB (\d+\.\d+)", "vnc", "VNC (RFB)", 1),
    (r"redis_version:([\d.]+)", "redis", "Redis", 1),
    (r"^(?:\+PONG|-NOAUTH|-DENIED|-ERR wrong number)", "redis", "Redis", 0),
    (r"^RTSP/", "rtsp", None, 0),
]
_COMPILED = [(re.compile(p, _F), s, pr, g) for p, s, pr, g in _FINGERPRINTS]
_VER_RE = re.compile(r"\d+(?:\.\d+)+")


def identify(port: int, banner: str, tls: bool = False) -> Tuple[str, Optional[str], Optional[str]]:
    service = PORT_SERVICES.get(port, "unknown")
    product: Optional[str] = None
    version: Optional[str] = None
    text = banner or ""
    matched = False
    for rx, svc, prod, grp in _COMPILED:
        m = rx.search(text)
        if m:
            service, product = svc or service, prod
            version = m.group(grp) if grp else None
            matched = True
            break
    if not matched and port == 3306 and text:
        if "mariadb" in text.lower():
            m = re.search(r"(\d+\.\d+\.\d+)-MariaDB", text, re.I) or re.search(r"5\.5\.5-(\d+\.\d+\.\d+)", text)
            service, product, version = "mysql", "MariaDB", (m.group(1) if m else None)
        else:
            m = re.search(r"(\d+\.\d+\.\d+)", text)
            if m:
                service, product, version = "mysql", "MySQL", m.group(1)
    if service == "http" and PORT_SERVICES.get(port) == "https":
        service = "https"          # e.g. router answering on 443 even if our TLS handshake failed
    if tls:
        if service == "http":
            service = "https"
        elif service == "unknown":
            service = "ssl/unknown"
    return service, product, version


def clean_version(v: Optional[str]) -> Optional[str]:
    """'2.4.41 ((Ubuntu))' -> '2.4.41';  '8.2p1' stays '8.2p1'."""
    if not v:
        return None
    m = re.match(r"\s*(\d+(?:\.\d+)*(?:p\d+)?)", v)
    if m:
        return m.group(1)
    m = _VER_RE.search(v)
    return m.group(0) if m else None

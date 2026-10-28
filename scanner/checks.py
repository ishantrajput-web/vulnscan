"""Passive misconfiguration / exposure checks. No exploitation, no login attempts."""
from __future__ import annotations

import re
from typing import List

from models import Finding, PortResult

# service -> (severity, title, detail, remediation)
_RISKY = {
    "telnet": ("high", "Telnet exposed (cleartext remote login)",
               "Credentials and sessions travel unencrypted and can be sniffed.",
               "Disable Telnet and use SSH with key-based authentication."),
    "ftp": ("medium", "FTP exposed (cleartext protocol)",
            "FTP sends credentials and data unencrypted; anonymous access is a common misconfiguration.",
            "Replace with SFTP/FTPS, disable anonymous login and restrict by firewall."),
    "smb": ("high", "SMB file sharing exposed",
            "SMB is a frequent target for worms and credential attacks (e.g. EternalBlue-class bugs).",
            "Block 445/139 at the perimeter, disable SMBv1, keep systems patched."),
    "netbios-ssn": ("medium", "NetBIOS session service exposed",
                    "Leaks host/user information and enables legacy attacks.",
                    "Disable NetBIOS over TCP/IP where not needed; firewall the port."),
    "msrpc": ("medium", "Windows RPC endpoint exposed",
              "RPC endpoint mapper exposes service information and attack surface.",
              "Restrict 135 to trusted management hosts."),
    "rdp": ("high", "Remote Desktop (RDP) exposed",
            "RDP is heavily targeted by brute-force and exploit campaigns (e.g. BlueKeep).",
            "Place RDP behind a VPN, enforce NLA and MFA, and patch regularly."),
    "vnc": ("high", "VNC remote desktop exposed",
            "VNC often uses weak or no authentication and weak encryption.",
            "Tunnel VNC through SSH/VPN, use strong passwords, restrict by firewall."),
    "rexec": ("high", "r-service (rexec) exposed", "Legacy cleartext trust-based remote execution.",
              "Disable r-services; use SSH."),
    "rlogin": ("high", "r-service (rlogin) exposed", "Legacy cleartext trust-based remote login.",
               "Disable r-services; use SSH."),
    "rsh": ("high", "r-service (rsh) exposed", "Legacy cleartext trust-based remote shell.",
            "Disable r-services; use SSH."),
    "x11": ("high", "X11 display server exposed", "Open X11 can allow keystroke capture and screen access.",
            "Disable TCP listening for X11; use SSH forwarding."),
    "docker": ("critical", "Docker remote API exposed (unencrypted)",
               "An unauthenticated Docker API gives full control of the host.",
               "Bind the API to a Unix socket or require mutual TLS; firewall the port."),
    "redis": ("high", "Redis exposed to the network",
              "Redis is frequently deployed without authentication, enabling data theft and RCE chains.",
              "Bind to localhost, enable requirepass/ACLs, firewall the port."),
    "mongodb": ("high", "MongoDB exposed to the network",
                "Databases reachable from the network are often unauthenticated.",
                "Enable authentication, bind to private interfaces, firewall the port."),
    "elasticsearch": ("high", "Elasticsearch exposed to the network",
                      "Unprotected Elasticsearch leaks data and has a history of RCE bugs.",
                      "Enable security features, restrict network access."),
    "memcached": ("high", "Memcached exposed to the network",
                  "Open memcached leaks cache data and can be abused for amplification attacks.",
                  "Bind to localhost, disable UDP, firewall the port."),
    "mysql": ("medium", "MySQL/MariaDB exposed to the network",
              "Database ports should not be reachable from untrusted networks.",
              "Bind to localhost/private interface, restrict by firewall, enforce strong auth."),
    "postgresql": ("medium", "PostgreSQL exposed to the network",
                   "Database ports should not be reachable from untrusted networks.",
                   "Restrict listen_addresses and pg_hba.conf; firewall the port."),
    "mssql": ("medium", "Microsoft SQL Server exposed", "Database ports should not face untrusted networks.",
              "Restrict by firewall/VPN; disable SA login; patch."),
    "oracle": ("medium", "Oracle DB listener exposed", "Database listeners should not face untrusted networks.",
               "Restrict by firewall; enable listener password/valid-node checking."),
    "nfs": ("medium", "NFS exposed", "Misconfigured exports can expose file systems.",
            "Restrict exports by host, use NFSv4 with Kerberos, firewall the port."),
    "rpcbind": ("medium", "rpcbind exposed", "Reveals RPC services and can be abused for amplification.",
                "Firewall port 111 from untrusted networks."),
    "snmp": ("medium", "SNMP exposed", "Default community strings leak extensive device information.",
             "Use SNMPv3, change community strings, restrict by ACL."),
    "winrm": ("medium", "WinRM exposed (HTTP)", "Remote management over unencrypted channel.",
              "Use WinRM over HTTPS and restrict access."),
    "kubernetes-api": ("medium", "Kubernetes API server exposed", "API servers should not face untrusted networks.",
                       "Restrict by firewall; enforce RBAC and authentication."),
    "rsync": ("medium", "rsync daemon exposed", "Open modules can leak or allow modification of files.",
              "Require authentication, restrict modules and hosts."),
    "mqtt": ("low", "MQTT broker exposed", "Brokers without auth leak IoT/telemetry data.",
             "Enable authentication and TLS."),
}

_OLD_TLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
_STATUS = re.compile(r"^HTTP/\d(?:\.\d)? (\d{3})")


def evaluate(p: PortResult) -> List[Finding]:
    out: List[Finding] = []
    svc = p.service
    if svc in _RISKY:
        sev, title, detail, fix = _RISKY[svc]
        out.append(Finding(sev, title + " (port %d)" % p.port, detail, fix))
    if svc == "http" and not p.tls:
        out.append(Finding("low", "Unencrypted HTTP service (port %d)" % p.port,
                           "Traffic is sent in cleartext.", "Serve over HTTPS and redirect HTTP to HTTPS."))
    if p.tls and p.tls_version in _OLD_TLS:
        out.append(Finding("medium", "Deprecated TLS protocol %s (port %d)" % (p.tls_version, p.port),
                           "Old protocol versions have known cryptographic weaknesses.",
                           "Disable SSLv3/TLS 1.0/1.1; allow TLS 1.2+ only."))
    if svc in ("http", "https") and p.banner.startswith("HTTP/"):
        m = _STATUS.match(p.banner)
        if m and m.group(1).startswith("2"):          # judge headers only on real 200-class pages
            low = p.banner.lower()
            missing = []
            if (p.tls or svc == "https") and "strict-transport-security" not in low:
                missing.append("Strict-Transport-Security")
            if "x-content-type-options" not in low:
                missing.append("X-Content-Type-Options")
            if "x-frame-options" not in low and "content-security-policy" not in low:
                missing.append("X-Frame-Options or CSP frame-ancestors")
            if missing:
                out.append(Finding("low", "Missing HTTP security headers (port %d)" % p.port,
                                   "Not set: " + ", ".join(missing) + ".",
                                   "Add the missing headers in the web server / application configuration."))
    if p.product and p.version and svc in ("ssh", "http", "https", "ftp", "smtp", "imap", "mysql"):
        out.append(Finding("info", "Version disclosure: %s %s (port %d)" % (p.product, p.version, p.port),
                           "Exact versions help attackers pick exploits.",
                           "Hide version banners where the software allows it."))
    return out

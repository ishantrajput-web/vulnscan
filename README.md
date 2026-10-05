# VulnScan - Network Vulnerability Scanner

![CI](https://github.com/YOUR_USERNAME/vulnscan/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Discovers hosts, scans ports, fingerprints services (banners, TLS, web titles), matches CVEs
(NIST NVD live + built-in offline DB), scores risk, and writes **PDF / HTML / JSON** reports.
Runs on Windows, Linux/Kali and macOS with **no required dependencies**.

> **Legal:** scan only networks you own or have written permission to test. The tool asks for confirmation before
> every scan and writes an audit log. Public IPs require typing `I HAVE PERMISSION`.

## Quick start
**Windows (PowerShell)**
```powershell
git clone https://github.com/YOUR_USERNAME/vulnscan.git
cd vulnscan
py -m pip install reportlab        # optional, enables PDF
py main.py --doctor
py main.py 192.168.1.0/24
```
**Kali / Linux / macOS**
```bash
git clone https://github.com/YOUR_USERNAME/vulnscan.git && cd vulnscan
pip install reportlab              # optional, enables PDF
python3 main.py --doctor
python3 main.py 192.168.1.0/24
```
Or run `setup.bat` (Windows) / `./setup.sh` (Linux/macOS) for a virtualenv setup.

## Features
- Async scanner with OS-aware concurrency limits (no false "closed" ports from file-descriptor exhaustion)
- Host discovery via ICMP **and** TCP probes (finds hosts that block ping)
- Banner grabbing over plain + TLS; web server headers and page title (identifies routers/devices)
- CVE correlation: NVD API 2.0 (CPE-exact) + local cache + built-in KB; works fully offline
- Passive exposure checks: Telnet/RDP/SMB/Redis/Docker API..., old TLS, missing HTTP security headers
- Risk score 0-100 per host, executive PDF report with charts, remediation tips
- `--compare old.json new.json`: see new/closed ports, version changes, new/fixed CVEs
- `--fail-on high`: CI/CD gate (exit code 4)
- Optional Nmap enrichment (`--nmap`) for deeper service/OS detection

## Usage
```
py main.py 192.168.1.10 -p 1-1024 --nmap          deeper scan with Nmap
py main.py 10.0.0.5-20 -p 22,80,443 -o out --format pdf,json
py main.py 192.168.1.10 -Pn                       target blocks ping
py main.py 192.168.1.10 --offline                 no internet (built-in CVE DB)
py main.py 192.168.1.0/24 --fail-on high          exit 4 if High/Critical found
py main.py --compare reports\old.json reports\new.json
```
Faster CVE lookups: free NVD API key -> `--nvd-key KEY` or env `NVD_API_KEY`.

Exit codes: `0` ok, `1` error during scan/report, `2` bad input, `3` authorisation refused, `4` `--fail-on` gate, `130` interrupted.

## Project layout
```
main.py            CLI, authorisation gate, report orchestration
engine.py          pipeline: discovery -> ports -> banners -> nmap -> CVE -> scoring
scanner/           discovery, portscan, banner, services, osdetect, nmap_engine, cve, checks
report/            scoring, compare, json_export, html_report, pdf_report
utils/             target/port parsing, console UI
tests/             python tests/test_scanner.py
```

## Reliability design
Standard-library only (reportlab/Nmap optional with automatic fallback) - NVD offline/rate-limited falls back to cache and
built-in DB - Ctrl+C saves partial results - hostile banners cannot break reports - Windows-safe event loop,
log handling and ping parsing - CI runs the tests on Windows, Linux and macOS.

## Limitations
CVE matching is version-based: back-ported distro patches can cause false positives, and services that hide
their version cannot be matched. The scanner is passive: it never exploits, brute-forces or logs in.

## License
MIT - see `LICENSE`. Use responsibly.

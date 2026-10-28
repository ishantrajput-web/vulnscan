# VulnScan - Network & Website Vulnerability Scanner

![CI](https://github.com/ishantrajput-web/vulnscan/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Scan **networks** (hosts, ports, services, CVEs) and **websites** (TLS, headers, cookies, exposed files, DNS) from one tool,
watch it live in a **browser dashboard**, and get **Word (.docx) / PDF / HTML / JSON** reports.
Runs on Windows, Linux/Kali and macOS with **no required dependencies**.

> **Legal:** scan only systems you own or have written permission to test. Every scan needs an explicit authorisation
> confirmation (enforced server-side in the dashboard too) and writes an audit log. Public targets require typing `I HAVE PERMISSION`.

## Quick start
**Windows:** double-click `start_ui.bat` (or run `py main.py --ui`) -> your browser opens the dashboard.
**Kali / Linux / macOS:** `./start_ui.sh`

Command line:
```
py main.py 192.168.1.0/24                  # network: discovery, ports, services, CVEs, web checks on found web ports
py main.py https://example.com             # website: TLS, headers, cookies, exposed files, SPF/DMARC, tech CVEs
py main.py 10.0.0.5,https://intranet.local # mix of both
py main.py --doctor                        # check your environment
```
Optional PDF support: `py -m pip install reportlab` (DOCX and HTML need nothing).

## What it checks
| Target | Checks |
|---|---|
| Network / IP | live hosts (ping + TCP), open ports, banners (plain + TLS), service/version, OS guess, known CVEs (NIST NVD + offline DB), risky exposure (Telnet, RDP, SMB, Redis, Docker API...) |
| Website / URL | TLS certificate (trust, expiry, legacy TLS), HTTP->HTTPS redirect, security headers (HSTS, CSP, X-Frame-Options...), cookie flags, CORS, exposed files (`/.env`, `/.git`, phpinfo...), version disclosure, technology CVEs (WordPress, PHP, nginx, Apache...), SPF/DMARC |

Everything is **passive**: no exploitation, brute force, logins or fuzzing. Secrets found in exposed files are never stored in reports.
Redirects to other hosts are not followed. For deep application testing use OWASP ZAP / Burp on systems you are authorised to test.

## Dashboard
`py main.py --ui` starts a local-only dashboard (`127.0.0.1`): live phase/progress/log, results with severity charts,
per-asset details, history of past scans, and download buttons for every report format.
Security: random per-run token, Host-header check (anti DNS-rebinding), strict CSP, no CORS, one scan at a time.

## Free Vercel hosting (website mode)

The repository includes an explicit WSGI entrypoint at `api/index.py` and `vercel.json` routing.
Keep the Vercel project's **Root Directory** at the repository root. Push to `main` to deploy.
This avoids treating the local CLI (`main.py`) as an HTTP application.

Before scanning, set **SCANNER_ACCESS_TOKEN** to a random secret of at least 32 characters in
each Vercel project's Environment Variables (Production and Preview as needed), then redeploy.
Generate one locally with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
Enter that secret in the dashboard's operator access field. Never commit it or share it publicly.
Without this environment variable the dashboard loads but scanning stays locked.

Hosted mode checks **one public HTTP(S) website on port 80 or 443** per request. The operator must
confirm ownership/written permission and type `I HAVE PERMISSION`. Each scan has a 90-second worker
timeout; there are no background jobs. Private/loopback/metadata addresses are rejected at every
outbound connection, including after DNS changes and redirects. Responses include Word, PDF
(when reportlab is available), HTML and JSON downloads. Temporary server-side files are removed
after the response is prepared.

The last 20 scans and their reports are saved in **this browser's IndexedDB**, not a cloud database.
History survives reloads on the same browser and origin until cleared or evicted by the browser.
Use **Clear browser history** to remove it; download important reports separately. If browser
storage is unavailable, reports remain available for the current page session only.

Network/port scans, Nmap, live background progress, email DNS checks and live NVD lookups remain
available in **local mode**. Hosted mode uses the built-in offline CVE database. A Vercel server
cannot scan your laptop's private LAN. Free hosting remains subject to Vercel Hobby usage limits;
this mode does not require a paid backend or persistent disk.

## Reports
`report_<id>.docx` (opens in Microsoft Word, **WPS Office**, LibreOffice, Google Docs), `.pdf`, `.html`, `.json`, plus `scan_<id>.log`
in `reports/`. Compare two scans: `py main.py --compare old.json new.json`. CI gate: `--fail-on high` (exit code 4).

## More options
```
-p 1-1024 | well-known | all | 22,80,443     ports            -Pn  skip ping           --nmap  use Nmap if installed
--offline  built-in CVE DB only               --no-web         skip web analysis       --with-ports  also port-scan a website's IP
--nvd-key KEY (or env NVD_API_KEY)            --format json,html,pdf,docx              -o folder
```
Exit codes: `0` ok, `1` error, `2` bad input, `3` authorisation refused, `4` `--fail-on` gate, `130` interrupted.

## Layout
```
main.py            CLI + authorisation gate          engine.py     scan pipeline
scanner/           discovery, portscan, banner, services, cve, checks, webcheck, nmap_engine
report/            scoring, compare, writer, docx_report, pdf_report, html_report, json_export, webview
webui/             server.py (local dashboard) + index.html / app.js / app.css
tests/             python tests/test_scanner.py
```

## Reliability design
Standard-library only (reportlab/Nmap optional with automatic fallback) - OS-aware concurrency limits - NVD offline/rate-limited
falls back to cache + built-in DB - Ctrl+C / Cancel saves partial results - hostile banners/titles cannot break reports or the UI
(everything is escaped) - Windows-safe event loop, log handling and ping parsing - CI on Windows, Linux and macOS.

## Limitations
CVE matching is version-based (back-ported distro patches can cause false positives; hidden versions can't be matched).
Web analysis is a passive baseline, not a replacement for a full web-app penetration test.

## License
MIT - see `LICENSE`. Use responsibly.

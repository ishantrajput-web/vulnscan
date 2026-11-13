# VulnScan engineering notes

## Problem and scope

VulnScan collects a bounded set of network and website security signals and gives the operator evidence to review. It does not execute exploits, authenticate to applications or establish that a CVE is exploitable. TCP connections, TLS negotiation and fixed-path HTTP GETs are active, non-exploitative probes. Calling the entire scanner passive would be inaccurate.

## Why this architecture

- **Python standard library:** sockets, asyncio, HTTP/TLS, dataclasses, ZIP/XML and JSON cover the core workflow without mandatory networking dependencies. ReportLab is optional for PDFs. A packaging install includes it to support hosted exports.
- **TCP connect scanning:** works without raw-socket privileges and observes an actual connection outcome. It does not provide SYN stealth scans or UDP coverage. Async concurrency is bounded to avoid exhausting file descriptors.
- **Separate local and hosted execution:** local mode can reach an authorized LAN and supports long-running jobs. Hosted mode accepts one public website, validates every resolved address immediately before connecting, and bounds the worker process. The public mode cannot inspect a user's private LAN.
- **Shared evidence:** result dataclasses feed scoring and the shared assessment model. Exporters use the same observations. JSON adds fields without removing the existing schema. Older records with no check ledger remain readable but cannot establish resolved website findings.
- **Browser-local hosted history:** IndexedDB avoids a persistent backend and accounts. History is device/origin specific and can be evicted. Local mode stores reports on disk.

## Check outcome contract

Each website check records a stable ID, label, UTC timestamp, status, safe evidence and any error:

| Status | Meaning |
| --- | --- |
| `issue` | An issue or informational observation was recorded. |
| `no_issue` | This particular check observed no issue in the sampled response. |
| `failed` | The outcome could not be verified. |
| `skipped` | The check was disabled or did not apply to the response/transport. |

Scan completion is separate from check coverage. A usable target produces a completed report and an observed-risk indicator even if an optional check is unavailable. Coverage counts and error reasons stay visible; this indicator describes recorded findings only, not overall safety. An unavailable/non-2xx target, interrupted scan or fatal scan error removes the aggregate score. Assessment schema v3 uses `completed` / `target_unavailable` and a separate `coverage_status`. Findings already observed are retained. A blocked exposure response, unexpected redirect or timeout is not treated as a clean check. A 404/410 or an unmatched bounded 200 response establishes only that the configured signature was not observed. HTTP error pages do not get missing-header findings for the application page.

The header checks primarily establish **presence**, not policy correctness. For example, a present CSP may still be too permissive. Fixed-path checks sample at most 4 KiB and page checks at most 128 KiB. Unsupported legacy TLS negotiation is inconclusive, rather than proof that old protocols are disabled. Email DNS checks inspect exact host record presence (normalizing a `www` alias); they do not infer organizational domains using a guessed public suffix.

## Identification and CVEs

Port numbers yield a **port-based guess**. Matched banners yield **self-reported identification**. Optional Nmap results are labelled separately. None of these proves vulnerability applicability.

Online CVE requests retain recognized OpenSSH `pN` patch suffixes in the CPE update field; unfamiliar suffixes do not get silently removed. Cache keys are versioned to avoid reusing older normalized queries. The bundled knowledge base is intentionally small; its rule count, source usage and per-service result cap are included in scan metadata. An ssh-agent-only rule was removed from server banner matching because detecting sshd does not establish agent exposure. OS/build, optional modules, back-ported fixes and prerequisites still require vendor validation.

CPE/NVD reference: https://nvd.nist.gov/developers/vulnerabilities

## Risk indicator

The 0–100 indicator is a project-specific prioritization heuristic. CVE weights (critical/high/medium/low/info) are 20/10/4/1/0; finding weights are 20/8/3/1/0. CVE contribution is capped at 60 per website/service; total score is capped at 100. High or critical observations force at least that risk level. Numeric thresholds otherwise map 70/40/15/1 to critical/high/medium/low. This is not a CVSS score for the asset or an exploit probability. Keeping the strongest individual severity visible avoids hiding a serious observation behind a low sum.

## Evidence and privacy

Findings identify the check, asset, observation time and reason. Exposure bodies and cookie values are not retained in the web result. The evidence records response status and a signature match, not the contents of a secret file. Reports and target URLs can still contain sensitive assessment metadata; share them only with authorized recipients. The network banner subsystem samples service-provided data separately.

## Comparison semantics

`python main.py --compare old.json new.json` compares network changes and website observations. The dashboard compares website results from its existing history without uploading browser-local history.

- **New:** observation appears in the follow-up snapshot.
- **Still present:** the stable observation identity appears in both snapshots.
- **Verified resolved:** the old finding disappears and its matching check completes with `no_issue` in an uninterrupted follow-up response.
- **Not verified:** the target/check is absent, skipped, failed, interrupted or has no compatible historical evidence. A CVE disappearing is also unverified; it does not prove that a patch was applied.

The CLI and browser implement the same conservative website contract and have parity tests. Neither comparison infers a historical trend from one snapshot. Comparing different scopes should be interpreted as scope change, not remediation.

## Reproducible demonstration

Run `python -m demo.lab --verify`. This starts a dummy-data server on an ephemeral loopback port, assesses the weak configuration, hardens the same server, rechecks it and asserts that the expected fixes are verified. Evidence is saved under ignored `output/demo/`.

For a live dashboard demonstration:

1. Run `python -m demo.lab --mode weak --port 8899` in one terminal.
2. Run `python main.py --ui` and assess `http://127.0.0.1:8899/` in offline mode.
3. Stop only the lab process and restart it with `--mode hardened --port 8899`.
4. Repeat the assessment and compare the two history entries.

Expected fixes: dummy `.env` and `.git/HEAD` exposure; CSP/framing/content-type controls; referrer/permissions headers; session cookie flags. HTTP remains intentionally unencrypted in this loopback lab and stays present. This is a known fixture, not a claim about an external website or complete scanner accuracy.

## Validation and remaining limits

Run `python -m unittest discover -s tests -v`. Tests cover localhost integration, authorization and SSRF boundaries, secret redaction, check uncertainty, redirected TLS identity, CVE suffix handling, export robustness and comparison resolution rules. JavaScript syntax/parity checks use Node when available. GitHub Actions runs the suite on three operating systems and three Python versions. Passing tests establish these contracts, not comprehensive detection accuracy.

Further work: maintained vulnerability-data coverage, semantic policy checks, authenticated workflows, complete network probe accounting and platform-wide hosted rate limiting. Per-instance hosted limits reset on cold starts and are not global abuse protection.

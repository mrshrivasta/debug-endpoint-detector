# Debug Endpoint Detector

A real, no-mock-data security auditing tool that makes a **bounded set of real, passive HTTP GET requests** to well-known debug/diagnostic paths on a URL you authorize — framework debug/error pages (Werkzeug, Django, Rails, ASP.NET), Spring Boot Actuator, `phpinfo()`, interactive debug consoles (Werkzeug console, Symfony profiler), Go `pprof`/`expvar`, and Apache `mod_status`/`mod_info` — and only reports an exposure when the real response **both succeeds AND contains a genuine content signature** for that specific debug tool, avoiding false positives from generic soft-200 catch-all pages.

Available as both a **command-line tool** and a **full multi-page web application**.

Developed by **Karanam Shrivasta**
GitHub: https://github.com/mrshrivasta
LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

---

## ⚠️ Disclaimer (read before use)

This tool sends **real HTTP requests** to whatever URL you provide it. It does not use sample data, fixtures, or simulated responses — every finding is derived from actual responses received from the target server at scan time.

- **Bounded, passive, read-only by design.** This tool checks a short, fixed list of well-known debug/diagnostic paths (see the Detection Rules table). Every request is a standard, non-destructive `GET` — the same technique used by well-known passive/light scanners (OWASP ZAP, Nikto) when probing for common exposed files/endpoints. No exploit payloads are ever sent, nothing is submitted, and no discovered debug console is ever interacted with beyond the initial confirming GET request.
- **Signature-confirmed to avoid false positives.** A finding is only produced when the response is BOTH a success status AND its body contains a specific, real content signature unique to that debug tool — not merely "a 200 status at this path," which many single-page apps or catch-all routers would produce regardless.
- **Authorized use only.** Only scan URLs and systems that you own, or that you have explicit, contractual, written authorization to test. Sending requests to third-party systems without authorization may violate the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), similar computer-crime laws in other jurisdictions, and the target's Terms of Service — even a set of harmless-looking GET requests for common file paths.
- **No warranty.** This software is provided **"AS IS"**, without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.
- **No liability.** The author, Karanam Shrivasta, accepts no liability for any damage, data loss, downtime, legal consequences, financial loss, or any other harm arising from the use, misuse, or inability to use this software.
- **Not a professional audit.** This tool is an educational and productivity aid. It does not replace a certified penetration test, a compliance audit, or a professional security assessment performed by a qualified practitioner.
- **You are responsible.** By using this tool you accept full responsibility for how you use it and for obtaining any necessary authorization before scanning a target.

---

## Who should use this project

- Web developers and DevOps engineers verifying their production deployment doesn't accidentally ship a framework's debug mode, an exposed Actuator endpoint, or a leftover `phpinfo.php`.
- AppSec engineers doing a fast, safe first pass for debug-endpoint exposure ahead of a deeper authorized assessment.
- SRE teams auditing infrastructure (Apache, Spring Boot, Go services) for accidentally exposed diagnostic surfaces.
- Students and educators studying real-world debug-endpoint information-disclosure risk with a genuine, working, bounded, non-destructive tool.

## Why use this project

A debug endpoint left enabled in production is one of the most consequential, and most common, deployment mistakes: framework debug pages leak source code and environment variables, `phpinfo()` discloses the full server configuration, and the Werkzeug interactive debug console allows arbitrary Python code execution from a browser if reached without its PIN. These are also some of the very first things automated attackers and scanning bots check for. This tool automates a real, bounded, signature-confirmed check for exactly this exposure, with clear severities, a full audit trail (scan logs, alerts, incidents), CSV reporting, and six chart types for trend visibility.

---

## Detection Rules

Every rule below is evaluated against the **actual results of real, passive HTTP GET requests** made to a fixed, bounded list of debug/diagnostic paths during a scan.

| Rule ID | Name | Severity | What it checks |
|---|---|---|---|
| DED-001 | Framework Debug/Error Page Exposed | **Critical** | A framework's interactive debug/error page (Werkzeug, Django, Rails "Whoops", ASP.NET YSOD, raw stack trace) is confirmed exposed. |
| DED-002 | Spring Boot Actuator Endpoint Exposed | High | A Spring Boot Actuator management endpoint (`/actuator`, `/actuator/env`) is confirmed publicly accessible. |
| DED-003 | phpinfo() Output Exposed | **Critical** | A real `phpinfo()` output page is confirmed publicly accessible. |
| DED-004 | Interactive Debug Console Exposed | **Critical** | An interactive debug console (Werkzeug console, Symfony profiler) is confirmed exposed. |
| DED-005 | Go pprof/expvar Debug Endpoint Exposed | Medium | A Go `net/http/pprof` or `expvar` debug endpoint is confirmed exposed. |
| DED-006 | Apache Server Status/Info Page Exposed | Medium | Apache's `mod_status` or `mod_info` diagnostic page is confirmed exposed. |
| DED-000 | Target Unreachable | Low (informational) | The target could not be reached (DNS failure, connection refused/timeout, TLS error, network policy block). Not a debug-endpoint finding — an operational note. |

---

## Architecture

```
debug-endpoint-detector/
├── Authentication        # app/auth — register/login/logout, Flask-Login sessions, hashed passwords
├── Dashboard              # app/dashboard — run a real scan, view live counters and recent scans
├── Security Engine        # app/security_engine — real, bounded, signature-confirmed endpoint probing
├── Detection Rules        # app/detection_rules — 6 pure functions evaluating real confirmed probes
├── Logs                   # app/logs — full scan history / audit trail, per-scan detail view
├── Alerts                 # app/alerts — generated from findings by severity threshold
├── Incident Management    # app/incident_management — track/triage/resolve alert-driven incidents
├── Analytics               # app/analytics — 6 real chart types (pie, bar, line, radar, doughnut, polar area)
├── Reports                 # app/reports — CSV export of findings
├── Settings                 # app/settings — per-user alert threshold and notification preferences
├── Database                 # app/database/models.py — SQLAlchemy models (SQLite by default)
├── CLI                       # cli/main.py — standalone command-line scanner
├── Web Application            # app/ (Flask app factory, blueprints, templates, static assets)
├── Tests                       # tests/ — rule-level unit tests + real local-server engine tests
├── Documentation                # this README
└── README.md
```

---

## Setup & Run

### Requirements
- Python 3.9+
- pip

### Install

```bash
cd debug-endpoint-detector
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Run the web application

```bash
python3 run.py
```

Then open `http://127.0.0.1:5000` in your browser, register an account, and run your first scan from the Dashboard by entering a URL you are authorized to test.

### Run the CLI

```bash
# Basic scan
python3 cli/main.py scan https://your-authorized-target.example.com

# JSON output (for piping into other tools)
python3 cli/main.py scan https://your-authorized-target.example.com --json

# Export findings to CSV
python3 cli/main.py scan https://your-authorized-target.example.com --csv findings.csv

# List all detection rules
python3 cli/main.py rules
```

The CLI exits with status code `1` if any findings were produced (CI/CD friendly) and `0` on a clean scan.

### Run the tests

```bash
PYTHONPATH=. python3 -m pytest tests/ -v
```

Tests include rule-level unit tests against synthetic-but-realistic probe-result dicts, and a genuine end-to-end test that boots a real local HTTP server on an ephemeral `127.0.0.1` port that genuinely serves realistic `phpinfo()`-style and Apache-status-style content at a couple of the probed paths, then performs real, passive HTTP requests against it via the real Security Engine — no third-party network calls are made during testing.

---

## Frequently Asked Questions

**What does the Debug Endpoint Detector check?**
It makes a bounded set of real, passive GET requests to well-known debug/diagnostic paths on a URL you authorize, and only reports an exposure when the real response is both a success status AND its body contains a genuine content signature for that specific debug tool (Werkzeug, Django, Spring Boot Actuator, phpinfo(), Symfony profiler, Go pprof/expvar, Apache mod_status/mod_info) — never sample data, and no exploit payload is ever sent.

**Who should use the Debug Endpoint Detector?**
Web developers and security engineers auditing whether framework/server debug and diagnostic endpoints are accidentally left publicly accessible in production, on sites and applications they own or are explicitly authorized to test.

**Why require a content signature match instead of just checking for a 200 status?**
Many modern applications and single-page-app routers return 200 for almost any path (serving a generic app shell). Requiring the response body to contain a genuine, specific signature for the actual debug tool avoids false-positive findings from those setups.

**Does this tool interact with any exposed debug console it finds?**
No, never. It only sends the same bounded, passive GET requests used to detect the initial exposure. It never attempts to execute code, browse further into a console, or interact with any exposed debug tool beyond confirming its presence.

---

## License & Attribution

Developed by **Karanam Shrivasta**.
GitHub: https://github.com/mrshrivasta · LinkedIn: https://www.linkedin.com/in/karanam-shrivasta

Provided for authorized security auditing and educational use only. See the Disclaimer section above. No warranty of any kind is provided.

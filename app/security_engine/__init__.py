"""
Security Engine — Debug Endpoint Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Performs a REAL, live HTTP GET request to a target URL you provide to
establish the site's base origin, then makes a bounded set of additional
real, passive GET requests to a fixed list of well-known
debug/diagnostic/framework-internal paths (Werkzeug/Django/Rails debug
pages, Spring Boot Actuator, phpinfo(), Symfony profiler, Go pprof/expvar,
Apache mod_status/mod_info). A finding is only produced when the response
is BOTH a success status code AND its body contains a specific, real
content signature for that debug tool — this avoids false positives from
generic custom-404/soft-200 catch-all pages. Nothing is simulated: every
finding is based on an actual HTTP response.

SAFETY / SCOPE: Every request is a standard, read-only, non-destructive
GET — the same technique used by well-known passive/light scanners (OWASP
ZAP, Nikto) when probing for common exposed files/endpoints. No exploit
payloads are ever sent, nothing is submitted, and the fixed probe list is
short and bounded (see DEBUG_PROBES) to keep the scan lightweight and
non-disruptive to the target.
"""
import time
from urllib.parse import urlsplit, urlunsplit

import requests

DEFAULT_TIMEOUT = 8
DEFAULT_USER_AGENT = "DebugEndpointDetector/1.0 (+https://github.com/mrshrivasta; educational security tool)"

# (path, rule_id, name, severity, [content signatures - ANY match confirms])
DEBUG_PROBES = [
    ("/", "DED-001", "Framework Debug/Error Page Exposed", "critical", [
        "Werkzeug Debugger", "Django Version", "Whoops,", "Server Error in '/' Application",
        "Traceback (most recent call last)", "at Function.Module._load",
    ]),
    ("/actuator", "DED-002", "Spring Boot Actuator Endpoint Exposed", "high", [
        "\"_links\"", "healthCheck", "\"health\"", "org.springframework.boot"
    ]),
    ("/actuator/env", "DED-002", "Spring Boot Actuator Endpoint Exposed", "high", [
        "\"activeProfiles\"", "\"propertySources\""
    ]),
    ("/phpinfo.php", "DED-003", "phpinfo() Output Exposed", "critical", ["phpinfo()", "PHP Version", "PHP Credits"]),
    ("/info.php", "DED-003", "phpinfo() Output Exposed", "critical", ["phpinfo()", "PHP Version", "PHP Credits"]),
    ("/console", "DED-004", "Interactive Debug Console Exposed", "critical", ["Werkzeug Debugger", "console.png", "__debugger__"]),
    ("/_profiler", "DED-004", "Interactive Debug Console Exposed", "critical", ["Symfony Profiler", "sf-toolbar", "symfony-profiler"]),
    ("/debug/pprof/", "DED-005", "Go pprof Debug Endpoint Exposed", "medium", ["/debug/pprof/", "profile</a>", "goroutine"]),
    ("/debug/vars", "DED-005", "Go expvar Debug Endpoint Exposed", "medium", ["\"cmdline\"", "\"memstats\""]),
    ("/server-status", "DED-006", "Apache Server Status Page Exposed", "medium", ["Apache Server Status", "Server uptime", "Current Time"]),
    ("/server-info", "DED-006", "Apache Server Info Page Exposed", "medium", ["Apache Server Information", "Server Settings"]),
]


def _base_origin(url):
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


class ScanEngine:
    def __init__(self, target_url, timeout=DEFAULT_TIMEOUT, verify_tls=True):
        self.target_url = target_url
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.errors_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def _fetch(self):
        page_resp = self.session.get(
            self.target_url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=True,
        )
        origin = _base_origin(page_resp.url)

        probes = []
        for path, rule_id, name, severity, signatures in DEBUG_PROBES:
            probe_url = origin + path
            try:
                r = self.session.get(probe_url, timeout=self.timeout, verify=self.verify_tls, allow_redirects=False)
                body = r.text[:20000] if r.text else ""
                matched = [sig for sig in signatures if sig in body]
                probes.append({
                    "url": probe_url, "rule_id": rule_id, "name": name, "severity": severity,
                    "status_code": r.status_code, "matched_signatures": matched,
                    "confirmed": r.status_code == 200 and bool(matched),
                })
            except requests.exceptions.RequestException:
                self.errors_count += 1
                probes.append({
                    "url": probe_url, "rule_id": rule_id, "name": name, "severity": severity,
                    "status_code": None, "matched_signatures": [], "confirmed": False,
                })

        return {
            "url": page_resp.url,
            "status_code": page_resp.status_code,
            "headers": dict(page_resp.headers),
            "headers_lower": {k.lower(): v for k, v in page_resp.headers.items()},
            "origin": origin,
            "probes": probes,
            "elapsed_ms": round(page_resp.elapsed.total_seconds() * 1000, 1),
        }

    def run(self):
        from app.detection_rules import ALL_RULES
        start = time.time()
        findings = []
        response = None
        try:
            response = self._fetch()
            for rule in ALL_RULES:
                try:
                    result = rule(response)
                except Exception:
                    self.errors_count += 1
                    continue
                if not result:
                    continue
                result_list = result if isinstance(result, list) else [result]
                for item in result_list:
                    item["file_path"] = response["url"]
                    item["permissions_octal"] = str(response["status_code"])
                    item["owner_uid"] = None
                    item["owner_gid"] = None
                    findings.append(item)
        except requests.exceptions.RequestException as exc:
            self.errors_count += 1
            findings.append({
                "rule_id": "DED-000",
                "rule_name": "Target Unreachable",
                "severity": "low",
                "description": f"Could not reach {self.target_url}: {exc}",
                "file_path": self.target_url,
                "permissions_octal": "-",
                "owner_uid": None,
                "owner_gid": None,
            })

        elapsed = time.time() - start
        return {
            "files_scanned": 1 if response else 0,
            "dirs_scanned": len(response["probes"]) if response else 0,
            "errors_count": self.errors_count,
            "response": response,
            "findings": findings,
            "elapsed_seconds": round(elapsed, 3),
        }

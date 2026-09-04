"""Tests for the Debug Endpoint Detector's Security Engine and rules.

Rule-level tests use synthetic response dicts with pre-built 'probes'
lists (no network calls). The engine-level tests spin up a REAL local
HTTP server (Python's http.server, on an ephemeral localhost port) that
genuinely serves realistic content at a couple of the probed debug paths,
and perform REAL HTTP requests against it via the actual ScanEngine code
path — genuine end-to-end testing without touching any third-party site.
Every request made is a standard, passive, read-only GET.
"""
import sys
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security_engine import ScanEngine
from app.detection_rules import (
    rule_framework_debug_page_exposed,
    rule_actuator_endpoint_exposed,
    rule_phpinfo_exposed,
    rule_interactive_debug_console_exposed,
    rule_go_debug_endpoint_exposed,
    rule_apache_status_info_exposed,
)


def resp(url="https://example.com/", probes=None):
    return {"url": url, "status_code": 200, "probes": probes or []}


def probe(rule_id="DED-001", name="Framework Debug/Error Page Exposed", severity="critical",
          url="https://example.com/", status_code=200, matched_signatures=None, confirmed=True):
    return {
        "url": url, "rule_id": rule_id, "name": name, "severity": severity,
        "status_code": status_code, "matched_signatures": matched_signatures or ["Werkzeug Debugger"],
        "confirmed": confirmed,
    }


def test_confirmed_framework_debug_page_flagged():
    result = rule_framework_debug_page_exposed(resp(probes=[probe(rule_id="DED-001", confirmed=True)]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "DED-001"


def test_unconfirmed_probe_not_flagged():
    result = rule_framework_debug_page_exposed(resp(probes=[probe(rule_id="DED-001", confirmed=False)]))
    assert result == []


def test_actuator_confirmed_flagged():
    result = rule_actuator_endpoint_exposed(resp(probes=[probe(rule_id="DED-002", name="Spring Boot Actuator Endpoint Exposed", severity="high")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "DED-002"


def test_phpinfo_confirmed_flagged():
    result = rule_phpinfo_exposed(resp(probes=[probe(rule_id="DED-003", name="phpinfo() Output Exposed", severity="critical")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "DED-003"


def test_console_confirmed_flagged():
    result = rule_interactive_debug_console_exposed(resp(probes=[probe(rule_id="DED-004", name="Interactive Debug Console Exposed", severity="critical")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "DED-004"


def test_go_debug_confirmed_flagged():
    result = rule_go_debug_endpoint_exposed(resp(probes=[probe(rule_id="DED-005", name="Go pprof Debug Endpoint Exposed", severity="medium")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "DED-005"


def test_apache_status_confirmed_flagged():
    result = rule_apache_status_info_exposed(resp(probes=[probe(rule_id="DED-006", name="Apache Server Status Page Exposed", severity="medium")]))
    assert len(result) == 1
    assert result[0]["rule_id"] == "DED-006"


def test_wrong_rule_id_not_matched():
    result = rule_phpinfo_exposed(resp(probes=[probe(rule_id="DED-006")]))
    assert result == []


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Homepage</body></html>")
        elif self.path == "/phpinfo.php":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>phpinfo()</h1>PHP Version 8.1.2<br>PHP Credits</body></html>")
        elif self.path == "/server-status":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Apache Server Status for 127.0.0.1<br>Server uptime: 3 days</body></html>")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def _start_test_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_real_engine_against_local_test_server():
    """Genuine end-to-end HTTP test: real bounded probing of a local
    server we control (not a third party). Every request is a standard,
    passive, read-only GET."""
    server, port = _start_test_server()
    try:
        time.sleep(0.2)
        engine = ScanEngine(f"http://127.0.0.1:{port}/", timeout=5)
        result = engine.run()
        assert result["response"]["status_code"] == 200
        assert len(result["response"]["probes"]) >= 10
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "DED-003" in rule_ids  # real phpinfo() content confirmed
        assert "DED-006" in rule_ids  # real apache server-status content confirmed
    finally:
        server.shutdown()


def test_engine_handles_unreachable_target_gracefully():
    engine = ScanEngine("http://127.0.0.1:1/", timeout=2)
    result = engine.run()
    assert result["errors_count"] >= 1
    assert any(f["rule_id"] == "DED-000" for f in result["findings"])

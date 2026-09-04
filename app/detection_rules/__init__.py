"""
Detection Rules — Debug Endpoint Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects the REAL results of a bounded set of passive GET
probes made against well-known debug/diagnostic paths (see
app/security_engine.DEBUG_PROBES). A probe is only "confirmed" when BOTH
the real HTTP status was 200 AND the real response body contained a
specific, known content signature for that debug tool — this avoids
false positives from generic soft-200 catch-all pages. No sample data is
generated, and no exploit payload is ever sent.
"""

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"


def _confirmed_probes_for(response, rule_id):
    return [p for p in (response.get("probes") or []) if p["rule_id"] == rule_id and p["confirmed"]]


def _make_finding(response, probe):
    return {
        "rule_id": probe["rule_id"],
        "rule_name": probe["name"],
        "severity": probe["severity"],
        "description": (
            f"{probe['name']} was confirmed at {probe['url']} — HTTP "
            f"{probe['status_code']} with real content matching known "
            f"signature(s): {', '.join(probe['matched_signatures'])}."
        ),
    }


def rule_framework_debug_page_exposed(response):
    """DED-001: A framework's interactive debug/error page (Werkzeug,
    Django DEBUG=True, Rails/Rack "Whoops", ASP.NET Yellow Screen of
    Death, or a raw stack trace) is exposed. These pages routinely leak
    source code fragments, file paths, environment variables, and
    sometimes an interactive code-execution console."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "DED-001")]


def rule_actuator_endpoint_exposed(response):
    """DED-002: A Spring Boot Actuator management endpoint is exposed and
    publicly accessible. Actuator endpoints can leak configuration,
    environment variables, health/metrics internals, and in
    misconfigured setups have historically enabled remote code execution
    via endpoints like /actuator/env combined with other gadgets."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "DED-002")]


def rule_phpinfo_exposed(response):
    """DED-003: A real phpinfo() output page is publicly accessible.
    This discloses the full PHP configuration, loaded modules, server
    environment variables, and internal file paths — extremely valuable
    reconnaissance information for an attacker."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "DED-003")]


def rule_interactive_debug_console_exposed(response):
    """DED-004: An interactive debug console (Werkzeug's in-browser
    Python console, or the Symfony web profiler/toolbar) is exposed.
    These are among the most severe debug-endpoint exposures possible:
    the Werkzeug console in particular allows arbitrary Python code
    execution directly from the browser if reached without its PIN."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "DED-004")]


def rule_go_debug_endpoint_exposed(response):
    """DED-005: A Go net/http/pprof profiling endpoint or an expvar
    debug-variable endpoint is exposed. These leak running-process
    internals (goroutine stacks, memory stats, command-line arguments)
    and, for pprof specifically, can also be used to place real load on
    the server via profiling requests."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "DED-005")]


def rule_apache_status_info_exposed(response):
    """DED-006: Apache's mod_status or mod_info diagnostic page is
    exposed. These leak the exact requests currently being processed
    (including URLs and client IPs for mod_status) and the full Apache
    module/configuration tree (for mod_info)."""
    return [_make_finding(response, p) for p in _confirmed_probes_for(response, "DED-006")]


ALL_RULES = [
    rule_framework_debug_page_exposed,
    rule_actuator_endpoint_exposed,
    rule_phpinfo_exposed,
    rule_interactive_debug_console_exposed,
    rule_go_debug_endpoint_exposed,
    rule_apache_status_info_exposed,
]

"""End-to-end integration test against the deliberately vulnerable fixture.

This is the test that proves the scanner does what it claims: it starts the
vulnerable app, scans it, and asserts that each planted vulnerability is
found - and that the noisy modules do not invent findings.
"""

from __future__ import annotations

import http.server
import socket
import threading
import time

import pytest

from nemesis.config import ScanConfig
from nemesis.engine import Engine
from nemesis.models import Confidence, Severity

from .fixtures.vulnerable_app import Handler


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def target_url():
    port = _free_port()
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture(scope="module")
def scan_result(target_url):
    config = ScanConfig(
        target=target_url,
        scope_rules=[f"127.0.0.1:{target_url.rsplit(':', 1)[1]}"],
        profile="full",
        rate={"requests_per_second": 50, "global_concurrency": 10},
        crawl={"max_pages": 40, "max_depth": 3},
    )
    import asyncio

    return asyncio.run(Engine(config).run())


def titles(result) -> list[str]:
    return [f.title.lower() for f in result.findings]


class TestPlantedVulnerabilitiesAreFound:
    def test_sql_injection(self, scan_result):
        matches = [f for f in scan_result.findings if "sql injection" in f.title.lower()]
        assert matches, "SQL injection was not detected"
        assert any(f.confidence == Confidence.CONFIRMED for f in matches)

    def test_reflected_xss(self, scan_result):
        matches = [f for f in scan_result.findings if "xss" in f.title.lower()]
        assert matches, "reflected XSS was not detected"
        assert any(f.confidence == Confidence.CONFIRMED for f in matches)

    def test_path_traversal(self, scan_result):
        matches = [f for f in scan_result.findings if "traversal" in f.title.lower()]
        assert matches, "path traversal was not detected"
        assert any(f.confidence == Confidence.CONFIRMED for f in matches)

    def test_open_redirect(self, scan_result):
        matches = [f for f in scan_result.findings if "redirect" in f.title.lower()]
        assert matches, "open redirect was not detected"

    def test_exposed_env_file(self, scan_result):
        matches = [f for f in scan_result.findings if "/.env" in f.title]
        assert matches
        assert matches[0].severity == Severity.CRITICAL

    def test_exposed_git_directory(self, scan_result):
        matches = [f for f in scan_result.findings if "/.git/HEAD" in f.title]
        assert matches

    def test_missing_security_headers(self, scan_result):
        matches = [f for f in scan_result.findings if "content-security-policy" in f.title.lower()]
        assert matches

    def test_insecure_cookie(self, scan_result):
        matches = [f for f in scan_result.findings if "httponly" in f.title.lower()]
        assert matches

    def test_directory_listing(self, scan_result):
        matches = [f for f in scan_result.findings if "directory listing" in f.title.lower()]
        assert matches

    def test_idor(self, scan_result):
        matches = [f for f in scan_result.findings if "idor" in f.title.lower()]
        assert matches

    def test_stack_trace_disclosure(self, scan_result):
        matches = [f for f in scan_result.findings if "stack trace" in f.title.lower()]
        assert matches


class TestNoFalsePositives:
    def test_no_command_injection_against_a_clean_endpoint(self, scan_result):
        """The app never executes shell commands, so this must stay silent."""
        matches = [
            f for f in scan_result.findings if "command injection" in f.title.lower()
        ]
        assert not matches, f"false positive: {[f.title for f in matches]}"

    def test_no_sql_injection_on_echo_endpoint(self, scan_result):
        """/echo reflects input but never touches a database."""
        matches = [
            f
            for f in scan_result.findings
            if "sql injection" in f.title.lower() and "echo" in f.target.lower()
        ]
        assert not matches, f"false positive: {[f.title for f in matches]}"

    def test_no_nosql_findings(self, scan_result):
        matches = [f for f in scan_result.findings if "nosql" in f.title.lower()]
        assert not matches, f"false positive: {[f.title for f in matches]}"


class TestReportQuality:
    def test_no_duplicate_titles_for_the_same_weakness(self, scan_result):
        """The same missing header must be reported once, not once per URL."""
        header_findings = [
            f for f in scan_result.findings if f.module == "headers_security"
        ]
        assert header_findings
        assert len(header_findings) == len({f.title for f in header_findings})

    def test_forms_are_deduplicated(self, scan_result):
        keys = [(f.method, f.action) for f in scan_result.forms]
        assert len(keys) == len(set(keys))

    def test_every_finding_has_a_remediation(self, scan_result):
        for finding in scan_result.findings:
            assert finding.remediation, f"no remediation for: {finding.title}"

    def test_every_finding_has_evidence(self, scan_result):
        for finding in scan_result.findings:
            assert finding.evidence.response or finding.evidence.matched, (
                f"no evidence for: {finding.title}"
            )

    def test_risk_score_is_bounded(self, scan_result):
        assert 0 <= scan_result.risk_score() <= 100

    def test_technology_fingerprinted(self, scan_result):
        assert any("nginx" in t.name.lower() for t in scan_result.technologies)

    def test_endpoints_discovered(self, scan_result):
        assert len(scan_result.endpoints) >= 8

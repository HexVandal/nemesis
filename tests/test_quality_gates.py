"""Four gates the scanner has to pass about itself, not about its targets.

These are the checks a buyer would run before trusting a report: does every
detector know what class of bug it looks for, does it say what to do about
it, does the output stay stable between runs, and does the same defect
arrive twice.
"""

from __future__ import annotations

import asyncio
import http.server
import re
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from nemesis.config import ScanConfig
from nemesis.engine import Engine
from nemesis.http.client import HttpClient, Response
from nemesis.models import Category, Confidence, Evidence, Finding, Severity
from nemesis.modules.base import ModuleRegistry
from nemesis.scope import Scope

CWE_RE = re.compile(r"^CWE-\d+$")
OWASP_RE = re.compile(r"^(A0[1-9]|A10|LLM\d{2}|API\d{2}|M\d|C\d)$")


def registry() -> ModuleRegistry:
    reg = ModuleRegistry(ScanConfig())
    reg.load_builtin()
    return reg


def modules():
    return list(registry()._modules.values())


class _Plain(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self):
        body = b"<html><body><h1>hello</h1></body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def bare_site():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Plain)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


class TestMappingCompleteness:
    """Every detector names the weakness class it hunts (ledger item 299)."""

    def test_every_module_declares_a_cwe(self):
        missing = [m.id for m in modules() if not CWE_RE.match(m.cwe or "")]
        assert missing == [], f"modules without a CWE: {missing}"

    def test_every_web_module_declares_an_owasp_category(self):
        # Memory forensics is not web work; OWASP Top 10 does not describe it.
        exempt = {m.id for m in modules() if m.group == "forensics"}
        bad = [
            m.id
            for m in modules()
            if m.id not in exempt and not OWASP_RE.match(m.owasp or "")
        ]
        assert bad == [], f"modules with a missing or invalid OWASP mapping: {bad}"

    def test_declared_values_are_capitalised_correctly(self):
        # 'cwe-79' and 'cwe79' both look fine to a human and break every
        # downstream join against a CWE database.
        bad = [m.id for m in modules() if not (m.cwe or "").startswith("CWE-")]
        assert bad == []


class TestRemediation:
    """A finding nobody can act on is a warning, not a result (ledger item 308)."""

    def test_every_module_has_remediation_text(self):
        empty = [m.id for m in modules() if not (m.remediation or "").strip()]
        assert empty == [], f"modules without remediation: {empty}"

    def test_remediation_is_an_instruction(self):
        # Long enough to say something, and not a restatement of the title.
        thin = [
            m.id
            for m in modules()
            if len(m.remediation.strip()) < 20
            or m.remediation.strip().lower() == m.name.strip().lower()
        ]
        assert thin == [], f"remediation too thin to act on: {thin}"

    def test_every_module_has_a_description(self):
        assert [m.id for m in modules() if not (m.description or "").strip()] == []

    def test_findings_inherit_the_remediation(self):
        module = registry()._modules["headers_security"]
        finding = module.finding(
            title="t", target="https://x.test", description="d",
            evidence_text="e", matched="m",
        )
        assert finding.remediation
        assert finding.cwe


class TestDeduplication:
    """The same defect must not arrive twice (ledger item 297)."""

    @staticmethod
    def _finding(module: str, title: str, target: str, confidence: Confidence,
                 severity: Severity = Severity.MEDIUM) -> Finding:
        return Finding(
            title=title, severity=severity, confidence=confidence, description="d",
            target=target, module=module, category=Category.INFO,
            evidence=Evidence(matched="m"),
        )

    def test_identical_findings_collapse(self):
        a = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.MEDIUM)
        b = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.MEDIUM)
        assert a.fingerprint == b.fingerprint
        assert len(Engine._dedupe([a, b])) == 1

    def test_the_kept_copy_is_the_more_confident_one(self):
        weak = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.LOW)
        strong = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.CONFIRMED)
        kept = Engine._dedupe([weak, strong])
        assert len(kept) == 1 and kept[0].confidence is Confidence.CONFIRMED

    def test_different_targets_do_not_collapse(self):
        a = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.HIGH)
        b = self._finding("idor", "IDOR on order", "https://x.test/o/2", Confidence.HIGH)
        assert len(Engine._dedupe([a, b])) == 2

    def test_different_detectors_do_not_collapse(self):
        a = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.HIGH)
        b = self._finding("bolo", "IDOR on order", "https://x.test/o/1", Confidence.HIGH)
        assert len(Engine._dedupe([a, b])) == 2

    def test_fingerprint_ignores_volatile_fields(self):
        first = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.HIGH)
        second = self._finding("idor", "IDOR on order", "https://x.test/o/1", Confidence.HIGH)
        # Identity and timestamp are assigned per instance; the fingerprint
        # must not move with them, or dedupe across runs would never work.
        assert first.id != second.id
        assert first.fingerprint == second.fingerprint


class TestDeterminism:
    """Two runs over the same fixture produce the same report (ledger item 309)."""

    @staticmethod
    def _scan(url: str) -> list[tuple]:
        config = ScanConfig(target=url, profile="web")
        client = HttpClient(config, Scope(rules=[url], default_host="127.0.0.1"))
        module = registry()._modules["headers_security"]
        ctx = SimpleNamespace(
            config=config,
            scope=Scope(rules=[url], default_host="127.0.0.1"),
            client=client,
            target_url=url,
            host="127.0.0.1",
            endpoints=[],
            forms=[],
            responses=[
                Response(url=f"{url}/", status=200, headers={}, text="<html>hello</html>",
                         content=b"", elapsed=0.01)
            ],
        )

        async def go():
            async with client:
                return await module.run(ctx)

        findings = asyncio.run(go())
        return [
            (f.module, f.title, f.target, f.severity.value, f.confidence.value, f.fingerprint)
            for f in Engine._dedupe(findings)
        ]

    def test_the_detector_fires_at_all(self, bare_site):
        assert self._scan(bare_site)

    def test_two_runs_are_identical(self, bare_site):
        assert self._scan(bare_site) == self._scan(bare_site)

    def test_order_is_stable(self, bare_site):
        first = self._scan(bare_site)
        second = self._scan(bare_site)
        assert [row[0] for row in first] == [row[0] for row in second]

    def test_no_finding_carries_a_random_fingerprint(self):
        # A fingerprint must be derived from the finding, never generated.
        ids = [m.finding(title="t", target="https://x.test", description="d",
                         evidence_text="e", matched="m").fingerprint for m in modules()[:20]]
        assert all(len(value) == 16 for value in ids)
        assert len(set(ids)) == len(ids)

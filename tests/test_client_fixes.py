"""Regressions for defects that shipped silently.

Each test here corresponds to a bug that existed, passed the suite, and was
found only by executing the scanner against a live target:

* request bodies were stripped out of the request before it was sent
* the HTML report inserted scanner output without escaping it
* scope could be escaped by a redirect

A test that does not fail against the old code is not a regression test.
"""

from __future__ import annotations

import asyncio
import http.server
import socket
import threading
import time
from pathlib import Path

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import HttpClient
from nemesis.models import Confidence, Evidence, Finding, ScanResult, Severity, Target
from nemesis.reporting.html import write_html
from nemesis.scope import Scope


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _Echo(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def _reply(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://elsewhere.invalid/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._reply(b"ok")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        self._reply(b"BODY=[" + body + b"]")


@pytest.fixture(scope="module")
def echo_url():
    port = _free_port()
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Echo)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(echo_url: str):
    config = ScanConfig(target=echo_url, profile="web")
    scope = Scope(rules=[echo_url], default_host="127.0.0.1")
    return HttpClient(config, scope)


class TestRequestBodiesAreActuallySent:
    """The bug: ``kwargs.pop("data")`` removed the body before the request."""

    def test_form_data_reaches_the_server(self, echo_url):
        async def go():
            async with _client(echo_url) as client:
                return await client.post(f"{echo_url}/x", data={"price": "-1", "qty": "1"})

        response = asyncio.run(go())
        assert "price=-1" in response.text
        assert "qty=1" in response.text

    def test_raw_content_reaches_the_server(self, echo_url):
        async def go():
            async with _client(echo_url) as client:
                return await client.post(f"{echo_url}/x", content=b"<xml>payload</xml>")

        assert "<xml>payload</xml>" in asyncio.run(go()).text

    def test_json_reaches_the_server(self, echo_url):
        async def go():
            async with _client(echo_url) as client:
                return await client.post(f"{echo_url}/x", json={"amount": -1})

        body = asyncio.run(go()).text
        assert "amount" in body and "-1" in body

    def test_the_recorded_body_matches_what_was_sent(self, echo_url):
        """Evidence must describe the request that happened, not one we meant to send."""

        async def go():
            async with _client(echo_url) as client:
                return await client.post(f"{echo_url}/x", data={"price": "-1"})

        response = asyncio.run(go())
        assert "price=-1" in response.text
        assert "-1" in response.request_body


class TestRedirectsCannotEscapeScope:
    def test_out_of_scope_redirect_is_refused(self, echo_url):
        async def go():
            async with _client(echo_url) as client:
                return await client.get(f"{echo_url}/redirect")

        response = asyncio.run(go())
        assert response.error == "redirect_out_of_scope"


class TestHtmlReportEscaping:
    """The bug: ``jinja2.Template`` defaults to ``autoescape=False``."""

    @staticmethod
    def _result(payload: str) -> ScanResult:
        finding = Finding(
            module="xss",
            title=payload,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            target=payload,
            description=payload,
            remediation=payload,
            evidence=Evidence(request="GET /", response=payload),
        )
        result = ScanResult(
            target=Target(
                base_url="https://victim.test",
                host="victim.test",
                scheme="https",
                port=443,
                name="victim",
            )
        )
        result.findings = [finding]
        return result

    def test_script_tags_are_escaped(self, tmp_path: Path):
        payload = "<script>alert(document.cookie)</script>"
        out = write_html(self._result(payload), tmp_path / "r.html").read_text()
        assert "<script>alert(document.cookie)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_attribute_breakouts_are_escaped(self, tmp_path: Path):
        payload = '"><img src=x onerror=alert(1)>'
        out = write_html(self._result(payload), tmp_path / "r.html").read_text()
        assert "<img src=x onerror=alert(1)>" not in out
        assert "&lt;img" in out

    def test_report_still_renders_real_content(self, tmp_path: Path):
        out = write_html(self._result("Plain finding title"), tmp_path / "r.html").read_text()
        assert "Plain finding title" in out
        assert "nemesis" in out

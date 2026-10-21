"""What the client does when a server misbehaves, and what a score means."""

from __future__ import annotations

import asyncio
import http.server
import json
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import HttpClient
from nemesis.models import Confidence, Finding, Severity
from nemesis.reporting.sarif import write_sarif
from nemesis.scope import Scope

HITS: dict[str, int] = {}


class _Flaky(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def _respond(self, status: int, body: str = "") -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        HITS["get"] = HITS.get("get", 0) + 1
        if HITS["get"] == 1:
            return self._respond(503, "later")
        return self._respond(200, "ok")

    def do_POST(self):
        HITS["post"] = HITS.get("post", 0) + 1
        return self._respond(503, "later")


@pytest.fixture(scope="module")
def flaky():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Flaky)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _client(url: str, **rate):
    config = ScanConfig(target=url, rate={"backoff": 0.01, **rate})
    return config, HttpClient(config, Scope(rules=[url], default_host="127.0.0.1"))


class TestRetry:
    def test_get_retries_a_503(self, flaky):
        HITS.clear()
        _, client = _client(flaky, max_retries=1)

        async def go():
            async with client:
                return await client.get(f"{flaky}/x")

        response = asyncio.run(go())
        assert response.status == 200
        assert HITS["get"] == 2

    def test_post_is_never_retried(self, flaky):
        HITS.clear()
        _, client = _client(flaky, max_retries=3)

        async def go():
            async with client:
                return await client.post(f"{flaky}/x", data={"a": "1"})

        response = asyncio.run(go())
        assert response.status == 503
        assert HITS["post"] == 1

    def test_zero_retries_means_one_request(self, flaky):
        HITS.clear()
        _, client = _client(flaky, max_retries=0)

        async def go():
            async with client:
                return await client.get(f"{flaky}/x")

        response = asyncio.run(go())
        assert response.status == 503
        assert HITS["get"] == 1


class TestScoring:
    def _finding(self, severity: Severity, **kwargs) -> Finding:
        return Finding(
            title="t", severity=severity, confidence=Confidence.HIGH,
            description="d", target="https://x.test", module="m", **kwargs,
        )

    def test_severity_supplies_a_score(self):
        assert self._finding(Severity.CRITICAL).cvss_score == 9.8
        assert self._finding(Severity.HIGH).cvss_score == 8.1
        assert self._finding(Severity.MEDIUM).cvss_score == 6.5
        assert self._finding(Severity.LOW).cvss_score == 3.1
        assert self._finding(Severity.INFO).cvss_score == 0.0

    def test_a_real_score_is_not_overwritten(self):
        finding = self._finding(Severity.LOW, cvss_score=9.1)
        assert finding.cvss_score == 9.1

    def test_a_vector_suppresses_the_band(self):
        finding = self._finding(Severity.CRITICAL, cvss="CVSS:3.1/AV:N/AC:L")
        assert finding.cvss_score is None

    def test_sarif_carries_the_score(self):
        finding = self._finding(Severity.HIGH)
        result = type(
            "R", (), {"findings": [finding], "target": None, "started_at": "",
                      "finished_at": "", "tool": None}
        )()
        with tempfile.TemporaryDirectory() as tmp:
            path = write_sarif(result, Path(tmp) / "out.sarif")
            data = json.loads(path.read_text())
        runs = data["runs"][0]
        rule = runs["tool"]["driver"]["rules"][0]
        assert rule["properties"]["security-severity"] == "8.1"

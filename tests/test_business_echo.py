"""The business-logic module must see a number that moved without the page moving."""

from __future__ import annotations

import asyncio
import http.server
import socket
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import HttpClient
from nemesis.models import Endpoint
from nemesis.modules.web.business import BusinessLogicModule
from nemesis.scope import Scope


class _Cart(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, body: str) -> None:
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        query = {k: v[-1] for k, v in parse_qs(urlparse(self.path).query).items()}
        quantity = query.get("quantity", "1")
        # Same page shape either way: one character of difference.
        self._send(f"total: {quantity}")


@pytest.fixture(scope="module")
def cart():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Cart)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.2)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _scan(url: str):
    config = ScanConfig(target=url, profile="web", rate={"requests_per_second": 50})
    scope = Scope(rules=[url], default_host="127.0.0.1")
    client = HttpClient(config, scope)
    ctx = SimpleNamespace(
        config=config, scope=scope, client=client, target_url=url, host="127.0.0.1",
        endpoints=[Endpoint(url=f"{url}/checkout?quantity=1", params={"quantity": "1"})],
        forms=[], responses=[],
    )

    async def go():
        async with client:
            return await BusinessLogicModule(config).run(ctx)

    return asyncio.run(go())


class TestEqualLengthTampering:
    def test_the_moved_number_is_reported(self, cart):
        findings = _scan(cart)
        assert findings, "the echoed -1 was filtered out by the size gate"
        assert any("quantity" in f.title for f in findings)

    def test_the_evidence_carries_both_sides(self, cart):
        finding = _scan(cart)[0]
        assert "Baseline" in finding.evidence.response
        assert "Probe" in finding.evidence.response
        assert "-1" in finding.evidence.response

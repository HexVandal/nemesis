"""Price tampering: carts, payment gateways and product pages.

These tests exist because the module is worthless if it merely notices that a
response changed. Every assertion here is about a *number*: the server's own
total must move to the attacker's value for a finding to be allowed.
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

from .fixtures.shop_app import Handler


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def shop_url():
    port = _free_port()
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture(scope="module")
def scan(shop_url):
    config = ScanConfig(
        target=shop_url,
        scope_rules=[shop_url],
        profile="web",
        include_modules=["price_tampering"],
        rate={"requests_per_second": 50, "global_concurrency": 10},
        crawl={"max_pages": 20, "max_depth": 3},
    )
    import asyncio

    return asyncio.run(Engine(config).run())


def _titles(scan) -> list[str]:
    return [f.title.lower() for f in scan.findings]


class TestTheModuleIsRegistered:
    def test_it_is_discoverable_by_id(self):
        from nemesis.config import ScanConfig as Cfg
        from nemesis.modules.base import ModuleRegistry

        registry = ModuleRegistry(Cfg())
        registry.load_builtin()
        assert "price_tampering" in registry._modules

    def test_it_sits_in_the_business_group(self, scan):
        assert all(f.module == "price_tampering" for f in scan.findings)


class TestProductPages:
    def test_query_string_price_is_caught(self, scan):
        matches = [
            f for f in scan.findings
            if "product page" in f.title.lower() and "price" in f.title.lower()
        ]
        assert matches, f"no product-page finding in {_titles(scan)}"
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].confidence == Confidence.CONFIRMED

    def test_the_evidence_states_the_before_and_after(self, scan):
        match = next(f for f in scan.findings if "product page" in f.title.lower())
        assert "baseline" in match.evidence.response.lower()
        assert "tampered" in match.evidence.response.lower()
        assert "100" in match.evidence.response


class TestCarts:
    def test_hidden_price_in_a_post_form_is_caught(self, scan):
        matches = [
            f for f in scan.findings
            if "cart" in f.title.lower() and "'price'" in f.title.lower()
        ]
        assert matches, f"no cart price finding in {_titles(scan)}"
        assert matches[0].confidence == Confidence.CONFIRMED

    def test_negative_quantity_is_caught(self, scan):
        matches = [
            f for f in scan.findings
            if "cart" in f.title.lower() and "'qty'" in f.title.lower()
        ]
        assert matches, f"no qty finding in {_titles(scan)}"

    def test_the_payload_actually_reached_the_server(self, scan):
        """The evidence must quote a total the server computed, not a 200."""
        cart = next(f for f in scan.findings if "'price'" in f.title and "cart" in f.title.lower())
        assert "total=-1.00" in cart.evidence.matched


class TestPaymentGateways:
    def test_a_json_only_gateway_is_caught(self, scan):
        matches = [f for f in scan.findings if "json" in f.title.lower()]
        assert matches, f"the JSON gateway was not tested: {_titles(scan)}"
        assert matches[0].severity == Severity.CRITICAL
        assert "amount=-1" in matches[0].evidence.matched


class TestNoFalsePositives:
    def test_a_server_side_price_is_not_reported(self, scan):
        """``/safe`` ignores the parameter; it must produce no finding."""
        assert not [f for f in scan.findings if "/safe" in f.target], _titles(scan)

    def test_every_finding_carries_a_proof(self, scan):
        for finding in scan.findings:
            assert finding.evidence.matched, f"no proof for {finding.title}"

    def test_findings_are_not_duplicated_per_parameter(self, scan):
        keys = [(f.target, f.title) for f in scan.findings]
        assert len(keys) == len(set(keys))

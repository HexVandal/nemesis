"""Tests that nemesis never leaves the scope it was given.

This is the most important safety property of the tool. A scanner that
wanders off the target is a scanner that gets people sued, so these tests
exercise it directly rather than trusting the implementation.
"""

from __future__ import annotations

import asyncio
import socket
import socketserver
import threading
import time

import pytest

from nemesis.config import ScanConfig
from nemesis.engine import Engine
from nemesis.scope import Scope

from .fixtures.vulnerable_app import Handler


def _free_ports(count: int) -> list[int]:
    """Reserve *count* distinct ports at once.

    Asking the OS for ports one at a time can return the same port twice,
    because the first socket is released before the second is opened.
    """
    sockets = []
    ports: list[int] = []
    try:
        for _ in range(count):
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            sockets.append(sock)
            ports.append(sock.getsockname()[1])
        return ports
    finally:
        for sock in sockets:
            sock.close()


class CountingHandler(Handler):
    """The fixture app, with a request counter."""

    hits: list[str] = []

    def do_GET(self):
        CountingHandler.hits.append(self.path)
        super().do_GET()

    def do_POST(self):
        CountingHandler.hits.append(self.path)
        super().do_POST()


@pytest.fixture(scope="module")
def two_hosts():
    """Two servers on different ports, standing in for two different hosts."""
    ports = _free_ports(2)
    servers = []
    CountingHandler.hits = []
    for port in ports:
        socketserver.TCPServer.allow_reuse_address = True
        server = socketserver.TCPServer(("127.0.0.1", port), CountingHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    time.sleep(0.3)
    try:
        yield ports
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


class TestScopeObject:
    def test_empty_scope_denies_everything(self):
        scope = Scope(rules=[])
        assert not scope.allows("https://example.com/")

    def test_scope_expands_to_a_bare_domain(self):
        scope = Scope(rules=["api.example.com"])
        seeds = scope.expand_seed("https://api.example.com/v1/users")
        assert "https://api.example.com/" in seeds

    def test_path_rule_respects_the_path(self):
        scope = Scope(rules=["example.com/api"])
        assert scope.allows("https://example.com/api/users")
        assert not scope.allows("https://example.com/admin/users")

    def test_exclusion_beats_inclusion(self):
        scope = Scope(rules=["example.com"], exclusions=["example.com/admin"])
        assert not scope.allows("https://example.com/admin/x")

    def test_port_is_part_of_the_identity(self):
        scope = Scope(rules=["example.com:8443"])
        assert scope.allows("https://example.com:8443/")
        assert not scope.allows("https://example.com/")

    def test_unicode_and_odd_schemes_are_denied(self):
        scope = Scope(rules=["example.com"])
        assert not scope.allows("ftp://example.com/")
        assert not scope.allows("")


class TestClientRespectsScope:
    def test_out_of_scope_host_is_refused(self, two_hosts):
        first, second = two_hosts
        config = ScanConfig(target=f"http://127.0.0.1:{first}")
        scope = Scope(rules=[f"127.0.0.1:{first}"])

        async def go():
            from nemesis.http.client import HttpClient

            async with HttpClient(config, scope) as client:
                return await client.get(f"http://127.0.0.1:{second}/")

        response = asyncio.run(go())
        assert response.status == 0
        assert response.error, "an out-of-scope request was not refused"

    def test_in_scope_host_is_allowed(self, two_hosts):
        first, _ = two_hosts
        config = ScanConfig(target=f"http://127.0.0.1:{first}")
        scope = Scope(rules=[f"127.0.0.1:{first}"])

        async def go():
            from nemesis.http.client import HttpClient

            async with HttpClient(config, scope) as client:
                return await client.get(f"http://127.0.0.1:{first}/")

        response = asyncio.run(go())
        assert response.status == 200

    def test_redirect_to_an_out_of_scope_host_is_not_followed(self, two_hosts):
        """A redirect must not smuggle the client off the target."""
        first, second = two_hosts
        config = ScanConfig(target=f"http://127.0.0.1:{first}")
        scope = Scope(rules=[f"127.0.0.1:{first}"])

        async def go():
            from nemesis.http.client import HttpClient

            async with HttpClient(config, scope) as client:
                return await client.get(
                    f"http://127.0.0.1:{first}/redirect?next=http://127.0.0.1:{second}/"
                )

        CountingHandler.hits.clear()
        response = asyncio.run(go())
        # The redirect must have been refused, not followed.
        assert response.error == "redirect_out_of_scope"
        assert response.redirect_chain == []
        # And the out-of-scope host must never have received a request.
        assert CountingHandler.hits == [f"/redirect?next=http://127.0.0.1:{second}/"]

    def test_in_scope_redirect_is_followed(self, two_hosts):
        first, _ = two_hosts
        config = ScanConfig(target=f"http://127.0.0.1:{first}")
        scope = Scope(rules=[f"127.0.0.1:{first}"])

        async def go():
            from nemesis.http.client import HttpClient

            async with HttpClient(config, scope) as client:
                return await client.get(f"http://127.0.0.1:{first}/redirect?next=/products")

        response = asyncio.run(go())
        assert not response.error
        assert response.status == 200
        assert "Products" in response.text


class TestCrawlerStaysInScope:
    def test_no_out_of_scope_endpoint_is_crawled(self, two_hosts):
        first, _second = two_hosts
        config = ScanConfig(
            target=f"http://127.0.0.1:{first}",
            scope_rules=[f"127.0.0.1:{first}"],
            profile="quick",
            rate={"requests_per_second": 40, "global_concurrency": 8},
            crawl={"max_pages": 20, "max_depth": 2},
        )
        result = asyncio.run(Engine(config).run())
        for endpoint in result.endpoints:
            assert f":{first}" in endpoint.url, endpoint.url

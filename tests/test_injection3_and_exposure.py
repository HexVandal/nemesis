"""The batch after the batch: eight more, each proved on a live fixture."""

from __future__ import annotations

import asyncio
import http.server
import json
import socket
import threading
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import Response
from nemesis.models import Endpoint, Form
from nemesis.modules.web.api_protocol import GraphqlBatchingModule, OAuthPkceModule
from nemesis.modules.web.injection3 import (
    CsrfTokenReuseModule,
    SsiInjectionModule,
    XPathInjectionModule,
)
from nemesis.modules.web.js_exposure import (
    RobotsDisclosureModule,
    SecretsInJavascriptModule,
    SourceMapModule,
)
from nemesis.scope import Scope

SOURCE_MAP = json.dumps({"version": 3, "mappings": "AAAA", "sources": ["src/app.ts", "src/key.ts"]})
BUNDLE = "const k='AKIAIOSFODNN7EXAMPLE'; const g='AIzaSyA1234567890abcdefghijklmnopqrstu';"


class _App(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, status: int, body: str = "", ctype: str = "text/html") -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        if parsed.path == "/xpath":
            term = query.get("q", "")
            if "'" in term or "1=1" in term:
                return self._send(500, "SimpleXMLElement::xpath(): Invalid expression")
            return self._send(200, f"<user>{term}</user>")
        if parsed.path == "/ssi":
            name = query.get("name", "")
            if "printenv" in name:
                return self._send(200, "DOCUMENT_ROOT=/var/www/html")
            return self._send(200, f"hello {name}")
        if parsed.path == "/form":
            return self._send(
                200,
                '<form method="post" action="/form">'
                '<input name="csrf_token" value="tok123">'
                '<input name="note" value=""></form>',
            )
        if parsed.path == "/strict/form":
            return self._send(
                200,
                '<form method="post" action="/strict/form">'
                '<input name="csrf_token" value="tok123"></form>',
            )
        if parsed.path == "/app.js":
            return self._send(200, BUNDLE, "application/javascript")
        if parsed.path == "/app.js.map":
            return self._send(200, SOURCE_MAP, "application/json")
        if parsed.path == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /public\n", "text/plain")
        if parsed.path == "/admin":
            return self._send(200, "admin panel")
        if parsed.path == "/public":
            return self._send(200, "public page")
        return self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode() if length else ""
        if parsed.path == "/form":
            return self._send(200, "note saved")
        if parsed.path == "/strict/form":
            return self._send(400, "csrf token expired or already used")
        if parsed.path == "/graphql":
            try:
                document = json.loads(body)
            except ValueError:
                return self._send(400, "bad request")
            if isinstance(document, list):
                return self._send(
                    200,
                    json.dumps([{"data": {"__typename": "Query"}} for _ in document]),
                    "application/json",
                )
            return self._send(200, json.dumps({"data": {"__typename": "Query"}}), "application/json")
        return self._send(404, "not found")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def app_url():
    port = _free_port()
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _App)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


def _run(module_cls, app_url, **kwargs):
    from nemesis.http.client import HttpClient

    config = ScanConfig(target=app_url, profile="web", allow_destructive=True)
    scope = Scope(rules=[app_url], default_host="127.0.0.1")
    client = HttpClient(config, scope)
    base = {
        "config": config, "scope": scope, "client": client, "target_url": app_url,
        "host": "127.0.0.1", "endpoints": [], "forms": [], "responses": [],
    }
    base.update(kwargs)
    ctx = SimpleNamespace(**base)

    async def go():
        async with client:
            return await module_cls(config).run(ctx)

    return asyncio.run(go())


class TestXPath:
    def test_a_parser_error_is_proof(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/xpath?q=alice", params={"q": "alice"})
        findings = _run(XPathInjectionModule, app_url, endpoints=[endpoint])
        assert findings and "SimpleXMLElement" in findings[0].evidence.matched

    def test_a_safe_parser_is_silent(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/public?q=alice", params={"q": "alice"})
        assert _run(XPathInjectionModule, app_url, endpoints=[endpoint]) == []


class TestSsi:
    def test_an_executed_directive_is_proof(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/ssi?name=x", params={"name": "x"})
        findings = _run(SsiInjectionModule, app_url, endpoints=[endpoint])
        assert findings and "DOCUMENT_ROOT" in findings[0].evidence.matched


class TestCsrfReuse:
    def _form(self, app_url, path):
        return Form(
            action=f"{app_url}{path}", method="post",
            fields={"csrf_token": "tok123", "note": "x"},
            raw_fields=["csrf_token", "note"], source_url=f"{app_url}{path}",
        )

    def test_a_token_accepted_twice_is_reported(self, app_url):
        findings = _run(CsrfTokenReuseModule, app_url, forms=[self._form(app_url, "/form")])
        assert findings

    def test_a_consumed_token_is_silent(self, app_url):
        findings = _run(
            CsrfTokenReuseModule, app_url, forms=[self._form(app_url, "/strict/form")]
        )
        assert findings == []


class TestJavascript:
    def _response(self, url, text, ctype="application/javascript"):
        return Response(
            url=url, status=200, headers={"content-type": ctype}, text=text,
            content=text.encode(), elapsed=0.01,
        )

    def test_a_key_in_a_bundle_is_reported(self):
        config = ScanConfig(target="https://t.test")
        ctx = SimpleNamespace(
            config=config,
            responses=[self._response("https://t.test/app.js", BUNDLE)],
            target_url="https://t.test",
        )
        findings = asyncio.run(SecretsInJavascriptModule(config).run(ctx))
        labels = {f.evidence.extra["kind"] for f in findings}
        assert "AWS access key" in labels

    def test_a_clean_bundle_is_silent(self):
        config = ScanConfig(target="https://t.test")
        ctx = SimpleNamespace(
            config=config,
            responses=[self._response("https://t.test/app.js", "const x = 1;")],
            target_url="https://t.test",
        )
        assert asyncio.run(SecretsInJavascriptModule(config).run(ctx)) == []


class TestSourceMap:
    def test_a_published_map_is_reported(self, app_url):
        response = Response(
            url=f"{app_url}/app.js", status=200, headers={}, text=BUNDLE,
            content=BUNDLE.encode(), elapsed=0.01,
        )
        findings = _run(SourceMapModule, app_url, responses=[response])
        assert findings and findings[0].evidence.extra["source_count"] == 2


class TestRobots:
    def test_a_reachable_disallowed_path_is_reported(self, app_url):
        findings = _run(RobotsDisclosureModule, app_url)
        assert findings and "/admin" in findings[0].evidence.extra["paths"]


class TestPkce:
    def _endpoint(self, app_url, extra=""):
        return Endpoint(
            url=f"{app_url}/oauth/authorize?client_id=a&response_type=code"
            f"&redirect_uri=https%3A%2F%2Fc.test%2Fcb{extra}",
            params={"client_id": "a"},
        )

    def test_a_code_flow_without_challenge_is_reported(self, app_url):
        findings = _run(OAuthPkceModule, app_url, endpoints=[self._endpoint(app_url)])
        assert findings

    def test_a_challenged_flow_is_silent(self, app_url):
        findings = _run(
            OAuthPkceModule,
            app_url,
            endpoints=[self._endpoint(app_url, "&code_challenge=abc&code_challenge_method=S256")],
        )
        assert findings == []


class TestGraphqlBatching:
    def test_an_array_of_operations_is_reported(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/graphql", params={})
        findings = _run(GraphqlBatchingModule, app_url, endpoints=[endpoint])
        assert findings and findings[0].evidence.extra["batch_size"] == 2

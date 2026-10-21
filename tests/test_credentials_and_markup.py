"""Eight more detectors, each with a vulnerable fixture and a hardened twin."""

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
from nemesis.http.client import Response
from nemesis.models import Endpoint, Form
from nemesis.modules.web.credentials2 import (
    DefaultCredentialsModule,
    OAuthStateModule,
    WeakPasswordPolicyModule,
)
from nemesis.modules.web.discovery2 import ApiSchemaModule, SensitiveDataInUrlModule
from nemesis.modules.web.ldap import LdapInjectionModule
from nemesis.modules.web.markup import ReverseTabnabbingModule, SriModule
from nemesis.scope import Scope

OPENAPI = '{"openapi": "3.0.1", "paths": {"/a": {}, "/b": {}}, "info": {"title": "x"}}'


class _App(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, status: int, body: str = "", headers: dict | None = None) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        if parsed.path == "/openapi.json":
            return self._send(200, OPENAPI, {"Content-Type": "application/json"})
        if parsed.path == "/oauth/authorize":
            return self._send(302, "", {"Location": query.get("redirect_uri", "/")})
        if parsed.path == "/oauth/strict/authorize":
            if "state" not in query:
                return self._send(400, "state required")
            return self._send(302, "", {"Location": query.get("redirect_uri", "/")})
        if parsed.path == "/ldap":
            term = query.get("user", "")
            if "*)(uid=*" in term:
                return self._send(
                    500,
                    "javax.naming.directory.InvalidSearchFilterException: bad filter",
                )
            return self._send(200, f"results for {term}")
        return self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode() if length else ""
        data = {k: v[0] for k, v in parse_qs(body).items()}

        if parsed.path == "/admin/login":
            if data.get("username") == "admin" and data.get("password") == "admin":
                return self._send(
                    302,
                    "<html><body>logout</body></html>",
                    {"Location": "/dashboard", "Set-Cookie": "session=abc123; Path=/"},
                )
            return self._send(200, "Invalid username or password.")
        if parsed.path == "/safe/login":
            return self._send(200, "Invalid username or password.")
        if parsed.path == "/register":
            return self._send(201, "<html>Welcome, your account was created.</html>")
        if parsed.path == "/safe/register":
            return self._send(400, "Password too short: at least 12 characters.")
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


def _ctx(app_url, client, **kwargs):
    config = ScanConfig(target=app_url, profile="web", allow_destructive=True)
    scope = Scope(rules=[app_url], default_host="127.0.0.1")
    base = {
        "config": config, "scope": scope, "client": client,
        "target_url": app_url, "host": "127.0.0.1", "endpoints": [], "forms": [],
        "responses": [],
    }
    base.update(kwargs)
    return config, SimpleNamespace(**base)


def _client(app_url):
    from nemesis.http.client import HttpClient

    config = ScanConfig(target=app_url, profile="web")
    return HttpClient(config, Scope(rules=[app_url], default_host="127.0.0.1"))


def _run(module_cls, app_url, **kwargs):
    client = _client(app_url)
    config, ctx = _ctx(app_url, client, **kwargs)

    async def go():
        async with client:
            return await module_cls(config).run(ctx)

    return asyncio.run(go())


def _login_form(app_url, path):
    return Form(
        action=f"{app_url}{path}", method="post",
        fields={"username": "", "password": ""},
        raw_fields=["username", "password"], source_url=f"{app_url}{path}",
    )


class TestDefaultCredentials:
    def test_a_shipped_default_is_reported(self, app_url):
        findings = _run(DefaultCredentialsModule, app_url, forms=[_login_form(app_url, "/admin/login")])
        assert findings
        assert findings[0].severity.value == 4
        assert findings[0].evidence.extra["username"] == "admin"

    def test_a_form_that_rejects_everything_is_silent(self, app_url):
        findings = _run(DefaultCredentialsModule, app_url, forms=[_login_form(app_url, "/safe/login")])
        assert findings == []


class TestWeakPasswordPolicy:
    def test_a_one_character_password_is_reported(self, app_url):
        form = Form(
            action=f"{app_url}/register", method="post",
            fields={"username": "", "password": ""},
            raw_fields=["username", "password"], source_url=f"{app_url}/register",
        )
        findings = _run(WeakPasswordPolicyModule, app_url, forms=[form])
        assert findings
        assert findings[0].severity.value == 2

    def test_a_policy_error_is_silent(self, app_url):
        form = Form(
            action=f"{app_url}/safe/register", method="post",
            fields={"username": "", "password": ""},
            raw_fields=["username", "password"], source_url=f"{app_url}/safe/register",
        )
        assert _run(WeakPasswordPolicyModule, app_url, forms=[form]) == []


class TestOAuthState:
    def _endpoint(self, app_url, path):
        return Endpoint(
            url=f"{app_url}{path}?client_id=abc&redirect_uri=https%3A%2F%2Fc.test%2Fcb&state=xyz",
            params={"client_id": "abc"},
        )

    def test_a_flow_without_state_is_reported(self, app_url):
        findings = _run(
            OAuthStateModule, app_url, endpoints=[self._endpoint(app_url, "/oauth/authorize")]
        )
        assert findings

    def test_an_endpoint_that_requires_state_is_silent(self, app_url):
        findings = _run(
            OAuthStateModule, app_url, endpoints=[self._endpoint(app_url, "/oauth/strict/authorize")]
        )
        assert findings == []


class TestApiSchema:
    def test_a_public_schema_is_reported(self, app_url):
        findings = _run(ApiSchemaModule, app_url)
        assert findings
        assert findings[0].evidence.extra["path_count"] == 2


class TestSensitiveDataInUrl:
    def test_a_token_in_the_query_is_reported(self):
        config = ScanConfig(target="https://t.test")
        endpoint = Endpoint(url="https://t.test/reset?token=abcdef1234567890", params={})
        ctx = SimpleNamespace(
            config=config, endpoints=[endpoint], responses=[], target_url="https://t.test"
        )
        findings = asyncio.run(SensitiveDataInUrlModule(config).run(ctx))
        assert findings and findings[0].severity.value == 2

    def test_a_plain_url_is_silent(self):
        config = ScanConfig(target="https://t.test")
        endpoint = Endpoint(url="https://t.test/search?q=shoes", params={})
        ctx = SimpleNamespace(
            config=config, endpoints=[endpoint], responses=[], target_url="https://t.test"
        )
        assert asyncio.run(SensitiveDataInUrlModule(config).run(ctx)) == []


class TestMarkup:
    def _response(self, text):
        return Response(
            url="https://t.test/page", status=200, headers={}, text=text,
            content=text.encode(), elapsed=0.01,
        )

    def test_a_third_party_script_without_integrity_is_reported(self):
        config = ScanConfig(target="https://t.test")
        response = self._response('<script src="https://cdn.other.test/lib.js"></script>')
        ctx = SimpleNamespace(
            config=config, responses=[response], target_url="https://t.test"
        )
        findings = asyncio.run(SriModule(config).run(ctx))
        assert findings and "cdn.other.test" in findings[0].evidence.matched

    def test_a_pinned_asset_is_silent(self):
        config = ScanConfig(target="https://t.test")
        response = self._response(
            '<script src="https://cdn.other.test/lib.js" integrity="sha384-abc"></script>'
        )
        ctx = SimpleNamespace(
            config=config, responses=[response], target_url="https://t.test"
        )
        assert asyncio.run(SriModule(config).run(ctx)) == []

    def test_a_blank_target_without_noopener_is_reported(self):
        config = ScanConfig(target="https://t.test")
        response = self._response('<a href="https://other.test" target="_blank">go</a>')
        ctx = SimpleNamespace(
            config=config, responses=[response], target_url="https://t.test"
        )
        assert asyncio.run(ReverseTabnabbingModule(config).run(ctx))

    def test_rel_noopener_is_silent(self):
        config = ScanConfig(target="https://t.test")
        response = self._response(
            '<a href="https://other.test" target="_blank" rel="noopener">go</a>'
        )
        ctx = SimpleNamespace(
            config=config, responses=[response], target_url="https://t.test"
        )
        assert asyncio.run(ReverseTabnabbingModule(config).run(ctx)) == []


class TestLdap:
    def test_a_directory_error_is_proof(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/ldap?user=alice", params={"user": "alice"})
        findings = _run(LdapInjectionModule, app_url, endpoints=[endpoint])
        assert findings
        assert "javax.naming" in findings[0].evidence.matched

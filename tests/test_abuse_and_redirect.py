"""Four checks that must prove their claims, not assert them.

Each test has a vulnerable endpoint and a hardened twin. A detector that
passes on the first and fails on the second is doing something real; one that
fires on both is noise.
"""

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
from nemesis.models import Endpoint, Form
from nemesis.modules.web.abuse import RateLimitingModule, StoredXssModule
from nemesis.modules.web.redirect import CrlfInjectionModule, OAuthRedirectModule
from nemesis.scope import Scope

STATE: dict[str, list[str]] = {"guestbook": [], "safe_guestbook": [], "logins": {}}


class _App(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: str = "", headers: dict | None = None) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def _form(self, action: str, fields: list[tuple[str, str]]) -> str:
        inputs = "".join(
            f'<input name="{name}" type="{kind}">' for name, kind in fields
        )
        return f'<html><body><form method="post" action="{action}">{inputs}</form></body></html>'

    # -- routes ----------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

        if parsed.path == "/login":
            return self._send(200, self._form("/login", [("username", "text"), ("password", "password")]))
        if parsed.path == "/strict/login":
            return self._send(
                200, self._form("/strict/login", [("username", "text"), ("password", "password")])
            )
        if parsed.path == "/zoo":
            # Vulnerable: the value goes into a response header verbatim.
            return self._send(200, "ok", {"X-Zoo": query.get("q", "")})
        if parsed.path == "/strict/zoo":
            # Hardened: control characters are stripped before the header.
            clean = query.get("q", "").replace("\r", "").replace("\n", "")
            return self._send(200, "ok", {"X-Zoo": clean})
        if parsed.path == "/oauth/authorize":
            target = query.get("redirect_uri", "/")
            return self._send(302, "", {"Location": target})
        if parsed.path == "/strict/oauth/authorize":
            target = query.get("redirect_uri", "/")
            if urlparse(target).netloc.endswith(".invalid"):
                target = "/"
            return self._send(302, "", {"Location": target})
        if parsed.path == "/guestbook":
            entries = "".join(f"<li>{e}</li>" for e in STATE["guestbook"])
            return self._send(200, self._form("/guestbook", [("name", "text"), ("message", "text")]) + entries)
        if parsed.path == "/safe/guestbook":
            import html

            entries = "".join(f"<li>{html.escape(e)}</li>" for e in STATE["safe_guestbook"])
            return self._send(
                200,
                self._form("/safe/guestbook", [("name", "text"), ("message", "text")]) + entries,
            )
        return self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode() if length else ""
        data = {k: v[0] for k, v in parse_qs(body).items()}

        if parsed.path == "/login":
            return self._send(200, "Invalid username or password.")
        if parsed.path == "/strict/login":
            attempts = STATE["logins"].get("strict", 0) + 1
            STATE["logins"]["strict"] = attempts
            if attempts >= 3:
                return self._send(429, "Too many attempts. Try again later.")
            return self._send(200, "Invalid username or password.")
        if parsed.path == "/guestbook":
            STATE["guestbook"].append(data.get("message", ""))
            return self._send(201, "stored")
        if parsed.path == "/safe/guestbook":
            STATE["safe_guestbook"].append(data.get("message", ""))
            return self._send(201, "stored")
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


def _run(module, ctx):
    return asyncio.run(module.run(ctx))


def _ctx(url: str, **kwargs):
    from nemesis.http.client import HttpClient

    config = ScanConfig(target=url, profile="web", allow_destructive=True)
    scope = Scope(rules=[url], default_host="127.0.0.1")
    return config, scope, HttpClient(config, scope)


def _login_form(url: str, action: str) -> Form:
    return Form(
        action=f"{url}{action}",
        method="post",
        fields={"username": "", "password": ""},
        raw_fields=["username", "password"],
        source_url=f"{url}{action}",
    )


class TestRateLimiting:
    def test_an_unthrottled_form_is_reported(self, app_url):
        config, scope, client = _ctx(app_url)
        ctx = SimpleNamespace(
            config=config, scope=scope, client=client, target_url=app_url,
            host="127.0.0.1", forms=[_login_form(app_url, "/login")],
        )

        async def go():
            async with client:
                return await RateLimitingModule(config).run(ctx)

        findings = asyncio.run(go())
        assert findings, "a login form with no throttle was not reported"
        assert findings[0].severity.value == 2
        assert findings[0].evidence.extra["attempts"] == 8

    def test_a_throttled_form_is_silent(self, app_url):
        STATE["logins"].clear()
        config, scope, client = _ctx(app_url)
        ctx = SimpleNamespace(
            config=config, scope=scope, client=client, target_url=app_url,
            host="127.0.0.1", forms=[_login_form(app_url, "/strict/login")],
        )

        async def go():
            async with client:
                return await RateLimitingModule(config).run(ctx)

        assert asyncio.run(go()) == []


class TestCrlf:
    def _ctx_for(self, app_url, path, param="q"):
        config, scope, client = _ctx(app_url)
        endpoint = Endpoint(url=f"{app_url}{path}?{param}=x", params={param: "x"})
        return config, client, SimpleNamespace(
            config=config, scope=scope, client=client, target_url=app_url,
            host="127.0.0.1", endpoints=[endpoint], forms=[],
        )

    def test_an_injected_header_is_proof(self, app_url):
        config, client, ctx = self._ctx_for(app_url, "/zoo")

        async def go():
            async with client:
                return await CrlfInjectionModule(config).run(ctx)

        findings = asyncio.run(go())
        assert findings, "the header was injected but not reported"
        assert findings[0].confidence.value == "confirmed"
        assert "X-Nemesis-Injected" in findings[0].evidence.matched

    def test_a_server_that_strips_newlines_is_silent(self, app_url):
        config, client, ctx = self._ctx_for(app_url, "/strict/zoo")

        async def go():
            async with client:
                return await CrlfInjectionModule(config).run(ctx)

        assert asyncio.run(go()) == []


class TestOAuth:
    def _ctx_for(self, app_url, path):
        config, scope, client = _ctx(app_url)
        url = f"{app_url}{path}?client_id=abc&redirect_uri=https%3A%2F%2Fclient.test%2Fcb&state=1"
        return config, client, SimpleNamespace(
            config=config, scope=scope, client=client, target_url=app_url,
            host="127.0.0.1", endpoints=[Endpoint(url=url, params={"client_id": "abc"})], forms=[],
        )

    def test_a_foreign_redirect_uri_is_reported(self, app_url):
        config, client, ctx = self._ctx_for(app_url, "/oauth/authorize")

        async def go():
            async with client:
                return await OAuthRedirectModule(config).run(ctx)

        findings = asyncio.run(go())
        assert findings, "the redirect left the site and was not reported"
        assert findings[0].confidence.value == "confirmed"

    def test_a_validating_endpoint_is_silent(self, app_url):
        config, client, ctx = self._ctx_for(app_url, "/strict/oauth/authorize")

        async def go():
            async with client:
                return await OAuthRedirectModule(config).run(ctx)

        assert asyncio.run(go()) == []


class TestStoredXss:
    def _ctx_for(self, app_url, path):
        config, scope, client = _ctx(app_url)
        form = Form(
            action=f"{app_url}{path}",
            method="post",
            fields={"name": "", "message": ""},
            raw_fields=["name", "message"],
            source_url=f"{app_url}{path}",
        )
        return config, client, SimpleNamespace(
            config=config, scope=scope, client=client, target_url=app_url,
            host="127.0.0.1", endpoints=[], forms=[form],
        )

    def test_a_stored_marker_is_reported(self, app_url):
        config, client, ctx = self._ctx_for(app_url, "/guestbook")

        async def go():
            async with client:
                return await StoredXssModule(config).run(ctx)

        findings = asyncio.run(go())
        assert findings, "the marker came back as markup and was not reported"
        assert findings[0].confidence.value == "confirmed"
        assert findings[0].evidence.matched.startswith("<xss")

    def test_an_escaping_renderer_is_silent(self, app_url):
        config, client, ctx = self._ctx_for(app_url, "/safe/guestbook")

        async def go():
            async with client:
                return await StoredXssModule(config).run(ctx)

        assert asyncio.run(go()) == []

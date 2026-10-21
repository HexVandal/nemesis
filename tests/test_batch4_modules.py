"""The fourth batch: thirty modules, one fixture, every one exercised."""

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
from nemesis.modules.ai.llm_deep import (
    AiEndpointAuthModule,
    AiRateLimitModule,
    IndirectPromptInjectionModule,
    SystemPromptModule,
)
from nemesis.modules.deps.supply import LockfileModule, ProvenanceModule, SbomModule
from nemesis.modules.web.abuse2 import (
    CacheControlModule,
    CacheDeceptionModule,
    GraphqlDepthModule,
    RaceConditionModule,
    RateLimitBypassModule,
)
from nemesis.modules.web.api_deep import (
    AccountEnumerationModule,
    ApiEndpointModule,
    ApiUnauthenticatedModule,
    FunctionLevelAuthzModule,
    OpenApiSecurityModule,
    ResetTokenEntropyModule,
)
from nemesis.modules.web.availability import ResourceExhaustionModule
from nemesis.modules.web.injection4 import (
    ElInjectionModule,
    NullByteModule,
    ParameterPollutionModule,
    RedosModule,
    UnicodeNormalizationModule,
)
from nemesis.modules.web.misc_deep import (
    ClientValidationModule,
    CsvFormulaModule,
    DanglingDnsModule,
    OauthScopeModule,
    SensitiveStorageModule,
    SubdomainTakeoverModule,
)
from nemesis.scope import Scope

HITS = {"throttled": 0}


class _App(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def _send(self, status: int, body: str = "", headers: dict | None = None,
              ctype: str = "text/html; charset=utf-8") -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        # Last value wins, the way PHP and most CGI stacks behave.
        query = {k: v[-1] for k, v in parse_qs(parsed.query).items()}

        if path == "/":
            return self._send(200, '<html><a href="/login">login</a>'
                                   '<script src="http://does-not-exist-nms.invalid/a.js"></script></html>')
        if path == "/login":
            return self._send(200, '<form method="post" action="/login">'
                                   '<input name="username"><input name="password" type="password">'
                                   "</form>")
        if path == "/admin":
            return self._send(200, "<h1>Admin console</h1>" * 5)
        if path == "/openapi.json":
            return self._send(200, json.dumps({"openapi": "3.0.1", "paths": {"/a": {}}}),
                              ctype="application/json")
        if path == "/api/users":
            return self._send(200, '{"users": [{"id": 1}], "note": "api root"}')
        if path == "/api/orders":
            return self._send(200, '{"orders": [1, 2, 3], "account": "alice"}')
        if path == "/expr":
            value = query.get("q", "")
            return self._send(200, "result 49" if "7*7" in value else "result")
        if path == "/hpp":
            return self._send(200, "x=" + query.get("x", ""))
        if path == "/slow":
            # Only the pathological shape is slow; the length-matched benign
            # baseline must stay fast or the ratio measures nothing.
            if "!" in query.get("q", ""):
                time.sleep(0.25)
            return self._send(200, "matched")
        if path == "/nul":
            value = query.get("f", "")
            if "\x00" in value:
                return self._send(200, "uploaded")
            return self._send(400, "rejected")
        if path == "/uni":
            value = query.get("q", "")
            return self._send(200, "wide" if any(ord(c) > 0xFF00 for c in value) else "ascii")
        if path == "/account":
            return self._send(200, "<html>my account logout email alice@example.test</html>")
        if path == "/account/x.css":
            return self._send(200, "<html>my account logout email alice@example.test</html>")
        if path == "/app.js":
            return self._send(200, "localStorage.setItem('auth_token', t);",
                              ctype="application/javascript")
        if path == "/export/users.csv":
            return self._send(200, "name,note\nbob,=1+1+cmd\n", ctype="text/csv")
        if path == "/bucket":
            return self._send(404, "<h1>NoSuchBucket</h1>")
        if path == "/oauth/authorize":
            return self._send(302, "", {"Location": query.get("redirect_uri", "/")})
        if path == "/api/chat":
            return self._send(200, json.dumps({
                "reply": "You are a helpful assistant. My instructions are to answer briefly.",
            }), ctype="application/json")
        if path == "/throttle":
            HITS["throttled"] += 1
            if "X-Forwarded-For" not in self.headers and HITS["throttled"] > 3:
                return self._send(429, "slow down")
            return self._send(200, "ok")
        return self._send(404, "not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        data = {k: v[-1] for k, v in parse_qs(raw.decode(errors="ignore")).items()}

        if parsed.path == "/login":
            if data.get("username") == "admin":
                return self._send(401, "Invalid password for this account.")
            return self._send(401, "No account with that name.")
        if parsed.path == "/cart":
            _App.counter = getattr(_App, "counter", 0) + 1
            return self._send(200, f"cart updated, receipt {_App.counter}")
        if parsed.path == "/profile":
            return self._send(200, "profile saved")
        if parsed.path == "/note":
            return self._send(201, "stored")
        if parsed.path == "/api/echo":
            return self._send(200, '{"ok": true}')
        if parsed.path == "/graphql":
            return self._send(200, json.dumps({"data": {"__schema": {}}}),
                              ctype="application/json")
        if parsed.path == "/api/chat":
            return self._send(200, json.dumps({"reply": "pong"}), ctype="application/json")
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


def _login(url: str) -> Form:
    return Form(
        action=f"{url}/login", method="post",
        fields={"username": "", "password": ""},
        raw_fields=["username", "password"], source_url=f"{url}/login",
    )


class TestApiAuthorization:
    def test_unauthenticated_access_needs_credentials(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/orders", params={})
        # No credentials configured: the module must stay silent, not guess.
        assert _run(ApiUnauthenticatedModule, app_url, endpoints=[endpoint]) == []

    def test_anonymous_admin_path(self, app_url):
        findings = _run(FunctionLevelAuthzModule, app_url, forms=[_login(app_url)])
        assert any("/admin" in f.evidence.matched for f in findings)

    def test_no_login_means_no_complaint(self, app_url):
        assert _run(FunctionLevelAuthzModule, app_url) == []

    def test_openapi_without_security(self, app_url):
        assert _run(OpenApiSecurityModule, app_url)

    def test_undocumented_api_root(self, app_url):
        findings = _run(ApiEndpointModule, app_url)
        assert any("/api/users" in f.evidence.matched for f in findings)

    def test_account_enumeration(self, app_url):
        findings = _run(AccountEnumerationModule, app_url, forms=[_login(app_url)])
        assert findings

    def test_short_reset_token(self):
        config = ScanConfig(target="https://t.test")
        endpoint = Endpoint(url="https://t.test/reset?token=abc123", params={})
        ctx = SimpleNamespace(config=config, endpoints=[endpoint], responses=[],
                              target_url="https://t.test")
        assert asyncio.run(ResetTokenEntropyModule(config).run(ctx))

    def test_long_reset_token_is_silent(self):
        config = ScanConfig(target="https://t.test")
        endpoint = Endpoint(url="https://t.test/reset?token=" + "a" * 40, params={})
        ctx = SimpleNamespace(config=config, endpoints=[endpoint], responses=[],
                              target_url="https://t.test")
        assert asyncio.run(ResetTokenEntropyModule(config).run(ctx)) == []


class TestParserEdges:
    def test_expression_language(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/expr?q=1", params={"q": "1"})
        assert _run(ElInjectionModule, app_url, endpoints=[endpoint])

    def test_parameter_pollution(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/hpp?x=1", params={"x": "1"})
        assert _run(ParameterPollutionModule, app_url, endpoints=[endpoint])

    def test_redos(self, app_url):
        module_threshold = RedosModule(ScanConfig(target=app_url))
        module_threshold.floor_seconds = 0.05
        module_threshold.factor = 2.0

        from nemesis.http.client import HttpClient

        config = ScanConfig(target=app_url, profile="web")
        client = HttpClient(config, Scope(rules=[app_url], default_host="127.0.0.1"))
        ctx = SimpleNamespace(
            config=config, scope=Scope(rules=[app_url], default_host="127.0.0.1"),
            client=client, target_url=app_url, host="127.0.0.1",
            endpoints=[Endpoint(url=f"{app_url}/slow?q=1", params={"q": "1"})],
            forms=[], responses=[],
        )

        async def go():
            async with client:
                return await module_threshold.run(ctx)

        assert asyncio.run(go())

    def test_null_byte(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/nul?f=x", params={"f": "x"})
        assert _run(NullByteModule, app_url, endpoints=[endpoint])

    def test_unicode_normalisation(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/uni?q=x", params={"q": "x"})
        assert _run(UnicodeNormalizationModule, app_url, endpoints=[endpoint])


class TestAbuse:
    def test_graphql_depth(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/graphql", params={})
        assert _run(GraphqlDepthModule, app_url, endpoints=[endpoint])

    def test_rate_limit_bypass(self, app_url):
        HITS["throttled"] = 0
        module_cls = RateLimitBypassModule
        original = module_cls.burst
        module_cls.burst = 4
        try:
            findings = _run(module_cls, f"{app_url}/throttle")
        finally:
            module_cls.burst = original
        assert findings

    def test_cache_deception(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/account", params={})
        assert _run(CacheDeceptionModule, app_url, endpoints=[endpoint])

    def test_cache_control(self):
        config = ScanConfig(target="https://t.test")
        response = Response(
            url="https://t.test/account", status=200,
            headers={"set-cookie": "sid=1"}, text="my account logout",
            content=b"", elapsed=0.01,
        )
        ctx = SimpleNamespace(config=config, responses=[response], target_url="https://t.test")
        assert asyncio.run(CacheControlModule(config).run(ctx))

    def test_race_condition(self, app_url):
        form = Form(action=f"{app_url}/cart", method="post", fields={"item": "1"},
                    raw_fields=["item"], source_url=f"{app_url}/cart")
        assert _run(RaceConditionModule, app_url, forms=[form])


class TestMiscellaneous:
    def test_sensitive_storage(self):
        config = ScanConfig(target="https://t.test")
        response = Response(
            url="https://t.test/app.js", status=200, headers={},
            text="localStorage.setItem('auth_token', t)", content=b"", elapsed=0.01,
        )
        ctx = SimpleNamespace(config=config, responses=[response], target_url="https://t.test")
        assert asyncio.run(SensitiveStorageModule(config).run(ctx))

    def test_client_validation(self, app_url):
        form = Form(action=f"{app_url}/profile", method="post", fields={"age": ""},
                    raw_fields=["age"], source_url=f"{app_url}/profile")
        assert _run(ClientValidationModule, app_url, forms=[form])

    def test_subdomain_takeover(self, app_url):
        assert _run(SubdomainTakeoverModule, f"{app_url}/bucket")

    def test_dangling_dns(self, app_url):
        response = Response(
            url=f"{app_url}/", status=200, headers={},
            text='<script src="http://does-not-exist-nms.invalid/a.js"></script>',
            content=b"", elapsed=0.01,
        )
        assert _run(DanglingDnsModule, app_url, responses=[response])

    def test_csv_formula(self, app_url):
        form = Form(action=f"{app_url}/note", method="post", fields={"note": ""},
                    raw_fields=["note"], source_url=f"{app_url}/note")
        endpoint = Endpoint(url=f"{app_url}/export/users.csv", params={})
        assert _run(CsvFormulaModule, app_url, forms=[form], endpoints=[endpoint])

    def test_oauth_scope(self, app_url):
        endpoint = Endpoint(
            url=f"{app_url}/oauth/authorize?client_id=a&redirect_uri=https%3A%2F%2Fc.test%2Fcb&scope=read",
            params={},
        )
        assert _run(OauthScopeModule, app_url, endpoints=[endpoint])


class TestSupplyChain:
    def test_missing_lockfile(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        config = ScanConfig(target="https://t.test")
        ctx = SimpleNamespace(config=config, code_path=str(tmp_path))
        assert asyncio.run(LockfileModule(config).run(ctx))

    def test_present_lockfile_is_silent(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        (tmp_path / "poetry.lock").write_text("")
        config = ScanConfig(target="https://t.test")
        ctx = SimpleNamespace(config=config, code_path=str(tmp_path))
        assert asyncio.run(LockfileModule(config).run(ctx)) == []

    def test_missing_sbom(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        config = ScanConfig(target="https://t.test")
        ctx = SimpleNamespace(config=config, code_path=str(tmp_path))
        assert asyncio.run(SbomModule(config).run(ctx))

    def test_missing_provenance(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
        config = ScanConfig(target="https://t.test")
        ctx = SimpleNamespace(config=config, code_path=str(tmp_path))
        assert asyncio.run(ProvenanceModule(config).run(ctx))


class TestAi:
    def test_system_prompt(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/chat", params={})
        assert _run(SystemPromptModule, app_url, endpoints=[endpoint])

    def test_ai_endpoint_auth(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/chat", params={})
        assert _run(AiEndpointAuthModule, app_url, endpoints=[endpoint])

    def test_ai_rate_limit(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/chat", params={})
        module_cls = AiRateLimitModule
        original = module_cls.burst
        module_cls.burst = 3
        try:
            findings = _run(module_cls, app_url, endpoints=[endpoint])
        finally:
            module_cls.burst = original
        assert findings

    def test_indirect_prompt_injection(self, app_url):
        form = Form(action=f"{app_url}/note", method="post", fields={"body": ""},
                    raw_fields=["body"], source_url=f"{app_url}/note")
        endpoint = Endpoint(url=f"{app_url}/api/chat", params={})
        # The fixture never echoes the canary, so this must stay silent.
        assert _run(IndirectPromptInjectionModule, app_url, forms=[form],
                    endpoints=[endpoint]) == []


class TestAvailability:
    def test_deep_json_accepted(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/echo", params={})
        module_cls = ResourceExhaustionModule
        original = module_cls.big_value_size
        module_cls.big_value_size = 128
        try:
            findings = _run(module_cls, app_url, endpoints=[endpoint])
        finally:
            module_cls.big_value_size = original
        assert findings

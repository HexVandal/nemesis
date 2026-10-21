"""The third batch: deployment artifacts, protocol handling, policy, money.

One fixture serves the whole file. Every module is exercised at least once,
and the ones with a plausible false-positive path have a hardened twin.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import socket
import threading
import time
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import Response
from nemesis.models import Endpoint, Form
from nemesis.modules.web.claims import JwtAudienceModule, JwtLifetimeModule
from nemesis.modules.web.deployment import (
    ActuatorModule,
    BackupFileModule,
    CiMetadataModule,
    DebugConsoleModule,
    DirectoryListingModule,
    EnvFileModule,
    ErrorFingerprintModule,
    VcsMetadataModule,
)
from nemesis.modules.web.policy import (
    CorsOriginReflectionModule,
    CspReportOnlyModule,
    PermissionsPolicyModule,
)
from nemesis.modules.web.protocol import (
    AcceptHeaderModule,
    ApiVersionFallbackModule,
    CookieScopeModule,
    HostHeaderCacheModule,
    MethodDiscoveryModule,
    MethodOverrideModule,
    VerbTamperingModule,
)
from nemesis.scope import Scope

ENV_BODY = "DB_HOST=localhost\nDB_PASSWORD=hunter2\nSECRET_KEY=abc123\n"


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
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # -- deployment artifacts
        if path == "/.env":
            return self._send(200, ENV_BODY, {"Content-Type": "text/plain"})
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", {"Content-Type": "text/plain"})
        if path == "/.gitlab-ci.yml":
            return self._send(200, "stages:\n  - build\nscript:\n  - make\n", {"Content-Type": "text/plain"})
        if path == "/actuator/env":
            return self._send(200, '{"propertySources": []}', {"Content-Type": "application/json"})
        if path == "/console":
            return self._send(200, "<title>H2 Console</title>Login")
        if path == "/app/index.bak":
            return self._send(200, "secret backup content")
        if path == "/files/":
            return self._send(200, "<title>Index of /files</title>")
        if path.startswith("/nemesis-"):
            return self._send(404, "<h1>Whitelabel Error Page</h1>")

        # -- protocol
        if path == "/api/v2/users":
            return self._send(200, '{"users": []}', {"Content-Type": "application/json"})
        if path == "/api/v1/users":
            return self._send(200, '{"users": []}', {"Content-Type": "application/json"})
        if path == "/api/things":
            return self._send(200, '{"things": []}', {"Content-Type": "application/json"})
        if path == "/origin":
            return self._send(
                200,
                "hello",
                {
                    "Access-Control-Allow-Origin": self.headers.get("Origin", ""),
                    "Access-Control-Allow-Credentials": "true",
                },
            )
        if path == "/poison":
            return self._send(
                200,
                f"<link href='https://{self.headers.get('X-Forwarded-Host', 'x')}/a.css'>",
                {"X-Cache": "HIT", "Age": "12"},
            )
        if path == "/report-only":
            return self._send(
                200, "page", {"Content-Security-Policy-Report-Only": "default-src 'self'"}
            )
        if path == "/no-policy":
            return self._send(200, "page")
        return self._send(404, "not found")

    def do_OPTIONS(self):
        if urlparse(self.path).path == "/api/things":
            return self._send(204, "", {"Allow": "GET, PUT, DELETE, OPTIONS"})
        return self._send(405, "")

    def do_PUT(self):
        if urlparse(self.path).path == "/api/things":
            return self._send(204, "")
        return self._send(405, "")

    def do_DELETE(self):
        return self._send(405, "")

    def do_PATCH(self):
        return self._send(405, "")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        self.rfile.read(length)
        if parsed.path == "/api/things":
            override = self.headers.get("X-HTTP-Method-Override", "")
            if override == "DELETE":
                return self._send(204, "")
            return self._send(200, "ok")
        if parsed.path == "/checkout":
            # Two identical submissions produce two different order ids.
            import itertools

            _App._order = getattr(_App, "_order", itertools.count(1000))
            return self._send(201, f"order {next(_App._order)} created")
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


class TestDeploymentArtifacts:
    def test_env_file(self, app_url):
        findings = _run(EnvFileModule, app_url)
        assert findings and findings[0].severity.value == 4

    def test_vcs_metadata(self, app_url):
        findings = _run(VcsMetadataModule, app_url)
        assert any("/.git" in f.evidence.extra["path"] for f in findings)

    def test_ci_metadata(self, app_url):
        assert _run(CiMetadataModule, app_url)

    def test_actuator(self, app_url):
        assert _run(ActuatorModule, app_url)

    def test_debug_console(self, app_url):
        assert _run(DebugConsoleModule, app_url)

    def test_backup_file(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/app/index", params={})
        assert _run(BackupFileModule, app_url, endpoints=[endpoint])

    def test_directory_listing(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/files/a.txt", params={})
        assert _run(DirectoryListingModule, app_url, endpoints=[endpoint])

    def test_error_fingerprint(self, app_url):
        assert _run(ErrorFingerprintModule, app_url)


class TestProtocol:
    def test_verb_tampering(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/things", params={})
        findings = _run(VerbTamperingModule, app_url, endpoints=[endpoint])
        assert any(f.evidence.extra["verb"] == "PUT" for f in findings)

    def test_options_discovery(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/things", params={})
        findings = _run(MethodDiscoveryModule, app_url, endpoints=[endpoint])
        assert findings and "DELETE" in findings[0].evidence.extra["verbs"]

    def test_method_override(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/things", params={})
        assert _run(MethodOverrideModule, app_url, endpoints=[endpoint])

    def test_api_version_fallback(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/v2/users", params={})
        findings = _run(ApiVersionFallbackModule, app_url, endpoints=[endpoint])
        assert findings

    def test_accept_header_xml(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/api/things", params={})
        # This fixture always answers JSON, so the module must stay quiet.
        assert _run(AcceptHeaderModule, app_url, endpoints=[endpoint]) == []

    def test_host_header_cache(self, app_url):
        findings = _run(HostHeaderCacheModule, app_url + "/poison")
        assert findings and findings[0].evidence.extra["cache_headers"]

    def test_cookie_scope(self):
        config = ScanConfig(target="https://t.test")
        response = Response(
            url="https://t.test/", status=200,
            headers={"set-cookie": "sid=1; Domain=.com; Path=/"},
            text="", content=b"", elapsed=0.01,
        )
        ctx = SimpleNamespace(config=config, responses=[response], target_url="https://t.test")
        assert asyncio.run(CookieScopeModule(config).run(ctx))

    def test_narrow_cookie_is_silent(self):
        config = ScanConfig(target="https://t.test")
        response = Response(
            url="https://t.test/", status=200,
            headers={"set-cookie": "sid=1; Domain=.app.test; Path=/"},
            text="", content=b"", elapsed=0.01,
        )
        ctx = SimpleNamespace(config=config, responses=[response], target_url="https://t.test")
        assert asyncio.run(CookieScopeModule(config).run(ctx)) == []


class TestPolicy:
    def _ctx(self, headers):
        config = ScanConfig(target="https://t.test")
        response = Response(
            url="https://t.test/", status=200, headers=headers,
            text="", content=b"", elapsed=0.01,
        )
        return config, SimpleNamespace(
            config=config, responses=[response], target_url="https://t.test",
            endpoints=[], forms=[],
        )

    def test_csp_report_only(self):
        config, ctx = self._ctx(
            {"content-security-policy-report-only": "default-src 'self'"}
        )
        assert asyncio.run(CspReportOnlyModule(config).run(ctx))

    def test_enforcing_csp_is_silent(self):
        config, ctx = self._ctx({"content-security-policy": "default-src 'self'"})
        assert asyncio.run(CspReportOnlyModule(config).run(ctx)) == []

    def test_missing_permissions_policy(self):
        config, ctx = self._ctx({})
        assert asyncio.run(PermissionsPolicyModule(config).run(ctx))

    def test_restrictive_permissions_policy_is_silent(self):
        config, ctx = self._ctx({"permissions-policy": "camera=(), microphone=()"})
        assert asyncio.run(PermissionsPolicyModule(config).run(ctx)) == []

    def test_cors_reflection(self, app_url):
        endpoint = Endpoint(url=f"{app_url}/origin", params={})
        findings = _run(CorsOriginReflectionModule, app_url, endpoints=[endpoint])
        assert findings and findings[0].severity.value == 3


class TestJwtClaims:
    def _ctx(self, token):
        config = ScanConfig(target="https://t.test")
        response = Response(
            url="https://t.test/", status=200, headers={"set-cookie": f"t={token}"},
            text="", content=b"", elapsed=0.01,
        )
        return config, SimpleNamespace(
            config=config, responses=[response], target_url="https://t.test",
            endpoints=[], forms=[],
        )

    def test_missing_audience(self):
        token = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxIn0."
            "c2lnbmF0dXJlc2lnbmF0dXJlc2lnbmF0dXJl"
        )
        config, ctx = self._ctx(token)
        assert asyncio.run(JwtAudienceModule(config).run(ctx))

    def test_long_lifetime(self):
        import base64

        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "1", "aud": "a", "iat": 0, "exp": 400 * 86400}).encode()
        ).rstrip(b"=").decode()
        token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.c2lnbmF0dXJlc2lnbmF0dXJl"
        config, ctx = self._ctx(token)
        findings = asyncio.run(JwtLifetimeModule(config).run(ctx))
        assert findings and findings[0].evidence.extra["lifetime_days"] >= 400


class TestBusinessRules:
    def test_duplicate_checkout(self, app_url):
        from nemesis.modules.web.business2 import IdempotencyModule

        form = Form(
            action=f"{app_url}/checkout", method="post", fields={"item": "1"},
            raw_fields=["item"], source_url=f"{app_url}/checkout",
        )
        assert _run(IdempotencyModule, app_url, forms=[form])

    def test_unbounded_page_size(self, app_url):
        from nemesis.modules.web.business2 import PaginationBoundaryModule

        # The fixture ignores the parameter, so the response never grows.
        endpoint = Endpoint(url=f"{app_url}/api/things?limit=10", params={"limit": "10"})
        assert _run(PaginationBoundaryModule, app_url, endpoints=[endpoint]) == []

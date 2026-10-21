"""JWT weaknesses and mass assignment.

Both modules make a claim that must survive scrutiny:

* JWT - "this token can be forged". Proved by reproducing the signature with a
  recovered key, or by reading ``alg: none`` off the wire.
* Mass assignment - "the server stored a field it never offered". Proved by
  reading the elevated value back out of the response.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import http.server
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from nemesis.config import ScanConfig
from nemesis.http.client import Response
from nemesis.models import Confidence, Severity
from nemesis.modules.web.jwt import JwtWeaknessModule, decode_token, recover_secret
from nemesis.modules.web.mass_assignment import MassAssignmentModule


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, secret: str | None = None) -> str:
    head = _b64(json.dumps(header, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode()
    if secret is None:
        return f"{head}.{body}."
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{head}.{body}.{_b64(sig)}"


def ctx_with(tokens: list[str]) -> SimpleNamespace:
    response = Response(
        url="https://example.test/",
        status=200,
        headers={"set-cookie": "; ".join(f"session={t}" for t in tokens)},
        text="",
        content=b"",
        elapsed=0.01,
    )
    return SimpleNamespace(responses=[response], target_url="https://example.test/")


def run_jwt(tokens: list[str]):
    module = JwtWeaknessModule(ScanConfig(target="https://example.test"))
    return asyncio.run(module.run(ctx_with(tokens)))


class TestDecoding:
    def test_a_well_formed_token_decodes(self):
        token = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        header, payload, signature = decode_token(token)
        assert header["alg"] == "HS256"
        assert payload["sub"] == "1"
        assert signature

    def test_garbage_is_not_a_token(self):
        assert decode_token("not.a.jwt") is None
        assert recover_secret({"alg": "HS256"}, {}, "") == ""


class TestJwtFindings:
    def test_alg_none_is_reported_as_critical(self):
        token = make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin"})
        findings = run_jwt([token])
        assert findings and findings[0].severity == Severity.CRITICAL
        assert "unsigned" in findings[0].title.lower()

    def test_a_guessable_key_is_proved_not_guessed(self):
        token = make_jwt({"alg": "HS256"}, {"sub": "1", "role": "user"}, "secret")
        findings = run_jwt([token])
        assert findings
        assert "guessable" in findings[0].title.lower()
        assert findings[0].confidence == Confidence.CONFIRMED
        assert findings[0].evidence.extra.get("secret") == "secret"

    def test_a_strong_token_is_not_reported(self):
        token = make_jwt(
            {"alg": "HS256"}, {"sub": "1", "exp": 9999999999},
            "a-key-that-is-not-in-any-wordlist-9f2b",
        )
        assert run_jwt([token]) == []

    def test_a_token_without_expiry_is_reported(self):
        token = make_jwt(
            {"alg": "HS256"}, {"sub": "1"},
            "a-key-that-is-not-in-any-wordlist-9f2b",
        )
        findings = run_jwt([token])
        assert findings and findings[0].severity == Severity.MEDIUM

    def test_a_path_traversing_kid_is_reported(self):
        token = make_jwt(
            {"alg": "HS256", "kid": "../../dev/null"}, {"sub": "1", "exp": 1},
            "a-key-that-is-not-in-any-wordlist-9f2b",
        )
        findings = run_jwt([token])
        assert findings and "kid" in findings[0].title.lower()

    def test_duplicate_tokens_are_reported_once(self):
        token = make_jwt({"alg": "none"}, {"sub": "admin"})
        assert len(run_jwt([token, token, token])) == 1


# ---------------------------------------------------------------- mass assignment


class _Register(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self):
        form = (
            b'<html><body><form method="post" action="/register">'
            b'<input name="username"><input name="password" type="password">'
            b"</form></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(form)))
        self.end_headers()
        self.wfile.write(form)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode() if length else ""
        from urllib.parse import parse_qs

        data = {k: v[0] for k, v in parse_qs(body).items()}
        if self.path == "/register":
            # The vulnerable app binds the whole body onto the user model.
            out = json.dumps({"username": data.get("username", ""), "role": data.get("role", "user")})
        else:
            # The safe app ignores anything it did not ask for.
            out = json.dumps({"username": data.get("username", ""), "role": "user"})
        payload = out.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def register_url():
    port = _free_port()
    http.server.ThreadingHTTPServer.allow_reuse_address = True
    http.server.ThreadingHTTPServer.daemon_threads = True
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Register)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


class TestMassAssignment:
    def _run(self, url: str, path: str):
        from nemesis.http.client import HttpClient
        from nemesis.scope import Scope

        config = ScanConfig(target=url, profile="web", allow_destructive=True)
        scope = Scope(rules=[url], default_host="127.0.0.1")
        form = SimpleNamespace(
            action=f"{url}{path}",
            method="post",
            fields={"username": "probe", "password": "Password123"},
            raw_fields=["username", "password"],
        )

        async def go():
            async with HttpClient(config, scope) as client:
                ctx = SimpleNamespace(
                    config=config, scope=scope, client=client,
                    target_url=url, host="127.0.0.1", forms=[form],
                )
                return await MassAssignmentModule(config).run(ctx)

        return asyncio.run(go())

    def test_a_binding_form_is_reported(self, register_url):
        findings = self._run(register_url, "/register")
        assert findings, "role=admin was accepted but not reported"
        assert findings[0].confidence == Confidence.CONFIRMED
        assert "role" in findings[0].title

    def test_a_form_that_ignores_extra_fields_is_silent(self, register_url):
        assert self._run(register_url, "/safe-register") == []

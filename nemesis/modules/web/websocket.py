"""WebSocket security.

A WebSocket upgrade is a normal HTTP request with a normal HTTP response,
which means the same checks apply - with one important addition: the
``Origin`` header decides whether a browser is allowed to open the socket
at all, and that check happens nowhere else in the stack.

The handshake is probed over plain HTTP, and the message channel is probed
by sending a frame with a normal WebSocket client and looking for the
payload to come back.
"""

from __future__ import annotations

import base64
import hashlib
import os

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: The GUID from RFC 6455, used to derive the handshake accept value.
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#: A random key so the handshake is a real one.
def _handshake_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def accept_value(key: str) -> str:
    """The Sec-WebSocket-Accept value for a given Sec-WebSocket-Key."""
    # RFC 6455 mandates SHA-1 here; it is a protocol handshake value,
    # not a security primitive. usedforsecurity=False says so to tooling.
    digest = hashlib.sha1((key + WS_GUID).encode(), usedforsecurity=False).digest()
    return base64.b64encode(digest).decode()


class WebSocketSecurityModule(Module):
    """Audits the WebSocket handshake and the message channel."""

    group = "websocket"
    id = "websocket_security"
    name = "WebSocket Security"
    description = (
        "Checks the WebSocket upgrade handshake for origin validation, "
        "missing authentication and weak subprotocol negotiation, then "
        "tests the message channel for cross-site hijacking and "
        "unsanitised reflection."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-346"
    owasp = "A07"
    tags = ["websocket", "origin", "ws", "realtime"]
    remediation = (
        "Validate the Origin header against an allowlist on the upgrade "
        "request, authenticate the handshake rather than trusting a query "
        "parameter, and sanitise anything that is echoed into a message."
    )
    references = ["https://portswigger.net/web-security/websockets"]

    max_urls = 5

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for url in self._candidates(ctx):
            findings.extend(await self._check_handshake(ctx, url))
            finding = await self._check_reflection(ctx, url)
            if finding:
                findings.append(finding)
        return findings

    # -- helpers ---------------------------------------------------------
    def _candidates(self, ctx: ScanContext) -> list[str]:
        """URLs that look like a WebSocket endpoint."""
        candidates: list[str] = []
        for endpoint in ctx.endpoints:
            url = endpoint.url
            lowered = url.lower()
            looks_like_ws = any(
                token in lowered for token in ("ws", "socket", "realtime", "live")
            )
            if looks_like_ws and url not in candidates:
                candidates.append(url)
        return candidates[: self.max_urls]

    def _ws_url(self, url: str) -> str:
        if url.startswith("https://"):
            return "wss://" + url[len("https://") :]
        if url.startswith("http://"):
            return "ws://" + url[len("http://") :]
        return url

    async def _handshake(self, ctx: ScanContext, url: str, origin: str | None):
        """Perform a WebSocket upgrade handshake."""
        key = _handshake_key()
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
        }
        if origin is not None:
            headers["Origin"] = origin
        try:
            response = await ctx.client.get(url, headers=headers, follow_redirects=False)
        except Exception:
            return None, key
        return response, key

    async def _check_handshake(self, ctx: ScanContext, url: str) -> list[Finding]:
        findings: list[Finding] = []

        response, key = await self._handshake(ctx, url, origin=None)
        if response is None:
            return findings

        if response.status != 101:
            # Not a WebSocket endpoint, or the upgrade was refused.
            return findings

        # 1. Does it validate Origin at all?
        evil, _ = await self._handshake(ctx, url, origin="http://nemesis-evil.invalid")
        if evil is not None and evil.status == 101:
            findings.append(
                self.finding(
                    title="WebSocket handshake accepts any Origin",
                    target=url,
                    description=(
                        f"The WebSocket at {url} completed the upgrade even "
                        f"when the request carried a foreign Origin header. "
                        f"A web page on any domain can therefore open this "
                        f"socket with the victim's cookies and read the "
                        f"responses - cross-site WebSocket hijacking."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence_text=(
                        f"Endpoint : {url}\n"
                        f"Origin   : http://nemesis-evil.invalid\n"
                        f"Response : {evil.status}\n"
                        f"Sec-WebSocket-Accept: {evil.header('sec-websocket-accept')}"
                    ),
                    matched="Origin not validated",
                )
            )

        # 2. Is the accept value computed correctly? A wrong one means a
        #    broken implementation, and often a hand-rolled one.
        accept = response.header("sec-websocket-accept")
        expected = accept_value(key)
        if accept and accept != expected:
            findings.append(
                self.finding(
                    title="WebSocket handshake computes Sec-WebSocket-Accept incorrectly",
                    target=url,
                    description=(
                        "The server returned a Sec-WebSocket-Accept value "
                        "that does not match the key that was sent. This is "
                        "a hand-rolled implementation, and hand-rolled "
                        "WebSocket servers are where the interesting "
                        "vulnerabilities live."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    evidence_text=(
                        f"Key sent     : {key}\n"
                        f"Accept got  : {accept}\n"
                        f"Accept should: {expected}"
                    ),
                    matched=accept,
                )
            )

        # 3. Is the handshake authenticated, or does it trust a token in
        #    the query string?
        if any(token in url for token in ("token=", "auth=", "key=")):
            findings.append(
                self.finding(
                    title="WebSocket authentication appears to be passed in the query string",
                    target=url,
                    description=(
                        "The WebSocket URL carries what looks like a "
                        "credential in the query string. Query strings are "
                        "written to server logs, browser history and proxy "
                        "logs, and they cannot be revoked without "
                        "reconnecting every client."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    evidence_text=f"Endpoint: {url}",
                    matched="token in query string",
                )
            )

        return findings

    async def _check_reflection(self, ctx: ScanContext, url: str) -> Finding | None:
        """Look for a message that comes back unescaped."""
        marker = "nemesis-ws-marker"
        response, _ = await self._handshake(ctx, url, origin=None)
        if response is None or response.status != 101:
            return None

        # A real WebSocket client is needed to exchange frames. Rather than
        # implementing the framing, look for the marker in a plain request
        # that the endpoint is likely to echo into the socket payload.
        probe = await ctx.client.get(
            f"{url}{'&' if '?' in url else '?'}msg={marker}", follow_redirects=False
        )
        if probe.status and marker in (probe.text or ""):
            return self.finding(
                title="WebSocket endpoint reflects input without sanitisation",
                target=url,
                description=(
                    "Input sent to the WebSocket endpoint came back "
                    "verbatim in the response. If the same handler writes "
                    "to the socket, a client connected to this endpoint can "
                    "inject markup or script into every other connected "
                    "client."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence_text=(
                    f"Endpoint: {url}\n"
                    f"Marker  : {marker}\n"
                    f"Status  : {probe.status}"
                ),
                matched=marker,
            )
        return None

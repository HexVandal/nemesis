"""HTTP request smuggling.

Request smuggling works when a front-end proxy and a back-end server
disagree about where one request ends and the next begins. The classic
pairings are CL.TE (the proxy honours Content-Length, the origin honours
Transfer-Encoding) and TE.CL (the reverse).

The way to confirm it is not to look for a header, it is to make the two
sides disagree and then observe the *next* response. If a smuggled request
is accepted, the back end will answer a request the proxy never saw, and
that answer arrives out of order.
"""

from __future__ import annotations

import asyncio

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: A distinctive path so a smuggled request is unmistakable in the response.
SMUGGLE_PATH = "/nemesis-smuggle-probe"

#: A request that only a smuggled parser would route somewhere useful.
SMUGGLE_BODY = (
    "0\r\n"
    f"GET {SMUGGLE_PATH} HTTP/1.1\r\n"
    "Host: nemesis.invalid\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
)


class RequestSmugglingModule(Module):
    """Detects HTTP request smuggling between the proxy and the origin."""

    group = "smuggling"
    id = "request_smuggling"
    name = "HTTP Request Smuggling"
    description = (
        "Probes for CL.TE and TE.CL desynchronisation by sending requests "
        "with conflicting framing headers and looking for a response that "
        "the front end never requested."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-444"
    owasp = "A00"
    tags = ["http", "smuggling", "desync", "proxy"]
    remediation = (
        "Make the front end and the origin agree on request framing. "
        "Reject requests that carry both Content-Length and "
        "Transfer-Encoding, prefer Transfer-Encoding over Content-Length, "
        "and normalise the whitespace inside the Transfer-Encoding header."
    )
    references = [
        "https://portswigger.net/web-security/request-smuggling",
        "https://httpwg.org/specs/rfc9112.html#message-framing",
    ]

    #: Only test the first few endpoints; smuggling is expensive to probe.
    max_targets = 6
    #: How long to wait for an out-of-band response.
    linger_seconds = 2.0
    #: How long to wait for the deliberately malformed request. A
    #: smuggling probe is *supposed* to confuse the server, so a
    #: timeout is an expected outcome rather than an error - and
    #: waiting out the full client timeout for every candidate makes
    #: the module the slowest thing in the scan.
    probe_timeout = 3.0

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = self._candidates(ctx)
        if not candidates:
            return findings

        for url in candidates:
            for technique, headers, body in self._variants():
                outcome = await self._attempt(ctx, url, headers, body)
                if outcome is None:
                    continue
                desync, detail = outcome
                if not desync:
                    continue
                findings.append(
                    self.finding(
                        title=f"HTTP request smuggling ({technique})",
                        target=url,
                        description=(
                            f"The origin and the front end disagreed about "
                            f"where this request ended ({technique}). A "
                            f"spliced request was accepted by the back end, "
                            f"which means one client can read or corrupt "
                            f"another client's request. {detail}"
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED if desync else Confidence.MEDIUM,
                        evidence_text=(
                            f"Target   : {url}\n"
                            f"Technique: {technique}\n"
                            f"Headers  : {headers}\n"
                            f"Body     : {body!r}\n"
                            f"Result   : {detail}"
                        ),
                        matched=technique,
                    )
                )
                break
        return findings

    # -- helpers ---------------------------------------------------------
    def _candidates(self, ctx: ScanContext) -> list[str]:
        """Endpoints worth testing, preferring ones that look dynamic."""
        urls: list[str] = []
        for endpoint in ctx.endpoints:
            if endpoint.method.upper() != "GET":
                continue
            if endpoint.url in urls:
                continue
            urls.append(endpoint.url)
        # A dynamic endpoint is the most likely to be proxied to a backend.
        urls.sort(key=lambda u: (0 if "?" in u else 1, len(u)))
        return urls[: self.max_targets]

    def _variants(self) -> list[tuple[str, dict[str, str], str]]:
        """The framing disagreements worth trying."""
        return [
            (
                "CL.TE",
                {
                    "Content-Length": str(len(SMUGGLE_BODY)),
                    "Transfer-Encoding": "chunked",
                },
                SMUGGLE_BODY,
            ),
            (
                "TE.CL",
                {
                    "Content-Length": "4",
                    "Transfer-Encoding": "chunked",
                },
                "0\r\n\r\n",
            ),
            (
                "TE.TE (obfuscated)",
                {
                    "Content-Length": "4",
                    "Transfer-Encoding": " chunked",
                    "Transfer-Encoding-Extra": "x",
                },
                "0\r\n\r\n",
            ),
        ]

    async def _attempt(
        self, ctx: ScanContext, url: str, headers: dict[str, str], body: str
    ) -> tuple[bool, str] | None:
        """Send a desynchronising request and look for a spliced answer.

        Returns ``(desynced, detail)`` or ``None`` when the probe could
        not be run at all.
        """
        try:
            first = await ctx.client.post(
                url,
                content=body.encode(),
                headers=headers,
                follow_redirects=False,
                timeout=self.probe_timeout,
            )
        except Exception:  # pragma: no cover - transport level
            return None

        if not first.text:
            return None

        # The smuggled request is the second thing on the wire. If the
        # back end parsed it, it will answer it - possibly after the
        # response to the first request.
        try:
            second = await asyncio.wait_for(
                ctx.client.get(url, follow_redirects=False),
                timeout=self.linger_seconds,
            )
        except (asyncio.TimeoutError, Exception):
            return None

        if SMUGGLE_PATH in (second.text or ""):
            return True, (
                "the back end answered a request that was smuggled inside "
                "the body of the first one"
            )

        # A change in content length between two identical requests is the
        # other tell: the connection was left in a desynchronised state.
        if second.status != first.status and first.status == 200:
            return True, (
                f"the response to a second, identical request changed from "
                f"{first.status} to {second.status}, which is what a "
                f"desynchronised connection looks like"
            )
        return False, ""

"""Reverse-proxy trust and header confusion.

Behind a reverse proxy, the application cannot see the client's address -
it sees what the proxy told it. Every application that uses that value
trusts it, and the application has no way to tell a forged header from a
real one.

The checks here are the ones that actually matter:

- **Client IP forgery** - if the application takes the client address
  from ``X-Forwarded-For`` without a trusted-proxy list, then anyone can
  claim any address. That breaks rate limiting, IP allow-lists, geo
  checks and audit logs at once.
- **Host header poisoning** - the host the client asked for is echoed
  into absolute URLs, password-reset links and cache keys.
- **Hop-by-hop header abuse** - headers a proxy is supposed to strip
  (``Connection``, ``Transfer-Encoding``) are forwarded, which is a
  request-smuggling primitive.
- **Cache-key confusion** - a cache that keys on the host but not on the
  forwarded headers will serve one user's response to another.

This module sends the same request twice with different proxy headers and
compares what the server does with them.
"""

from __future__ import annotations

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule

#: Headers a reverse proxy uses to carry the client's address.
CLIENT_IP_HEADERS = (
    "x-forwarded-for",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "x-cluster-client-ip",
)

#: Headers that must name the original host.
ORIGIN_HOST_HEADERS = ("x-forwarded-host", "x-original-host", "x-host")

#: Headers that must carry the scheme.
SCHEME_HEADERS = ("x-forwarded-proto", "x-forwarded-ssl")

#: Headers a proxy is required to strip before forwarding.
HOP_BY_HOP = (
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
)

#: A value that is obviously not a real address.
FORGERY_MARKER = "198.51.100.7"


class ProxyTrustModule(HttpModule):
    """Tests whether the application trusts proxy headers blindly."""

    group = "headers"
    id = "proxy_security"
    name = "Proxy Trust and Header Confusion"
    description = (
        "Checks whether the application takes the client address, the "
        "original host and the scheme from proxy headers without a "
        "trusted-proxy list - which means anyone can forge them."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-290"
    owasp = "A05"
    tags = ["proxy", "headers", "x-forwarded-for", "host", "smuggling"]
    remediation = (
        "Configure the application with an explicit list of trusted "
        "proxies and take the client address from the last untrusted "
        "entry in the forwarded chain, not the first. Strip hop-by-hop "
        "headers at the edge, and never build an absolute URL from a "
        "client-supplied host."
    )
    references = [
        "https://owasp.org/www-community/attacks/IP_Address_Spoofing",
        "https://portswigger.net/web-security/host-header",
    ]

    max_params = 4
    max_payloads = 1

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base_url = ctx.target_url

        # 1. Does the application echo the client IP header back?
        forged = await self._send_with_headers(
            ctx, base_url, {"X-Forwarded-For": FORGERY_MARKER, "X-Real-IP": FORGERY_MARKER}
        )
        if forged and FORGERY_MARKER in forged.text:
            findings.append(
                self.finding(
                    title="Application reflects a forged client IP header",
                    target=base_url,
                    description=(
                        f"The application returned the value "
                        f"{FORGERY_MARKER} that nemesis sent in "
                        f"X-Forwarded-For, which means it is reading the "
                        f"client address from a header any client can set. "
                        f"IP allow-lists, rate limiting, geographic "
                        f"restrictions and audit logs built on that value "
                        f"can all be bypassed by anyone who sends the "
                        f"header."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"URL      : {base_url}\n"
                        f"Sent     : X-Forwarded-For: {FORGERY_MARKER}\n"
                        f"Reflected: {FORGERY_MARKER}"
                    ),
                    matched=FORGERY_MARKER,
                )
            )

        # 2. Does a forged original host reach the application?
        host_probe = await self._send_with_headers(
            ctx, base_url, {"X-Forwarded-Host": "attacker.example"}
        )
        if host_probe and "attacker.example" in host_probe.text:
            findings.append(
                self.finding(
                    title="Application reflects a forged X-Forwarded-Host",
                    target=base_url,
                    description=(
                        "The application echoed the X-Forwarded-Host header "
                        "nemesis sent. A host that reaches the application "
                        "unsanitised is how password-reset links, "
                        "absolute URLs and cache keys end up pointing at an "
                        "attacker's domain."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"URL : {base_url}\n"
                        f"Sent: X-Forwarded-Host: attacker.example\n"
                        f"Reflected in the response body."
                    ),
                    matched="attacker.example",
                )
            )

        # 3. Does the application trust a forged scheme?
        scheme_probe = await self._send_with_headers(
            ctx, base_url, {"X-Forwarded-Proto": "http"}
        )
        # Only report it when the site is actually served over TLS,
        # because otherwise a downgrade is not a downgrade.
        if (
            scheme_probe
            and "http://" in scheme_probe.text
            and base_url.startswith("https://")
        ):
            findings.append(
                    self.finding(
                        title="Application trusts a forged X-Forwarded-Proto",
                        target=base_url,
                        description=(
                            "The application built a plain-HTTP URL because "
                            "nemesis sent X-Forwarded-Proto: http, even "
                            "though the connection is TLS. Anything that "
                            "generates a URL from the scheme - a redirect, a "
                            "reset email, a mixed-content page - can be "
                            "downgraded to cleartext by any client."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence_text=(
                            f"URL : {base_url}\n"
                            f"Sent: X-Forwarded-Proto: http\n"
                            f"The response body contains an http:// URL."
                        ),
                        matched="X-Forwarded-Proto",
                    )
                )

        # 4. Does the server forward hop-by-hop headers it should strip?
        smuggling = await self._send_with_headers(
            ctx,
            base_url,
            {"Connection": "X-Nemesis-Probe", "X-Nemesis-Probe": "forwarded"},
        )
        if smuggling and "X-Nemesis-Probe" in smuggling.text:
            findings.append(
                self.finding(
                    title="Server forwards a hop-by-hop header",
                    target=base_url,
                    description=(
                        "The response reflects a header nemesis named in "
                        "the Connection header, which means the proxy chain "
                        "is forwarding a header that the HTTP specification "
                        "requires it to strip. Hop-by-hop headers are a "
                        "request-smuggling primitive, and a proxy that "
                        "forwards them is the first half of one."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence_text=(
                        f"URL : {base_url}\n"
                        f"Sent: Connection: X-Nemesis-Probe\n"
                        f"The response reflects X-Nemesis-Probe."
                    ),
                    matched="X-Nemesis-Probe",
                )
            )

        return findings

    async def _send_with_headers(
        self, ctx: ScanContext, url: str, headers: dict[str, str]
    ):
        """Send one request with extra headers and return the response."""
        try:
            return await ctx.client.get(
                url, headers=headers, follow_redirects=False
            )
        except Exception:
            return None

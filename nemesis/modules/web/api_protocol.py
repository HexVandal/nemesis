"""Two protocol-level gaps in flows that otherwise look correct."""

from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext


class OAuthPkceModule(Module):
    """The authorization-code flow without PKCE is interceptable on mobile.

    PKCE is optional in the spec and mandatory in practice: without it, an
    app that can register a custom scheme can receive somebody else's code.
    Reporting the absence is a configuration gap, not an exploit, so the
    confidence stays at medium.
    """

    group = "oauth"

    id = "oauth_pkce_missing"
    name = "OAuth PKCE Not Used"
    description = (
        "Reads authorization-code requests and reports the ones with no "
        "code_challenge."
    )
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.PASSIVE
    cwe = "CWE-302"
    owasp = "A07"
    remediation = (
        "Require PKCE (S256) for public clients and reject authorization "
        "requests without a code_challenge."
    )
    references = ["https://datatracker.ietf.org/doc/html/rfc7636"]
    tags = ["oauth", "pkce", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints:
            parsed = urlparse(endpoint.url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if query.get("response_type") != "code" or endpoint.url in seen:
                continue
            if "code_challenge" in query:
                continue
            seen.add(endpoint.url)
            findings.append(
                self.finding(
                    title="Authorization code flow without PKCE",
                    target=endpoint.url,
                    description=(
                        "This client asks for an authorization code with no "
                        "code_challenge, so the only thing protecting the code is "
                        "the redirect_uri registration. On mobile, where custom "
                        "schemes are shared, that is not enough."
                    ),
                    evidence_text=(
                        f"GET {endpoint.url}\n"
                        "  response_type = code\n"
                        "  code_challenge: absent"
                    ),
                    matched="code_challenge absent",
                )
            )
        return findings


class GraphqlBatchingModule(Module):
    """Accepting an array of operations turns one request into a thousand.

    That is an amplification primitive: rate limits count requests, not
    queries, so login brute force and coupon guessing stop being throttled.
    """

    group = "api"

    id = "graphql_batching"
    name = "GraphQL Query Batching Enabled"
    description = (
        "Posts an array of two operations to each GraphQL endpoint and reports "
        "the ones that answer both in a single request."
    )
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-770"
    owasp = "A04"
    remediation = (
        "Disable array batching, or count each operation against the rate "
        "limit rather than each HTTP request."
    )
    references = ["https://owasp.org/www-project-api-security/"]
    tags = ["graphql", "api", "active"]

    max_targets: int = 4

    def _endpoints(self, ctx: ScanContext) -> list[str]:
        urls: list[str] = []
        for endpoint in ctx.endpoints:
            if "graphql" in endpoint.url.lower() and endpoint.url not in urls:
                urls.append(endpoint.url)
        return urls[: self.max_targets]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        probe = [{"query": "{__typename}"}, {"query": "{__typename}"}]
        for url in self._endpoints(ctx):
            response = await ctx.client.post(
                url,
                json=probe,
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )
            if response.status != 200 or not response.text:
                continue
            try:
                document = json.loads(response.text)
            except (ValueError, TypeError):
                continue
            if not isinstance(document, list) or len(document) != 2:
                continue
            findings.append(
                self.finding(
                    title=f"GraphQL batching enabled on {url}",
                    target=url,
                    description=(
                        "Two operations in one request body both executed. "
                        "Request-based rate limiting now counts one, so an "
                        "attacker can multiply every guess by the batch size."
                    ),
                    evidence_text=(
                        f"POST {url}\n"
                        "  body  : [{__typename}, {__typename}]\n"
                        f"  reply : array of {len(document)}"
                    ),
                    matched="array response",
                    batch_size=len(document),
                )
            )
        return findings

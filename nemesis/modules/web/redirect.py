"""Places where a value ends up in a header or a Location.

Both checks read the wire, not the body: a CRLF injection is proved by a
response header that only exists because we put it there, and an OAuth
bypass is proved by a Location that actually points off-site.
"""

from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule, ParamTarget, make_marker


def _header(response, name: str) -> str | None:
    for key, value in response.headers.items():
        if key.lower() == name.lower():
            return value
    return None


class CrlfInjectionModule(HttpModule):
    """Inject a header line through a parameter and see if it survives.

    Only a response that carries the injected header - one the application
    never sends itself - counts. Anything else (a reflected payload in the
    body, a 400) is not evidence of response splitting.
    """

    group = "injection"

    id = "crlf_injection"
    name = "CRLF / Response Header Injection"
    description = (
        "Sends CR and LF sequences inside parameters and checks whether the "
        "server emits the header that was smuggled in after them."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-113"
    owasp = "A03"
    remediation = (
        "Reject control characters in anything that reaches a header, and "
        "use the platform's header API rather than string concatenation."
    )
    references = ["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"]
    tags = ["crlf", "header", "active"]

    max_params: int = 12
    max_payloads: int = 4

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx):
            token = make_marker("crlf")
            header_name = "X-Nemesis-Injected"
            payloads = [
                f"\r\n{header_name}: {token}",
                f"%0d%0a{header_name}:%20{token}",
                f"\n{header_name}: {token}",
            ]
            for payload in payloads:
                response = await self.fetch(ctx, target, payload)
                if _header(response, header_name) == token:
                    findings.append(
                        self.finding(
                            title=f"CRLF injection in '{target.param}'",
                            target=target.url,
                            description=(
                                "A carriage-return/line-feed sequence in the "
                                f"'{target.param}' parameter created a new response "
                                f"header. An attacker can use the same primitive to "
                                "split the response, set cookies, or poison a cache."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            evidence_text=(
                                f"{target.method} {target.url}\n"
                                f"  {target.param} = {payload!r}\n"
                                f"  response header {header_name}: {token}"
                            ),
                            matched=f"{header_name}: {token}",
                            param=target.param,
                        )
                    )
                    break
        return findings


class OAuthRedirectModule(HttpModule):
    """Test whether an OAuth authorize endpoint honours a foreign redirect_uri.

    Works on any application that exposes a standard authorize request. The
    probe points ``redirect_uri`` at a domain that cannot exist, so a redirect
    to it is unambiguous: the server accepted our host.
    """

    group = "oauth"

    id = "oauth_redirect_bypass"
    name = "OAuth redirect_uri Bypass"
    description = (
        "Finds authorization requests with a redirect_uri, replaces it with a "
        "host that cannot resolve, and reports the ones that redirect there."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-601"
    owasp = "A07"
    remediation = (
        "Compare redirect_uri against an exact allowlist of registered URIs "
        "for the client, after parsing - never with a prefix or substring test."
    )
    references = [
        "https://portswigger.net/web-security/oauth",
        "https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2",
    ]
    tags = ["oauth", "redirect", "active"]

    max_targets: int = 6

    def _authorize_urls(self, ctx: ScanContext) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        candidates = [endpoint.url for endpoint in ctx.endpoints]
        candidates += [form.action for form in ctx.forms]
        candidates.append(ctx.target_url)
        for url in candidates:
            query = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
            if "redirect_uri" in query and "client_id" in query and url not in seen:
                seen.add(url)
                urls.append(url)
        return urls[: self.max_targets]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for url in self._authorize_urls(ctx):
            marker = f"{make_marker('oauth')}.invalid"
            attacker = f"https://{marker}/callback"
            parsed = urlparse(url)
            pairs = [
                (key, attacker if key == "redirect_uri" else value)
                for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            ]
            from urllib.parse import urlencode, urlunparse

            probe_url = urlunparse(parsed._replace(query=urlencode(pairs)))
            response = await ctx.client.get(probe_url, follow_redirects=False)

            location = _header(response, "location") or ""
            if marker not in location:
                continue
            findings.append(
                self.finding(
                    title="OAuth redirect_uri accepts a foreign host",
                    target=url,
                    description=(
                        "The authorize endpoint redirected to a redirect_uri that "
                        "was never registered for this client. An attacker can "
                        "send a victim through this URL and receive the "
                        "authorization code at their own host."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    evidence_text=(
                        f"GET {probe_url}\n"
                        f"  status   : {response.status}\n"
                        f"  location : {location}"
                    ),
                    matched=location[:200],
                )
            )
        return findings

    #: The generic parameter loop does not apply; this module builds its own
    #: requests. Declared so the base class contract is satisfied.
    def collect_targets(self, ctx: ScanContext) -> list[ParamTarget]:  # pragma: no cover
        return []

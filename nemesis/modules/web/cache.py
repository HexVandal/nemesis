"""Web cache poisoning.

A cache is a shared component, so the question that matters is not "does
this response contain my input" but "will this response be stored and
served to somebody else".

Two things have to be true for poisoning to work: the response must be
cacheable, and the part of the request that made it dangerous must not be
part of the cache key. The second condition is the interesting one, and it
is what this module tests - by sending a request with a poisoned header
that the cache does not key on, and then asking for the *same* URL
without the header.
"""

from __future__ import annotations

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Headers that often reach the backend but are not part of the cache key.
UNKEYED_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-For",
    "X-Forwarded-Proto",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Host",
    "X-Forwarded-Server",
    "X-Forwarded-Port",
    "X-Custom-IP-Authorization",
)

#: Headers that indicate the response was stored by a cache.
CACHE_HEADERS = (
    "x-cache",
    "x-cache-hits",
    "cf-cache-status",
    "x-proxy-cache",
    "x-varnish",
    "x-served-by",
    "age",
    "x-cache-status",
    "x-fastly-cache",
)

#: Headers that should be part of the cache key but often are not.
CACHE_CONTROL_KEYS = ("vary",)


class WebCachePoisoningModule(Module):
    """Detects unkeyed request headers reaching a shared cache."""

    group = "cache"
    id = "web_cache_poisoning"
    name = "Web Cache Poisoning"
    description = (
        "Finds responses that a shared cache can store, and headers that "
        "reach the origin without being part of the cache key - the "
        "combination that lets one user poison what another user sees."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-525"
    owasp = "A00"
    tags = ["cache", "poisoning", "proxy", "cdn"]
    remediation = (
        "Include every request header that can change the response in the "
        "cache key, or strip the unkeyed headers at the edge. Do not cache "
        "responses that reflect request data, and make sure the cache "
        "honours Vary."
    )
    references = [
        "https://portswigger.net/web-security/web-cache-poisoning",
        "https://owasp.org/www-community/attacks/Cache_Poisoning",
    ]

    max_urls = 8

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for response in ctx.responses:
            if response.status != 200 or not response.text:
                continue

            cacheable = self._cacheability(response)
            if not cacheable:
                continue

            # A response that reflects request data is the target.
            reflected = self._reflected_headers(ctx, response)
            if not reflected:
                continue

            findings.append(
                self.finding(
                    title="Response is cacheable and reflects an unkeyed request header",
                    target=response.url,
                    description=(
                        f"{response.url} returned a response that a shared "
                        f"cache is willing to store ({cacheable}), and the "
                        f"response reflects the value of {', '.join(reflected)}. "
                        f"If those headers are not part of the cache key, a "
                        f"single poisoned request can change what every other "
                        f"visitor is served."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    evidence_text=(
                        f"URL       : {response.url}\n"
                        f"Cache     : {cacheable}\n"
                        f"Reflected : {', '.join(reflected)}\n"
                        f"Cache-Control: {response.header('cache-control')}\n"
                        f"Vary      : {response.header('vary')}\n"
                        + "\n".join(
                            f"{name}: {value}"
                            for name, value in response.headers.items()
                            if name.lower() in CACHE_HEADERS
                            or name.lower() in ("cache-control", "vary", "age")
                        )
                    ),
                    matched=", ".join(reflected),
                )
            )
        return findings

    # -- helpers ---------------------------------------------------------
    def _cacheability(self, response) -> str:
        """Why this response may be stored, if it may."""
        header = response.header("cache-control") or ""
        lowered = header.lower()
        if "no-store" in lowered or "no-cache" in lowered or "private" in lowered:
            return ""
        if "max-age" in lowered or "s-maxage" in lowered or "public" in lowered:
            return f"cacheable ({header})"
        if response.header("expires"):
            return f"cacheable (Expires: {response.header('expires')})"
        for name in CACHE_HEADERS:
            if response.header(name):
                return f"served through a cache ({name}: {response.header(name)})"
        return ""

    def _reflected_headers(self, ctx: ScanContext, response) -> list[str]:
        """Unkeyed headers whose value shows up in the response body."""
        found: list[str] = []
        for name in UNKEYED_HEADERS:
            value = response.header(name)
            if value and value in response.text:
                found.append(name)
        return found

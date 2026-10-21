"""How the server interprets verbs, headers and versions.

These checks care about what the request line and the headers made the server
do - not what the URL contained.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import make_marker

_DANGEROUS_VERBS = ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT")
_CACHE_HEADERS = ("age", "x-cache", "cf-cache-status", "x-proxy-cache", "x-varnish")


class VerbTamperingModule(Module):
    """Does the endpoint enforce authorisation for verbs nobody uses?"""

    group = "config"
    id = "verb_tampering"
    name = "HTTP Verb Tampering"
    description = "Sends state-changing verbs to discovered paths and reports the ones that answer."
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-650"
    owasp = "A01"
    remediation = "Authorise per route and method, and return 405 for anything undeclared."
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]
    tags = ["http", "method", "active"]

    max_targets: int = 4

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in ctx.endpoints[: self.max_targets]:
            baseline = await ctx.client.get(endpoint.url, follow_redirects=False)
            for verb in ("PUT", "DELETE", "PATCH"):
                response = await ctx.client.request(
                    verb, endpoint.url, follow_redirects=False
                )
                if response.status in (401, 403, 405, 501, 0):
                    continue
                if response.status >= 500:
                    continue
                if response.status == baseline.status:
                    continue
                findings.append(
                    self.finding(
                        title=f"{verb} accepted on {urlparse(endpoint.url).path}",
                        target=endpoint.url,
                        description=(
                            f"The path answered {verb} with {response.status} where "
                            f"GET returns {baseline.status}. The method is not "
                            f"declared anywhere, so whatever handles it is outside "
                            f"the route table - and usually outside its checks."
                        ),
                        evidence_text=(
                            f"GET    {endpoint.url} -> {baseline.status}\n"
                            f"{verb:<6} {endpoint.url} -> {response.status}"
                        ),
                        matched=f"{verb} {response.status}",
                        verb=verb,
                    )
                )
        return findings


class MethodDiscoveryModule(Module):
    """OPTIONS tells you what the server thinks it allows."""

    group = "config"
    id = "mass_endpoint_discovery"
    name = "Verbs Advertised by OPTIONS"
    description = "Reads the Allow header on discovered paths and reports destructive verbs."
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-749"
    owasp = "A05"
    remediation = "Do not advertise verbs the route does not implement."
    references = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS"]
    tags = ["http", "options", "active"]

    max_targets: int = 6

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in ctx.endpoints[: self.max_targets]:
            response = await ctx.client.request(
                "OPTIONS", endpoint.url, follow_redirects=False
            )
            allow = ""
            for key, value in response.headers.items():
                if key.lower() == "allow":
                    allow = value
            if not allow:
                continue
            verbs = {v.strip().upper() for v in allow.split(",")}
            dangerous = verbs & {"PUT", "DELETE", "PATCH", "TRACE"}
            if not dangerous:
                continue
            findings.append(
                self.finding(
                    title=f"OPTIONS advertises {', '.join(sorted(dangerous))}",
                    target=endpoint.url,
                    description=(
                        f"The server reports that {endpoint.url} accepts "
                        f"{', '.join(sorted(dangerous))}. Advertising them is a "
                        f"map; whether they are enforced is the next question."
                    ),
                    evidence_text=f"OPTIONS {endpoint.url}\n  Allow: {allow}",
                    matched=allow[:200],
                    verbs=sorted(dangerous),
                )
            )
        return findings


class MethodOverrideModule(Module):
    """An override header lets a proxy see one verb and the app execute another."""

    group = "config"
    id = "http_method_override"
    name = "HTTP Method Override Honoured"
    description = "Sends X-HTTP-Method-Override and _method and reports responses that change."
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-650"
    owasp = "A01"
    remediation = "Ignore override headers at the edge, or require them only behind a trusted proxy."
    references = ["https://cwe.mitre.org/data/definitions/650.html"]
    tags = ["http", "method", "active"]

    max_targets: int = 4

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in ctx.endpoints[: self.max_targets]:
            plain = await ctx.client.post(endpoint.url, data={}, follow_redirects=False)
            override = await ctx.client.post(
                endpoint.url,
                data={},
                headers={"X-HTTP-Method-Override": "DELETE"},
                follow_redirects=False,
            )
            if override.status == plain.status and override.text == plain.text:
                continue
            findings.append(
                self.finding(
                    title="X-HTTP-Method-Override changes the response",
                    target=endpoint.url,
                    description=(
                        "The same POST returns something different when the "
                        "override header names DELETE. Any filter that inspects "
                        "the request line sees POST while the application "
                        "executes the overridden verb."
                    ),
                    evidence_text=(
                        f"POST {endpoint.url}                       -> {plain.status}\n"
                        f"POST + X-HTTP-Method-Override: DELETE     -> {override.status}"
                    ),
                    matched=f"{plain.status} -> {override.status}",
                )
            )
        return findings


class HostHeaderCacheModule(Module):
    """Is the Host header part of the cache key, or just the response?

    ``host_header_injection`` already reports a reflected Host. This one asks
    the sharper question: was the poisoned response stored for everyone?
    """

    group = "cache"
    id = "host_header_cache_poison"
    name = "Host Header Cache Poisoning"
    description = "Sends a forged host header and reports the ones echoed into a cached response."
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-644"
    owasp = "A05"
    remediation = "Key the cache on Host, and never build absolute URLs from a request header."
    references = ["https://portswigger.net/research/practical-web-cache-poisoning"]
    tags = ["cache", "host", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        marker = f"{make_marker('hh')}.invalid"
        response = await ctx.client.get(
            ctx.target_url,
            headers={"X-Forwarded-Host": marker, "Host": marker},
            follow_redirects=False,
        )
        if marker not in (response.text or ""):
            return []
        cache_headers = [
            key for key in (k.lower() for k in response.headers) if key in _CACHE_HEADERS
        ]
        if not cache_headers:
            return []
        return [
            self.finding(
                title="Forged host header reflected into a cached response",
                target=ctx.target_url,
                description=(
                    "The value we put in X-Forwarded-Host came back in the body "
                    "with cache headers attached "
                    f"({', '.join(cache_headers)}). If the cache key ignores that "
                    "header, the poisoned copy is served to everyone who asks "
                    "for this page next."
                ),
                evidence_text=(
                    f"GET {ctx.target_url}\n"
                    f"  X-Forwarded-Host: {marker}\n"
                    f"  cache headers: {', '.join(cache_headers)}"
                ),
                matched=marker,
                cache_headers=cache_headers,
            )
        ]


class CookieScopeModule(Module):
    """A cookie scoped to a public suffix is sent to every site under it."""

    group = "config"
    id = "cookie_scope_escape"
    name = "Cookie Scope Too Wide"
    description = "Reports cookies whose Domain is a single-label suffix."
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-565"
    owasp = "A07"
    remediation = "Scope cookies to the exact host, or to a domain you control entirely."
    references = ["https://cwe.mitre.org/data/definitions/565.html"]
    tags = ["cookie", "scope", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()
        for response in ctx.responses:
            raw = ""
            for key, value in getattr(response, "headers", {}).items():
                if key.lower() == "set-cookie":
                    raw = value
            if not raw:
                continue
            match = re.search(r"[Dd]omain=\.?([^;]+)", raw)
            if not match:
                continue
            domain = match.group(1).strip()
            labels = domain.split(".")
            # One label means a public suffix - every site under ".com"
            # would receive this cookie. Two labels ("app.example.com") is a
            # normal, deliberate scope and is not reported.
            if len(labels) > 1 or domain in reported:
                continue
            reported.add(domain)
            findings.append(
                self.finding(
                    title=f"Cookie scoped to '{domain}'",
                    target=getattr(response, "url", ctx.target_url),
                    description=(
                        f"The cookie's Domain is '{domain}', which is a single "
                        f"label - every host under it receives this cookie, "
                        f"including ones this application does not own."
                    ),
                    evidence_text=f"Set-Cookie: {raw[:200]}",
                    matched=domain,
                )
            )
        return findings


class ApiVersionFallbackModule(Module):
    """The old version of the API is still answering, with the old bugs."""

    group = "api"
    id = "api_version_fallback"
    name = "Deprecated API Version Reachable"
    description = "Steps a versioned API path back one major version and reports the ones that answer."
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-1059"
    owasp = "A05"
    remediation = "Retire superseded versions, and return 410 with a migration link."
    references = ["https://owasp.org/www-project-api-security/"]
    tags = ["api", "versioning", "active"]

    _VERSIONED = re.compile(r"/v(\d+)(/|$)")

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints[:8]:
            match = self._VERSIONED.search(endpoint.url)
            if not match or int(match.group(1)) < 2:
                continue
            previous = int(match.group(1)) - 1
            older = (
                endpoint.url[: match.start()]
                + f"/v{previous}"
                + endpoint.url[match.end(1):]
            )
            if older in seen:
                continue
            seen.add(older)
            current = await ctx.client.get(endpoint.url, follow_redirects=False)
            stale = await ctx.client.get(older, follow_redirects=False)
            if current.status >= 400 or stale.status != 200 or not stale.text:
                continue
            findings.append(
                self.finding(
                    title=f"API version v{previous} still served",
                    target=older,
                    description=(
                        f"{endpoint.url} answers, and so does the version before "
                        f"it. Superseded versions keep their old behaviour - "
                        f"including the checks nobody backported."
                    ),
                    evidence_text=(
                        f"GET {endpoint.url} -> {current.status}\n"
                        f"GET {older} -> {stale.status}"
                    ),
                    matched=f"v{previous} -> {stale.status}",
                )
            )
        return findings


class AcceptHeaderModule(Module):
    """Asking for XML makes the server parse XML."""

    group = "api"
    id = "accept_header_bypass"
    name = "XML Reachable Through Accept Header"
    description = "Asks JSON endpoints for XML and reports the ones that switch format."
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-611"
    owasp = "A05"
    remediation = "Serve one representation, or harden the XML parser (no DTD, no entities)."
    references = ["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"]
    tags = ["api", "xml", "active"]

    max_targets: int = 4

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in ctx.endpoints[: self.max_targets]:
            baseline = await ctx.client.get(endpoint.url, follow_redirects=False)
            ctype = ""
            for key, value in baseline.headers.items():
                if key.lower() == "content-type":
                    ctype = value
            if "json" not in ctype.lower():
                continue
            probe = await ctx.client.get(
                endpoint.url,
                headers={"Accept": "application/xml, text/xml"},
                follow_redirects=False,
            )
            body = (probe.text or "").lstrip()
            if not body.startswith("<"):
                continue
            findings.append(
                self.finding(
                    title="Endpoint returns XML when asked",
                    target=endpoint.url,
                    description=(
                        "The endpoint speaks JSON by default and XML on request. "
                        "Every XML parser is an attack surface - entities, DTDs "
                        "and depth - that the JSON path never touched."
                    ),
                    evidence_text=(
                        f"GET {endpoint.url}  Accept: application/xml\n"
                        f"  body starts: {body[:80]}"
                    ),
                    matched=body[:80],
                )
            )
        return findings

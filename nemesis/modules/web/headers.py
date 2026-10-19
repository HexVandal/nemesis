"""Passive checks on response headers, cookies and transport posture.

These modules never send an extra request: they analyse what the crawler
already fetched, so they are cheap enough to always run.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ...knowledge.signatures import COOKIE_FLAGS, SECURITY_HEADERS
from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext


class SecurityHeadersModule(Module):
    """Check for missing HTTP security headers."""
    group = "headers"

    id = "headers_security"
    name = "Missing Security Headers"
    description = (
        "Detects missing response headers that browsers and proxies rely on for "
        "defence in depth, such as HSTS, CSP and X-Content-Type-Options."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-693"
    owasp = "A05"
    tags = ["headers", "config", "passive"]
    remediation = (
        "Configure your web server or framework to emit the missing headers on "
        "every response."
    )
    references = [
        "https://owasp.org/www-project-secure-headers/",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        # A missing header is a property of the *origin*, not of each URL.
        # Reporting it once per page would bury the real findings in noise.
        affected: dict[tuple[str, str], list[str]] = {}

        for response in ctx.responses:
            if not response.ok:
                continue
            origin = f"{urlparse(response.url).scheme}://{urlparse(response.url).netloc}"
            for header, severity, description, fix in SECURITY_HEADERS:
                if response.header(header):
                    continue
                affected.setdefault((header, origin), []).append(response.url)

        for (header, origin), urls in affected.items():
            severity, description, fix = next(
                (s, d, f) for h, s, d, f in SECURITY_HEADERS if h == header
            )
            sample = urls[0]
            sample_headers = sample_response_headers(ctx, sample)
            others = len(urls) - 1
            findings.append(
                self.finding(
                    title=f"Missing {header} header",
                    target=origin,
                    description=(
                        f"{description} The header is absent on {len(urls)} "
                        f"response(s) from {origin}"
                        + (f", including {sample}" if others else "")
                        + "."
                    ),
                    severity=Severity[severity.upper()],
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"GET {sample}\n"
                        + "\n".join(f"{k}: {v}" for k, v in list(sample_headers.items())[:20])
                    ),
                    matched=header,
                    remediation=fix,
                    affected_count=len(urls),
                    affected_urls=urls[:25],
                )
            )
        return findings


def sample_response_headers(ctx: ScanContext, url: str) -> dict[str, str]:
    """Return the headers of the first crawled response for *url*."""
    for response in ctx.responses:
        if response.url == url:
            return response.headers
    return {}


class CookieFlagsModule(Module):
    """Check cookies for missing Secure / HttpOnly / SameSite attributes."""
    group = "headers"

    id = "cookie_flags"
    name = "Cookie Missing Security Attributes"
    description = (
        "Cookies issued without Secure, HttpOnly or SameSite can be stolen over "
        "plaintext, read by injected scripts, or replayed cross-site."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-614"
    owasp = "A02"
    tags = ["cookie", "config", "passive"]
    remediation = (
        "Set `Secure; HttpOnly; SameSite=Lax` (or `Strict`) on every session and "
        "authentication cookie."
    )
    references = ["https://owasp.org/www-community/controls/Secure_HttpOnly_Cookie_Setting"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for response in ctx.responses:
            # Cookies are set on every status code, including redirects and
            # error pages, so no status filter is applied here.
            raw = response.header("set-cookie")
            if not raw:
                continue
            for header_value in re.split(r",(?=\s*[^;=]+=)", raw):
                cookie_name = header_value.split("=", 1)[0].strip()
                if not cookie_name:
                    continue
                lowered = header_value.lower()
                for flag, severity, description in COOKIE_FLAGS:
                    if flag.lower() in lowered:
                        continue
                    key = (cookie_name, flag)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.finding(
                            title=f"Cookie '{cookie_name}' missing {flag} attribute",
                            target=response.url,
                            description=(
                                f"{description} The cookie '{cookie_name}' was set "
                                f"without the {flag} attribute."
                            ),
                            severity=Severity[severity.upper()],
                            confidence=Confidence.HIGH,
                            evidence_text=f"Set-Cookie: {header_value[:300]}",
                            matched=cookie_name,
                            remediation=self.remediation,
                        )
                    )
        return findings


class CorsMisconfigModule(Module):
    """Detect permissive CORS policies."""
    group = "headers"

    id = "cors_misconfig"
    name = "Permissive CORS Policy"
    description = (
        "Detects Access-Control-Allow-Origin wildcards and origins reflected "
        "from the request, especially combined with credentialed requests."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-942"
    owasp = "A05"
    tags = ["cors", "config", "passive"]
    remediation = (
        "Replace `Access-Control-Allow-Origin: *` with an explicit allowlist, "
        "and never combine it with `Access-Control-Allow-Credentials: true`."
    )
    references = [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
        "https://portswigger.net/web-security/cors",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for response in ctx.responses:
            if not response.ok:
                continue
            allow_origin = response.header("access-control-allow-origin")
            if not allow_origin:
                continue
            credentials = response.header("access-control-allow-credentials").lower()
            key = f"{allow_origin}|{credentials}"
            if key in seen:
                continue
            seen.add(key)

            if allow_origin.strip() == "*":
                severity = Severity.HIGH if credentials == "true" else Severity.MEDIUM
                description = (
                    "The server allows any origin"
                    + (
                        " and permits credentialed requests, which lets any website "
                        "read authenticated responses."
                        if credentials == "true"
                        else " to read cross-origin responses."
                    )
                )
            elif credentials == "true":
                severity = Severity.MEDIUM
                description = (
                    "The server reflects the request Origin header while allowing "
                    "credentials, which permits any site to make authenticated "
                    "cross-origin requests."
                )
            else:
                continue

            findings.append(
                self.finding(
                    title="Overly permissive CORS policy",
                    target=response.url,
                    description=f"{description} (Access-Control-Allow-Origin: {allow_origin})",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"GET {response.url}\n"
                        f"Access-Control-Allow-Origin: {allow_origin}\n"
                        f"Access-Control-Allow-Credentials: {credentials or '(absent)'}"
                    ),
                    matched=allow_origin,
                    remediation=self.remediation,
                )
            )
        return findings


class ClickjackingModule(Module):
    """Check for missing clickjacking protection."""
    group = "headers"

    id = "clickjacking"
    name = "Missing Clickjacking Protection"
    description = (
        "Pages without X-Frame-Options or a CSP frame-ancestors directive can be "
        "embedded by an attacker to trick a user into clicking."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-1021"
    owasp = "A05"
    tags = ["clickjacking", "config", "passive"]
    remediation = "Set `X-Frame-Options: DENY` and a CSP `frame-ancestors 'none'` directive."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()

        for response in ctx.responses:
            if "html" not in response.content_type:
                continue
            if response.header("x-frame-options"):
                continue
            csp = response.header("content-security-policy")
            if csp and "frame-ancestors" in csp.lower():
                continue
            host = urlparse(response.url).netloc
            if host in reported:
                continue
            reported.add(host)
            findings.append(
                self.finding(
                    title="Page can be framed by a third party",
                    target=response.url,
                    description=(
                        f"{response.url} can be embedded in an iframe by any origin. "
                        "An attacker can overlay invisible controls to steal clicks."
                    ),
                    confidence=Confidence.HIGH,
                    evidence_text=f"GET {response.url} -> {response.status}",
                    matched="X-Frame-Options/CSP frame-ancestors",
                    remediation=self.remediation,
                )
            )
        return findings


class MixedContentModule(Module):
    """Detect mixed content on HTTPS pages."""
    group = "headers"

    id = "mixed_content"
    name = "Mixed Content"
    description = "HTTPS pages that load sub-resources over plain HTTP can be downgraded or tampered with."
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.TRANSPORT
    capability = Capability.PASSIVE
    cwe = "CWE-319"
    owasp = "A02"
    tags = ["tls", "config", "passive"]
    remediation = "Serve every sub-resource over HTTPS, or add `Strict-Transport-Security` to force upgrade."

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for response in ctx.responses:
            if not response.ok or "html" not in response.content_type:
                continue
            if urlparse(response.url).scheme != "https":
                continue
            pattern = re.compile(r"""(?:src|href)\s*=\s*["'](http://[^"']+)["']""", re.IGNORECASE)
            for match in pattern.finditer(response.text[:400000]):
                url = match.group(1)
                if url in seen:
                    continue
                seen.add(url)
                findings.append(
                    self.finding(
                        title="Insecure sub-resource loaded over HTTP",
                        target=response.url,
                        description=(
                            f"The HTTPS page {response.url} loads {url} over plain "
                            "HTTP, allowing an active network attacker to modify the "
                            "response in transit."
                        ),
                        evidence_text=match.group(0)[:200],
                        matched=url,
                        remediation=self.remediation,
                    )
                )
                if len(findings) >= 25:
                    return findings
        return findings

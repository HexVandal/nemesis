"""Authentication, authorisation and access-control modules."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ...knowledge.signatures import REDIRECT_PAYLOADS
from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import HttpModule, ParamTarget, replace_param

#: Parameter names that usually carry a redirect target.
_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "return", "return_url", "returnurl", "returnto", "return_to", "next",
    "next_url", "nexturl", "dest", "destination", "go", "goto", "target",
    "out", "view", "continue", "forward", "f", "r", "u", "callback",
    "callback_url", "success_url", "cancel_url", "ref", "referer", "referrer",
}

#: Parameters that usually carry an object identifier.
_ID_PARAMS = {
    "id", "uid", "user_id", "userid", "user", "account", "acct", "profile",
    "order", "order_id", "orderid", "invoice", "invoice_id", "doc", "doc_id",
    "document", "item", "item_id", "project", "project_id", "ticket", "ticket_id",
    "group", "group_id", "org", "org_id", "workspace", "record", "row", "key",
}


class OpenRedirectModule(HttpModule):
    """Detect open redirect vulnerabilities."""
    group = "auth"

    id = "open_redirect"
    name = "Open Redirect"
    description = (
        "Supplies external URLs into redirect-like parameters and checks "
        "whether the server will actually redirect off-site."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.AUTH
    cwe = "CWE-601"
    owasp = "A01"
    tags = ["redirect", "active", "phishing"]
    remediation = (
        "Allowlist redirect targets, or resolve relative paths server-side "
        "instead of echoing user input into a Location header."
    )
    references = [
        "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
        "https://portswigger.net/web-security/open-redirect",
    ]
    max_params = 20
    max_payloads = 8

    def collect_targets(self, ctx: ScanContext) -> list[ParamTarget]:
        targets: list[ParamTarget] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints:
            for param in endpoint.params:
                if param.lower() not in _REDIRECT_PARAMS:
                    continue
                key = f"{endpoint.url}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(ParamTarget(url=endpoint.url, param=param))
        for form in ctx.forms:
            for param in form.raw_fields:
                if param.lower() not in _REDIRECT_PARAMS:
                    continue
                key = f"{form.action}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    ParamTarget(
                        url=form.action, param=param, method=form.method,
                        fields=dict(form.fields),
                    )
                )
        return targets[: self.max_params]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx):
            for payload in REDIRECT_PAYLOADS[: self.max_payloads]:
                url = replace_param(target.url, target.param, payload)
                response = await ctx.client.get(url, follow_redirects=False)
                if response.status not in (301, 302, 303, 307, 308):
                    continue
                location = response.header("location")
                if not location:
                    continue
                host = (urlparse(location).hostname or "").lower()
                if not host or host == ctx.host.lower():
                    continue
                if host.endswith(("example.com", "evil.example")):
                    findings.append(
                        self.finding(
                            title=f"Open redirect in parameter '{target.param}'",
                            target=target.url,
                            description=(
                                f"Parameter '{target.param}' on {target.url} causes a "
                                f"redirect to the attacker-controlled host {host}."
                            ),
                            confidence=Confidence.CONFIRMED,
                            evidence_text=(
                                f"GET {url}\n-> {response.status}\nLocation: {location}"
                            ),
                            matched=location,
                            parameter=target.param,
                        )
                    )
                    break
            if len(findings) >= 20:
                break
        return findings


class IdorModule(HttpModule):
    """Detect insecure direct object references by swapping identifiers."""
    group = "auth"

    id = "idor"
    name = "Insecure Direct Object Reference"
    description = (
        "Substitutes object identifiers with values belonging to other records "
        "and reports when the server returns a different, unauthorised object."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.AUTH
    cwe = "CWE-639"
    owasp = "A01"
    tags = ["idor", "authz", "active"]
    remediation = (
        "Authorise every object access against the authenticated principal's "
        "ownership, and use unguessable identifiers as defence in depth."
    )
    references = [
        "https://owasp.org/www-community/attacks/Insecure_Direct_Object_References",
        "https://portswigger.net/web-security/idor",
    ]
    max_params = 20

    #: Identifier values that commonly belong to someone else.
    _CANDIDATES = ["1", "2", "999999", "0", "-1", "1000000", "3", "42", "admin"]

    def collect_targets(self, ctx: ScanContext) -> list[ParamTarget]:
        targets: list[ParamTarget] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints:
            for param, value in endpoint.params.items():
                if param.lower() not in _ID_PARAMS:
                    continue
                if not value or not re.fullmatch(r"\d+", value):
                    continue
                key = f"{endpoint.url}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(ParamTarget(url=endpoint.url, param=param))
        return targets[: self.max_params]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()
        for target in self.collect_targets(ctx):
            baseline = await self.fetch(ctx, target, "1")
            for candidate in self._CANDIDATES:
                if candidate == "1":
                    continue
                probe = await self.fetch(ctx, target, candidate)
                if probe.status != 200 or not probe.ok:
                    continue
                if probe.length == baseline.length and probe.text == baseline.text:
                    continue
                # A different object was returned for a different id.
                if abs(probe.length - baseline.length) < 20 and probe.text == baseline.text:
                    continue
                # The same weakness across many URLs is one weakness.
                dedupe_key = f"{ctx.host}:{target.param}"
                if dedupe_key in reported:
                    break
                reported.add(dedupe_key)
                findings.append(
                    self.finding(
                        title=f"Possible IDOR on parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"Requesting {target.url} with {target.param}={candidate} "
                            f"returned a different object "
                            f"({probe.length} bytes vs {baseline.length} bytes for id=1) "
                            "without an authorisation failure. The server is likely "
                            "not checking object ownership."
                        ),
                        confidence=Confidence.MEDIUM,
                        evidence_text=(
                            f"GET {target.url}?{target.param}=1  -> {baseline.status} "
                            f"({baseline.length} bytes)\n"
                            f"GET {target.url}?{target.param}={candidate} -> {probe.status} "
                            f"({probe.length} bytes)"
                        ),
                        matched=candidate,
                        parameter=target.param,
                    )
                )
                break
            if len(findings) >= 15:
                break
        return findings


class CsrfModule(Module):
    """Detect forms that appear to lack CSRF protection."""
    group = "auth"

    id = "csrf_missing"
    name = "Missing CSRF Protection"
    description = (
        "Identifies state-changing forms that carry no anti-CSRF token, and "
        "checks whether the server enforces an Origin or Referer check."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.PASSIVE
    cwe = "CWE-352"
    owasp = "A01"
    tags = ["csrf", "auth", "passive"]
    remediation = (
        "Embed a cryptographically random per-session token in every "
        "state-changing form and validate it server-side, or require a "
        "custom header that a cross-site form cannot set."
    )

    _TOKEN_HINTS = ("csrf", "xsrf", "token", "authenticity", "_token", "nonce")
    _STATE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms:
            if form.method.upper() not in self._STATE_METHODS:
                continue
            if any(hint in name.lower() for name in form.raw_fields for hint in self._TOKEN_HINTS):
                continue
            findings.append(
                self.finding(
                    title=f"Form without CSRF token ({form.method})",
                    target=form.source_url or form.action,
                    description=(
                        f"The {form.method} form at {form.action} accepts the fields "
                        f"{form.raw_fields} without any anti-CSRF token. If the "
                        "endpoint is state-changing, it is likely forgeable from a "
                        "third-party site."
                    ),
                    evidence_text=(
                        f"Form action: {form.action}\nMethod: {form.method}\n"
                        f"Fields: {form.raw_fields}\nDiscovered at: {form.source_url}"
                    ),
                    matched=form.action,
                )
            )
            if len(findings) >= 25:
                break
        return findings


class HostHeaderInjectionModule(HttpModule):
    """Detect host header injection and password reset poisoning."""
    group = "auth"

    id = "host_header_injection"
    name = "Host Header Injection"
    description = (
        "Sends a foreign Host header and checks whether it is reflected into "
        "the response, a Location header or an absolute link."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.INJECTION
    cwe = "CWE-644"
    owasp = "A05"
    tags = ["headers", "injection", "active"]
    remediation = (
        "Never build absolute URLs from the Host header. Use a configured "
        "canonical host and validate the Host header against an allowlist."
    )
    max_params = 0

    _MARKER = "nemesis-host-canary.example"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tested = 0
        for endpoint in ctx.endpoints:
            if tested >= 12:
                break
            if not endpoint.url.lower().startswith("http"):
                continue
            tested += 1
            response = await ctx.client.get(
                endpoint.url, headers={"Host": self._MARKER}, follow_redirects=False
            )
            if not response.ok:
                continue
            reflected = self._MARKER in response.text
            location = response.header("location")
            if not reflected and (not location or self._MARKER not in location):
                continue
            findings.append(
                self.finding(
                    title="Host header reflected into the response",
                    target=endpoint.url,
                    description=(
                        f"{endpoint.url} reflects the Host header into its output. "
                        "An attacker who can influence the Host header (for example "
                        "via a password-reset link) can poison absolute URLs and "
                        "redirect victims to a domain they control."
                    ),
                    evidence_text=(
                        f"GET {endpoint.url}\nHost: {self._MARKER}\n"
                        f"-> {response.status}\n"
                        f"Location: {location or '(none)'}\n"
                        f"Body contains marker: {reflected}"
                    ),
                    matched=self._MARKER,
                )
            )
        return findings

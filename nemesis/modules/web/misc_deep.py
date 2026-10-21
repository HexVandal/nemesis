"""Storage, validation, DNS and export - the edges around the request."""

from __future__ import annotations

import re
import socket
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

_STORAGE = re.compile(
    r"(?:localStorage|sessionStorage)\.setItem\(\s*['\"]([^'\"]{0,40})['\"]", re.I
)
_SECRET_KEY = re.compile(r"(token|jwt|auth|session|api|key|secret|password)", re.I)

_TAKEOVER = re.compile(
    r"(NoSuchBucket|There isn't a GitHub Pages site here|No such app|"
    r"herokucdn\.com/error-pages/no-such-app|Fastly error: unknown domain|"
    r"This domain is not configured|Repository not found|"
    r"<title>Site Not Found</title>|The specified bucket does not exist)",
    re.I,
)

_NUMERIC_FIELD = re.compile(r"(qty|quantity|amount|price|age|count|number|num|id)$", re.I)
_NOT_NUMERIC = re.compile(r"(invalid|must be a number|numeric|not a valid)", re.I)


class SensitiveStorageModule(Module):
    """A token written to localStorage is readable by any script on the origin."""

    group = "browser"
    id = "sensitive_data_in_storage"
    name = "Credential Written to Browser Storage"
    description = "Reads served JavaScript for tokens written to local or session storage."
    severity = Severity.LOW
    confidence: Confidence = Confidence.MEDIUM
    category = Category.DISCLOSURE
    capability = Capability.PASSIVE
    cwe = "CWE-922"
    owasp = "A02"
    remediation = "Keep session material in an HttpOnly cookie, out of reach of script."
    references = ["https://cwe.mitre.org/data/definitions/922.html"]
    tags = ["browser", "storage", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for response in ctx.responses:
            url = getattr(response, "url", "") or ""
            if not urlparse(url).path.endswith((".js", ".mjs", ".jsx")):
                continue
            for match in _STORAGE.finditer(getattr(response, "text", "") or ""):
                key = match.group(1)
                if not _SECRET_KEY.search(key) or key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self.finding(
                        title=f"'{key}' stored in browser storage",
                        target=url,
                        description=(
                            f"The bundle writes '{key}' into local or session "
                            f"storage. Any XSS on this origin reads it directly - "
                            f"an HttpOnly cookie would not be reachable."
                        ),
                        evidence_text=f"GET {url}\n  {match.group(0)}",
                        matched=key,
                    )
                )
        return findings


class ClientValidationModule(Module):
    """The browser is not an enforcement point, but some servers think it is."""

    group = "injection"
    id = "client_side_validation_bypass"
    name = "Server Accepts Value the Client Rejects"
    description = (
        "Submits non-numeric text into fields that name themselves numeric and "
        "reports the servers that store it."
    )
    severity = Severity.LOW
    confidence: Confidence.HIGH
    category = Category.BUG
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-602"
    owasp = "A04"
    remediation = "Validate on the server; treat client-side validation as usability only."
    references = ["https://cwe.mitre.org/data/definitions/602.html"]
    tags = ["validation", "logic", "destructive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms[:3]:
            field = next(
                (n for n in form.raw_fields if _NUMERIC_FIELD.search(n)), None
            )
            if not field:
                continue
            body = {k: (v or "nemesis") for k, v in form.fields.items()}
            body[field] = "not-a-number"
            response = await ctx.client.post(form.action, data=body, follow_redirects=False)
            if response.status >= 400:
                continue
            if _NOT_NUMERIC.search(response.text or ""):
                continue
            findings.append(
                self.finding(
                    title=f"'{field}' accepted non-numeric input",
                    target=form.action,
                    description=(
                        f"The field '{field}' is numeric in the UI, and the server "
                        f"stored 'not-a-number' instead of rejecting it. Whatever "
                        f"reads this column later is now parsing nonsense."
                    ),
                    evidence_text=(
                        f"POST {form.action}\n  {field} = not-a-number\n"
                        f"  status: {response.status}"
                    ),
                    matched="not-a-number",
                    field=field,
                )
            )
        return findings


class SubdomainTakeoverModule(Module):
    """A host that answers with its provider's 'unclaimed' page is takeable."""

    group = "host"
    id = "subdomain_takeover"
    name = "Subdomain Takeover Fingerprint"
    description = (
        "Looks for the placeholder pages providers serve for an unconfigured "
        "host - S3, GitHub Pages, Heroku, Fastly and others."
    )
    severity = Severity.HIGH
    confidence: Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-840"
    owasp = "A05"
    remediation = "Remove the DNS record, or claim the name at the provider."
    references = ["https://owasp.org/www-community/attacks/Subdomain_takeover"]
    tags = ["dns", "takeover", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        response = await ctx.client.get(ctx.target_url, follow_redirects=False)
        match = _TAKEOVER.search(response.text or "")
        if not match:
            return []
        return [
            self.finding(
                title=f"Host answers with a provider placeholder ({match.group(0)})",
                target=ctx.target_url,
                description=(
                    "The hostname resolves to a service that does not recognise "
                    "it. Anyone who registers that name at the provider inherits "
                    "this hostname, its cookies and its TLS certificate."
                ),
                evidence_text=(
                    f"GET {ctx.target_url} -> {response.status}\n"
                    f"  fingerprint: {match.group(0)}"
                ),
                matched=match.group(0),
            )
        ]


class DanglingDnsModule(Module):
    """An asset pointing at a hostname that no longer resolves."""

    group = "host"
    id = "dangling_dns"
    name = "Dangling Host Reference"
    description = (
        "Resolves the external hosts referenced by the site and reports the "
        "ones that no longer exist."
    )
    severity = Severity.LOW
    confidence: Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-840"
    owasp = "A05"
    remediation = "Remove references to retired hosts; they are registrable by anyone."
    references = ["https://cwe.mitre.org/data/definitions/840.html"]
    tags = ["dns", "takeover", "passive"]

    max_hosts: int = 8

    def _resolves(self, host: str) -> bool:
        try:
            socket.getaddrinfo(host, None)
            return True
        except socket.gaierror:
            return False
        except OSError:
            return True

    async def run(self, ctx: ScanContext) -> list[Finding]:
        own = urlparse(ctx.target_url).hostname or ""
        hosts: list[str] = []
        for response in ctx.responses:
            for match in re.finditer(r"(?:src|href)=['\"]https?://([^/'\"]+)", getattr(response, "text", "") or ""):
                host = match.group(1).split(":")[0]
                if host and host != own and host not in hosts:
                    hosts.append(host)

        findings: list[Finding] = []
        for host in hosts[: self.max_hosts]:
            if "." not in host:
                continue
            if self._resolves(host):
                continue
            findings.append(
                self.finding(
                    title=f"Referenced host does not resolve: {host}",
                    target=ctx.target_url,
                    description=(
                        f"The page loads a resource from {host}, which no longer "
                        f"resolves. If that name is re-registered, the new owner "
                        f"serves code into this page."
                    ),
                    evidence_text=f"GET {getattr(response, 'url', '')}\n  asset host: {host}\n  DNS: NXDOMAIN",
                    matched=host,
                )
            )
        return findings


class CsvFormulaModule(Module):
    """A spreadsheet treats a leading = as code."""

    group = "exposure"
    id = "csv_formula_injection"
    name = "CSV Formula Injection"
    description = (
        "Submits a formula into a form field, then reads the CSV export back "
        "and reports the cell that survived unescaped."
    )
    severity = Severity.MEDIUM
    confidence: Confidence.HIGH
    category = Category.INJECTION
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-1236"
    owasp = "A03"
    remediation = "Prefix cells starting with = + - @ with a single quote on export."
    references = ["https://owasp.org/www-community/attacks/CSV_Injection"]
    tags = ["csv", "export", "destructive"]

    marker = "=1+1+cmd"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        exports = [
            endpoint.url
            for endpoint in ctx.endpoints
            if "csv" in endpoint.url.lower() or "export" in endpoint.url.lower()
        ]
        if not exports or not ctx.forms:
            return []

        form = ctx.forms[0]
        body = {k: (v or "nemesis") for k, v in form.fields.items()}
        for name in form.raw_fields[:2]:
            body[name] = self.marker
        await ctx.client.post(form.action, data=body, follow_redirects=False)

        for url in exports[:3]:
            response = await ctx.client.get(url, follow_redirects=False)
            if response.status != 200 or self.marker not in (response.text or ""):
                continue
            findings.append(
                self.finding(
                    title=f"Formula survives export at {url}",
                    target=url,
                    description=(
                        "A value starting with '=' was written through the form and "
                        "came back in the CSV unchanged. Excel and Sheets evaluate "
                        "it on open, which turns an export into a delivery "
                        "mechanism."
                    ),
                    evidence_text=(
                        f"POST {form.action}  {name}={self.marker}\n"
                        f"GET  {url}\n  cell: {self.marker}"
                    ),
                    matched=self.marker,
                )
            )
        return findings


class OauthScopeModule(Module):
    """Can a client ask for more than it was granted?"""

    group = "oauth"
    id = "oauth_scope_escalation"
    name = "OAuth Scope Escalation"
    description = (
        "Replays an authorization request with an elevated scope and reports "
        "endpoints that issue the redirect anyway."
    )
    severity = Severity.MEDIUM
    confidence: Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-269"
    owasp = "A07"
    remediation = "Reject any scope the client is not registered for; never silently downgrade."
    references = ["https://datatracker.ietf.org/doc/html/rfc6749#section-3.3"]
    tags = ["oauth", "scope", "active"]

    elevated = "openid profile email admin write"

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints:
            parsed = urlparse(endpoint.url)
            pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
            if "client_id" not in pairs or "redirect_uri" not in pairs or endpoint.url in seen:
                continue
            seen.add(endpoint.url)
            requested = pairs.get("scope", "")
            if self.elevated in requested:
                continue
            elevated = urlunparse(
                parsed._replace(
                    query=urlencode(
                        [(k, self.elevated if k == "scope" else v) for k, v in pairs.items()]
                    )
                )
            )
            response = await ctx.client.get(elevated, follow_redirects=False)
            if response.status not in (301, 302, 303):
                continue
            location = ""
            for key, value in response.headers.items():
                if key.lower() == "location":
                    location = value
            if pairs.get("redirect_uri", "")[:20] not in location:
                continue
            findings.append(
                self.finding(
                    title="Authorization server accepts an unregistered scope",
                    target=endpoint.url,
                    description=(
                        f"The client asked for '{self.elevated}' and the server "
                        f"redirected with a code anyway. If the token carries the "
                        f"requested scopes, a low-privilege client can mint a "
                        f"high-privilege token."
                    ),
                    evidence_text=(
                        f"GET {endpoint.url}  (original scope: {requested or 'none'})\n"
                        f"GET {elevated}\n  -> {response.status} {location[:120]}"
                    ),
                    matched=self.elevated,
                )
            )
        return findings

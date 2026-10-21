"""Access control and identity questions, answered by comparison."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Paths that should never answer an anonymous client on an app that has logins.
PRIVILEGED = [
    "/admin", "/admin/users", "/api/admin", "/api/admin/users",
    "/api/users", "/internal", "/manage", "/api/v1/admin",
]

#: Where an API description usually lives.
SCHEMA_PATHS = ["/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs"]

_TOKEN_PARAMS = ("token", "reset", "code", "key", "ticket", "invite")


def _has_auth(ctx: ScanContext) -> bool:
    config = ctx.config
    return bool(getattr(config, "cookies", None) or getattr(config, "extra_headers", None))


def _text_probe_like(a: str, b: str) -> float:
    """Cheap similarity: shared prefix length over the longer string."""
    if not a or not b:
        return 0.0
    limit = min(len(a), len(b))
    same = 0
    for index in range(limit):
        if a[index] != b[index]:
            break
        same += 1
    return same / max(len(a), len(b))


class ApiUnauthenticatedModule(Module):
    """Does the API answer without the session it was designed to require?

    Runs only when the operator supplied credentials - without a session there
    is nothing to compare against, and guessing would produce noise.
    """

    group = "api"
    id = "api_unauthenticated_access"
    name = "API Answers Without Credentials"
    description = (
        "Replays discovered API requests with the session removed and reports "
        "the ones that still return data."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-306"
    owasp = "A01"
    remediation = "Require authentication at the router, not in each handler."
    references = ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"]
    tags = ["api", "authz", "active"]

    max_targets: int = 10

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not _has_auth(ctx):
            return []
        findings: list[Finding] = []
        for endpoint in ctx.endpoints[: self.max_targets]:
            with_auth = await ctx.client.get(endpoint.url, follow_redirects=False)
            anonymous = await ctx.client.get(
                endpoint.url, headers={"Cookie": ""}, follow_redirects=False
            )
            if with_auth.status != 200 or anonymous.status != 200:
                continue
            if len(anonymous.text or "") < 40:
                continue
            if _text_probe_like(with_auth.text or "", anonymous.text or "") < 0.9:
                continue
            findings.append(
                self.finding(
                    title=f"Unauthenticated request returns the same body: {endpoint.url}",
                    target=endpoint.url,
                    description=(
                        "The response with the session removed is byte-identical "
                        "in its opening to the authenticated one. Whatever this "
                        "endpoint protects, it is not protecting it with "
                        "authentication."
                    ),
                    evidence_text=(
                        f"GET {endpoint.url} (with session) -> {with_auth.status}, "
                        f"{len(with_auth.text)} bytes\n"
                        f"GET {endpoint.url} (no session)   -> {anonymous.status}, "
                        f"{len(anonymous.text)} bytes"
                    ),
                    matched="identical body",
                )
            )
        return findings


class FunctionLevelAuthzModule(Module):
    """Administrative paths that answer a client with no session at all."""

    group = "auth"
    id = "function_level_authz"
    name = "Privileged Path Without Authentication"
    description = "Requests administrative paths anonymously and reports the ones that answer 200."
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-862"
    owasp = "A01"
    remediation = "Authorise by role on every route, and deny by default."
    references = ["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"]
    tags = ["authz", "admin", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.forms:
            # No login anywhere: an open /admin is not a broken control, it is
            # an app with no accounts. Stay quiet.
            return []
        root = ctx.target_url.rstrip("/")
        findings: list[Finding] = []
        for path in PRIVILEGED:
            response = await ctx.client.get(f"{root}{path}", follow_redirects=False)
            if response.status != 200 or len(response.text or "") < 40:
                continue
            findings.append(
                self.finding(
                    title=f"Privileged path answers anonymously: {path}",
                    target=f"{root}{path}",
                    description=(
                        f"{path} returned 200 with a body to a client carrying no "
                        f"session. The application has a login form, so this route "
                        f"was meant to sit behind it."
                    ),
                    evidence_text=f"GET {root}{path} -> 200, {len(response.text)} bytes",
                    matched=path,
                )
            )
        return findings


class OpenApiSecurityModule(Module):
    """A published schema that declares no security requirement at all."""

    group = "api"
    id = "openapi_security_definition"
    name = "OpenAPI Declares No Security"
    description = "Reads the published schema and reports an empty or absent security section."
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-1059"
    owasp = "A05"
    remediation = "Declare securitySchemes and a global security requirement in the schema."
    references = ["https://spec.openapis.org/oas/v3.1.0#security-requirement-object"]
    tags = ["api", "openapi", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        import json

        root = ctx.target_url.rstrip("/")
        for path in SCHEMA_PATHS:
            response = await ctx.client.get(f"{root}{path}", follow_redirects=False)
            if response.status != 200 or not response.text:
                continue
            try:
                document = json.loads(response.text)
            except (ValueError, TypeError):
                continue
            if not isinstance(document, dict):
                continue
            schemes = document.get("securitySchemes") or document.get("components", {}).get(
                "securitySchemes"
            )
            if document.get("security") or schemes:
                continue
            if not document.get("paths"):
                continue
            return [
                self.finding(
                    title=f"{path} declares no security requirement",
                    target=f"{root}{path}",
                    description=(
                        "The schema lists paths but no security scheme and no "
                        "global requirement. Either the API is open, or the "
                        "documentation is wrong about what is protected."
                    ),
                    evidence_text=(
                        f"GET {root}{path}\n"
                        f"  paths    : {len(document.get('paths', {}))}\n"
                        "  security : absent"
                    ),
                    matched="security absent",
                )
            ]
        return []


class ApiEndpointModule(Module):
    """Undocumented API roots sitting next to the documented ones."""

    group = "api"
    id = "api_endpoint_bruteforce"
    name = "Undocumented API Endpoint"
    description = "Requests a short list of conventional API paths and reports the ones not in the crawl."
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-1059"
    owasp = "A05"
    remediation = "Publish the whole surface, or remove what is not needed."
    references = ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"]
    tags = ["api", "discovery", "active"]

    paths = ["/api", "/api/v1", "/api/v2", "/api/users", "/api/status", "/graphql", "/api/health"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.target_url.rstrip("/")
        known = {urlparse(endpoint.url).path.rstrip("/") for endpoint in ctx.endpoints}
        findings: list[Finding] = []
        for path in self.paths:
            if path.rstrip("/") in known:
                continue
            response = await ctx.client.get(f"{root}{path}", follow_redirects=False)
            if response.status != 200 or len(response.text or "") < 20:
                continue
            findings.append(
                self.finding(
                    title=f"Undeclared API path answers: {path}",
                    target=f"{root}{path}",
                    description=(
                        f"{path} returned content although the crawl never found a "
                        f"link to it. Endpoints nobody documents are endpoints "
                        f"nobody tests."
                    ),
                    evidence_text=f"GET {root}{path} -> 200, {len(response.text)} bytes",
                    matched=path,
                )
            )
        return findings


class AccountEnumerationModule(Module):
    """Different answers for different identities is an account oracle."""

    group = "auth"
    id = "account_enumeration"
    name = "Account Enumeration"
    description = (
        "Submits two logins that cannot succeed - one for a common account "
        "name, one random - and reports forms that answer them differently."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-204"
    owasp = "A07"
    remediation = "Return one message for every failed login, whatever the reason."
    references = ["https://cwe.mitre.org/data/definitions/204.html"]
    tags = ["auth", "enumeration", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms[:2]:
            identity = next(
                (n for n in form.raw_fields if any(h in n.lower() for h in ("user", "email", "login"))),
                None,
            )
            secret = next((n for n in form.raw_fields if "pass" in n.lower()), None)
            if not identity or not secret:
                continue

            async def attempt(
                value: str,
                form=form,
                identity=identity,
                secret=secret,
            ):
                body = {k: (v or "nemesis") for k, v in form.fields.items()}
                body[identity] = value
                body[secret] = "nemsis-wrong-password-1"
                return await ctx.client.post(form.action, data=body, follow_redirects=False)

            common = await attempt("admin")
            random = await attempt("nms_" + "zq8x2v7k")
            if common.status != random.status:
                continue
            similarity = _text_probe_like(common.text or "", random.text or "")
            if similarity > 0.9:
                continue
            findings.append(
                self.finding(
                    title=f"Login answers differ by account on {form.action}",
                    target=form.action,
                    description=(
                        "A login attempt for 'admin' and one for a random string "
                        "produced different responses. That difference tells an "
                        "attacker which accounts exist before a single password "
                        "is guessed."
                    ),
                    evidence_text=(
                        f"POST {form.action}  {identity}=admin        -> {common.status}\n"
                        f"POST {form.action}  {identity}=nms_zq8x2v7k -> {random.status}\n"
                        f"  opening similarity: {similarity:.2f}"
                    ),
                    matched="different failure messages",
                )
            )
        return findings


class ResetTokenEntropyModule(Module):
    """A reset token short enough to guess is not a token."""

    group = "auth"
    id = "reset_token_entropy"
    name = "Weak Password Reset Token"
    description = "Measures reset tokens observed in crawled URLs for length and alphabet."
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.PASSIVE
    cwe = "CWE-330"
    owasp = "A07"
    remediation = "Use at least 128 bits from a CSPRNG, single-use, bound to the account."
    references = ["https://cwe.mitre.org/data/definitions/330.html"]
    tags = ["auth", "token", "passive"]

    _HEX = re.compile(r"^[0-9a-fA-F]+$")

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        urls = [endpoint.url for endpoint in ctx.endpoints]
        urls += [getattr(response, "url", "") for response in ctx.responses]
        for url in urls:
            for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
                if not any(hint in key.lower() for hint in _TOKEN_PARAMS):
                    continue
                if len(value) < 4 or value in seen:
                    continue
                seen.add(value)
                weak = len(value) < 16 or (bool(self._HEX.match(value)) and len(value) < 32)
                if not weak:
                    continue
                findings.append(
                    self.finding(
                        title=f"Short reset token in '{key}' ({len(value)} chars)",
                        target=url,
                        description=(
                            f"The token is {len(value)} characters of "
                            f"{'hexadecimal' if self._HEX.match(value) else 'mixed characters'}. "
                            f"That is small enough to enumerate."
                        ),
                        evidence_text=f"GET {url}\n  {key} = {value[:6]}… ({len(value)} chars)",
                        matched=f"{len(value)} chars",
                    )
                )
        return findings

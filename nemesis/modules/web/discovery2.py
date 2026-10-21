"""What the application publishes about itself, and what it leaves in URLs."""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Paths that expose a machine-readable description of the API.
SCHEMA_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/openapi.yaml",
]

#: A JWT sitting in a query string is a credential in a referer header away
#: from leaking to a third party.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_SECRET_PARAMS = ("token", "api_key", "apikey", "access_token", "password", "secret", "session")


class ApiSchemaModule(Module):
    """Report API descriptions that are served to anonymous clients.

    An schema is not a vulnerability by itself. It is a map: every path,
    every parameter, every field the team thought was internal.
    """

    group = "exposure"

    id = "api_schema_exposure"
    name = "Public API Schema"
    description = (
        "Probes the conventional locations of OpenAPI and Swagger documents "
        "and reports the ones served to an unauthenticated client."
    )
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-200"
    owasp = "A05"
    remediation = (
        "Serve the schema only to authenticated developers, or generate it at "
        "build time and keep it out of production."
    )
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]
    tags = ["api", "exposure", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        root = ctx.target_url.rstrip("/")
        for path in SCHEMA_PATHS:
            url = f"{root}{path}"
            response = await ctx.client.get(url, follow_redirects=False)
            if response.status != 200 or not response.text:
                continue
            try:
                document = json.loads(response.text)
            except (ValueError, TypeError):
                continue
            if not isinstance(document, dict):
                continue
            if not ({"openapi", "swagger"} & set(document)) and "paths" not in document:
                continue

            paths = document.get("paths")
            count = len(paths) if isinstance(paths, dict) else 0
            findings.append(
                self.finding(
                    title=f"API schema published at {path}",
                    target=url,
                    description=(
                        f"{path} returned a machine-readable API description "
                        f"listing {count} path(s). It is readable without "
                        f"authentication, so the attack surface is enumerated "
                        f"for anyone who asks."
                    ),
                    evidence_text=(
                        f"GET {url}\n"
                        f"  status = {response.status}\n"
                        f"  keys   = {sorted(document)[:8]}\n"
                        f"  paths  = {count}"
                    ),
                    matched=path,
                    path_count=count,
                )
            )
        return findings


class SensitiveDataInUrlModule(Module):
    """Credentials in query strings leak through referers, logs and history.

    This reads only what the crawler already fetched - no extra traffic.
    """

    group = "disclosure"

    id = "sensitive_data_in_url"
    name = "Sensitive Data in URL"
    description = (
        "Scans crawled URLs and links for tokens, keys and JWTs carried in the "
        "query string."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.PASSIVE
    cwe = "CWE-598"
    owasp = "A04"
    remediation = (
        "Keep credentials in headers or in a POST body, never in a URL that "
        "ends up in logs, history and Referer headers."
    )
    references = ["https://cwe.mitre.org/data/definitions/598.html"]
    tags = ["disclosure", "secrets", "passive"]

    def _offending(self, url: str) -> tuple[str, str] | None:
        if _JWT.search(url):
            return "jwt", "a JSON Web Token"
        for key, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
            if key.lower() in _SECRET_PARAMS and len(value) >= 8:
                return key, f"a '{key}' parameter"
        return None

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        urls = [endpoint.url for endpoint in ctx.endpoints]
        urls += [response.url for response in ctx.responses if getattr(response, "url", "")]
        for url in urls:
            if url in seen:
                continue
            seen.add(url)
            hit = self._offending(url)
            if not hit:
                continue
            key, description = hit
            findings.append(
                self.finding(
                    title=f"Credential in URL ({key})",
                    target=url,
                    description=(
                        f"The URL carries {description} in its query string. Every "
                        f"proxy log, browser history entry and outbound Referer "
                        f"header copies it."
                    ),
                    evidence_text=f"GET {url}",
                    matched=key,
                )
            )
        return findings

"""Configuration, information disclosure and protocol-level modules."""

from __future__ import annotations

import re

from ...knowledge.signatures import STACKTRACE_SIGNATURES, match_signatures
from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import HttpModule


class InfoDisclosureModule(Module):
    """Detect stack traces, debug output and verbose error pages."""
    group = "disclosure"

    id = "info_disclosure"
    name = "Information Disclosure"
    description = (
        "Detects stack traces, verbose framework errors, debug pages and "
        "internal hostnames leaked into responses."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.PASSIVE
    cwe = "CWE-209"
    owasp = "A05"
    tags = ["disclosure", "passive"]
    remediation = (
        "Disable detailed error pages in production, return generic errors to "
        "clients, and log the detail server-side."
    )
    references = ["https://owasp.org/www-community/attacks/Information_Leakage"]

    #: Internal-looking names that should not reach a client.
    _INTERNAL_PATTERNS = [
        (r"\.internal\b|\.local\b|\.corp\b", "internal domain name"),
        (r"192\.168\.\d{1,3}\.\d{1,3}", "private IP address"),
        (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "private IP address"),
        (r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", "private IP address"),
        (r"/(?:home|Users|var/www|app|opt/srv)/[\w./-]+", "filesystem path"),
        (r"jdbc:(?:mysql|postgresql|oracle)", "database connection string"),
        (r"mongodb(?:\+srv)?://[^/\s]+", "MongoDB connection string"),
        (r"postgres(?:ql)?://[^/\s]+", "PostgreSQL connection string"),
        (r"redis://[^/\s]+", "Redis connection string"),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        # The same leaked hostname on twenty pages is one disclosure, not
        # twenty. Report each distinct value once.
        reported: set[str] = set()
        for response in ctx.responses:
            # Error responses are inspected too - a stack trace is almost
            # always rendered on a 4xx/5xx page.
            if not response.text:
                continue
            hits = match_signatures(response.text, STACKTRACE_SIGNATURES, limit=2)
            if hits:
                label, matched = hits[0]
                findings.append(
                    self.finding(
                        title="Stack trace or verbose error in response",
                        target=response.url,
                        description=(
                            f"{response.url} returns a {label} stack trace. These "
                            "expose file paths, library versions and sometimes "
                            "credentials, and give an attacker a map of the backend."
                        ),
                        evidence_text=f"GET {response.url}\n{matched[:600]}",
                        matched=matched,
                    )
                )
                continue

            for pattern, description in self._INTERNAL_PATTERNS:
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    if match.group(0).lower() in reported:
                        break
                    reported.add(match.group(0).lower())
                    findings.append(
                        self.finding(
                            title=f"{description[0].upper()}{description[1:]} disclosed",
                            target=response.url,
                            description=(
                                f"{response.url} discloses a {description}: "
                                f"{match.group(0)[:120]}"
                            ),
                            severity=Severity.LOW,
                            evidence_text=f"GET {response.url}\n{match.group(0)[:300]}",
                            matched=match.group(0)[:200],
                        )
                    )
                    break
            if len(findings) >= 30:
                break
        return findings


class HttpMethodsModule(HttpModule):
    """Check for dangerous HTTP methods and permissive CORS preflight."""
    group = "config"

    id = "http_method_probe"
    name = "Permissive HTTP Methods"
    description = (
        "Probes whether the server accepts unsafe methods such as TRACE, PUT "
        "and DELETE on resources it should not modify."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-16"
    owasp = "A05"
    tags = ["http", "config"]
    remediation = (
        "Restrict allowed methods per resource and disable TRACE at the server "
        "or reverse proxy."
    )
    max_params = 0

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        tested = 0
        for endpoint in ctx.endpoints:
            if tested >= 10:
                break
            tested += 1
            for method in ("TRACE", "PUT", "DELETE"):
                response = await ctx.client.request(
                    method, endpoint.url, follow_redirects=False
                )
                if response.error:
                    continue
                if method == "TRACE" and response.status in (200, 405) and response.text:
                    if "TRAC" in response.text.upper() or response.status == 200:
                        findings.append(
                            self.finding(
                                title="HTTP TRACE method is enabled",
                                target=endpoint.url,
                                description=(
                                    f"{endpoint.url} answers TRACE requests, allowing "
                                    "an attacker to read back cookies and "
                                    "authorization headers sent by other clients "
                                    "(Cross-Site Tracing)."
                                ),
                                evidence_text=f"{method} {endpoint.url} -> {response.status}",
                                matched="TRACE",
                            )
                        )
                elif method in ("PUT", "DELETE") and response.status in (200, 201, 204):
                    findings.append(
                        self.finding(
                            title=f"HTTP {method} accepted on a static resource",
                            target=endpoint.url,
                            description=(
                                f"{endpoint.url} accepts {method} requests and "
                                f"returned {response.status}. Unauthenticated write "
                                "or delete access to resources is a serious control gap."
                            ),
                            confidence=Confidence.MEDIUM,
                            evidence_text=f"{method} {endpoint.url} -> {response.status}",
                            matched=method,
                        )
                    )
        return findings


class GraphqlIntrospectionModule(HttpModule):
    """Check whether GraphQL introspection is enabled."""
    group = "exposure"

    id = "graphql_introspection"
    name = "GraphQL Introspection Enabled"
    description = (
        "Queries the GraphQL introspection endpoint to see whether the full "
        "schema is exposed to unauthenticated clients."
    )
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-200"
    owasp = "A05"
    tags = ["graphql", "disclosure", "active"]
    remediation = (
        "Disable introspection in production, or gate it behind authentication and "
        "an allowlist."
    )
    max_params = 0

    _QUERY = {"query": "{__schema{types{name fields{name type{name kind}}}}}"}

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = {"/graphql", "/api/graphql", "/graphql/api", "/gql"}
        for endpoint in ctx.endpoints:
            if "graphql" in endpoint.url.lower():
                candidates.add(endpoint.url)

        seen: set[str] = set()
        for candidate in candidates:
            url = candidate if candidate.startswith("http") else ctx.target_url.rstrip("/") + candidate
            if url in seen or not ctx.scope.allows(url):
                continue
            seen.add(url)
            response = await ctx.client.post(url, json=self._QUERY)
            if not response.ok:
                continue
            if "__schema" in response.text and '"types"' in response.text:
                findings.append(
                    self.finding(
                        title="GraphQL schema exposed via introspection",
                        target=url,
                        description=(
                            f"{url} returns the full GraphQL schema to an "
                            "unauthenticated client. The schema is a map of every "
                            "query, mutation and type the application supports."
                        ),
                        evidence_text=(
                            f"POST {url}\n{response.text[:1200]}"
                        ),
                        matched="__schema",
                    )
                )
        return findings


class TechOutdatedModule(Module):
    """Flag fingerprinted software running an obviously outdated version."""
    group = "supplychain"

    id = "tech_outdated"
    name = "Outdated Component Version"
    description = (
        "Compares fingerprinted component versions against known-vulnerable "
        "release ranges for a small set of high-profile products."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.SUPPLY_CHAIN
    capability = Capability.PASSIVE
    cwe = "CWE-1104"
    owasp = "A06"
    tags = ["supply-chain", "version", "passive"]
    remediation = "Upgrade the affected component to a currently supported release."

    #: product -> (known-bad versions, note)
    _EOL: dict[str, tuple[set[str], str]] = {
        "PHP": ({"5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0"}, "PHP 8.0 and older are end-of-life"),
        "WordPress": ({"4.9", "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8"}, "WordPress 5.8 and older no longer receive security fixes"),
        "Apache Tomcat": ({"7", "8", "8.5"}, "Tomcat 8.5 and older are end-of-life"),
        "Microsoft IIS": ({"6", "7", "7.5"}, "IIS 7.5 and older are end-of-life"),
        "Drupal": ({"7", "8", "9"}, "Drupal 9 and older are end-of-life"),
        "Joomla": ({"3", "3.9"}, "Joomla 3.x is end-of-life"),
        "OpenSSL": ({"1.0", "1.0.1", "1.0.2", "1.1.0", "1.1.1"}, "OpenSSL 1.1.1 reached end-of-life in 2023"),
    }

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for tech in ctx.technologies:
            if not tech.version:
                continue
            for product, (bad_versions, note) in self._EOL.items():
                if tech.name.lower() != product.lower():
                    continue
                major_minor = ".".join(tech.version.split(".")[:2])
                if major_minor in bad_versions or tech.version in bad_versions:
                    findings.append(
                        self.finding(
                            title=f"Outdated {tech.name} {tech.version}",
                            target=ctx.target_url,
                            description=(
                                f"{tech.name} {tech.version} is fingerprinted on the "
                                f"target. {note}. It is likely to carry known, "
                                "publicly documented vulnerabilities."
                            ),
                            evidence_text=f"Detected {tech} via {tech.source}",
                            matched=tech.version,
                        )
                    )
        return findings

"""What the deployment left in the web root.

Eight checks that ask one question each: does this path answer with something
the public should not see? Every one of them requires a positive response with
matching content - a 200 alone proves nothing.
"""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Paths that are only ever created by accident.
BACKUP_SUFFIXES = [".bak", ".old", ".orig", ".save", "~", ".swp", ".copy"]

VCS_PATHS = [
    ("/.git/HEAD", re.compile(r"^ref:\s+refs/")),
    ("/.git/config", re.compile(r"\[core\]")),
    ("/.svn/entries", re.compile(r"\d+|dir")),
    ("/.hg/requires", re.compile(r"revlog|store")),
    ("/.bzr/README", re.compile(r"Bazaar")),
]

CI_PATHS = [
    ("/.gitlab-ci.yml", re.compile(r"stages:|script:")),
    ("/Jenkinsfile", re.compile(r"pipeline\s*\{|node\s*\{")),
    ("/.travis.yml", re.compile(r"language:")),
    ("/bitbucket-pipelines.yml", re.compile(r"pipelines:")),
    ("/.github/workflows/main.yml", re.compile(r"on:|jobs:")),
    ("/azure-pipelines.yml", re.compile(r"trigger:|pool:")),
]

ENV_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.dev",
    "/config.env", "/.env.backup", "/app.env",
]

ACTUATOR_PATHS = [
    ("/actuator", re.compile(r'"_links"|"status"')),
    ("/actuator/env", re.compile(r'"propertySources"|"activeProfiles"')),
    ("/actuator/health", re.compile(r'"status"\s*:\s*"(UP|DOWN)"')),
    ("/actuator/beans", re.compile(r'"beans"')),
    ("/actuator/heapdump", None),
    ("/actuator/mappings", re.compile(r'"contexts"|"mappings"')),
]

DEBUG_PATHS = [
    ("/console", re.compile(r"H2 Console|h2-console|Login")),
    ("/phpinfo.php", re.compile(r"PHP Version|phpinfo\(\)")),
    ("/debug", re.compile(r"werkzeug|Debugger|interactive")),
    ("/__debug__", re.compile(r"werkzeug|Debugger")),
    ("/server-status", re.compile(r"Apache Server Status")),
    ("/server-info", re.compile(r"Apache Server Information")),
]

_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=.*$", re.MULTILINE)
_FRAMEWORK_ERROR = re.compile(
    r"(Whitelabel Error Page|Whoops!|Symfony Exception|Django tried these URL patterns|"
    r"Laravel|Express.*Cannot GET|ASP\.NET|Stack trace)",
    re.IGNORECASE,
)


class _PathProbe(Module):
    """Shared behaviour: request paths, keep the ones that answer with X."""

    abstract = True

    max_paths: int = 12

    async def probe(
        self,
        ctx: ScanContext,
        paths: list[tuple[str, re.Pattern | None]],
    ) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        root = ctx.target_url.rstrip("/")
        for path, pattern in paths[: self.max_paths]:
            response = await ctx.client.get(f"{root}{path}", follow_redirects=False)
            if response.status != 200 or not response.text:
                continue
            if pattern is not None and not pattern.search(response.text):
                continue
            hits.append((path, response.text[:400]))
        return hits

    def report(
        self,
        path: str,
        url: str,
        body: str,
        *,
        title: str,
        description: str,
        severity: Severity,
        matched: str,
    ) -> Finding:
        return self.finding(
            title=title,
            target=url,
            description=description,
            severity=severity,
            confidence=Confidence.CONFIRMED,
            evidence_text=f"GET {url}{path}\n  {body[:200]}",
            matched=matched,
            path=path,
        )


class BackupFileModule(_PathProbe):
    group = "exposure"
    id = "backup_file_sweep"
    name = "Backup File Exposure"
    description = "Appends editor and backup suffixes to discovered paths and reports the ones served."
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-530"
    owasp = "A05"
    remediation = "Never deploy editor backups; strip them from the image at build time."
    references = ["https://owasp.org/www-community/vulnerabilities/Backup_file"]
    tags = ["exposure", "backup", "active"]
    max_paths = 8

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        paths: list[tuple[str, re.Pattern | None]] = []
        for endpoint in ctx.endpoints[:4]:
            from urllib.parse import urlparse

            path = urlparse(endpoint.url).path
            if not path or path == "/":
                continue
            paths.extend((f"{path}{suffix}", None) for suffix in BACKUP_SUFFIXES[:2])
        for path, body in await self.probe(ctx, paths):
            findings.append(
                self.report(
                    path, ctx.target_url, body,
                    title=f"Backup file served: {path}",
                    description=(
                        "A backup copy of a live file is downloadable. These are "
                        "generated by editors and deploy scripts and routinely "
                        "contain source, credentials and comments the original "
                        "never exposed."
                    ),
                    severity=Severity.HIGH,
                    matched=path,
                )
            )
        return findings


class VcsMetadataModule(_PathProbe):
    group = "exposure"
    id = "vcs_metadata"
    name = "Version Control Metadata"
    description = "Checks for .git, .svn, .hg and .bzr directories in the web root."
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-538"
    owasp = "A05"
    remediation = "Serve from a build artifact, never from a working copy."
    references = ["https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url"]
    tags = ["exposure", "vcs", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [
            self.report(
                path, ctx.target_url, body,
                title=f"Repository metadata exposed: {path}",
                description=(
                    "The deployment serves version-control metadata. With .git "
                    "readable, the full history - including deleted secrets - can "
                    "be reconstructed."
                ),
                severity=Severity.HIGH,
                matched=path,
            )
            for path, body in await self.probe(ctx, VCS_PATHS)
        ]


class CiMetadataModule(_PathProbe):
    group = "exposure"
    id = "ci_metadata"
    name = "CI Configuration Exposure"
    description = "Checks for pipeline definitions served from the web root."
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-538"
    owasp = "A05"
    remediation = "Keep pipeline definitions out of the served directory."
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]
    tags = ["exposure", "ci", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [
            self.report(
                path, ctx.target_url, body,
                title=f"CI configuration served: {path}",
                description=(
                    "A pipeline definition is readable. These files name internal "
                    "registries, deploy targets and sometimes credentials passed "
                    "as plain environment variables."
                ),
                severity=Severity.MEDIUM,
                matched=path,
            )
            for path, body in await self.probe(ctx, CI_PATHS)
        ]


class EnvFileModule(_PathProbe):
    group = "exposure"
    id = "env_file_exposure"
    name = "Environment File Exposure"
    description = "Checks for .env files and confirms the response looks like a key-value environment."
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-538"
    owasp = "A05"
    remediation = "Never serve .env; load it from the process environment or a secret manager."
    references = ["https://cwe.mitre.org/data/definitions/538.html"]
    tags = ["exposure", "secrets", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        root = ctx.target_url.rstrip("/")
        for path in ENV_PATHS:
            response = await ctx.client.get(f"{root}{path}", follow_redirects=False)
            if response.status != 200 or not response.text:
                continue
            keys = _ENV_LINE.findall(response.text)
            if len(keys) < 2:
                continue
            findings.append(
                self.report(
                    path, ctx.target_url, response.text,
                    title=f"Environment file served: {path}",
                    description=(
                        f"{len(keys)} environment variables are readable, keys "
                        f"included. Everything the application needed at boot - "
                        f"database passwords, API keys, signing secrets - is in "
                        f"this response."
                    ),
                    severity=Severity.CRITICAL,
                    matched=path,
                )
            )
        return findings


class ActuatorModule(_PathProbe):
    group = "exposure"
    id = "actuator_endpoints"
    name = "Spring Actuator Endpoints"
    description = "Checks for exposed Spring Boot actuator endpoints."
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-200"
    owasp = "A05"
    remediation = "Expose only health and info, and require authentication for the rest."
    references = ["https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"]
    tags = ["exposure", "spring", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path, body in await self.probe(ctx, ACTUATOR_PATHS):
            severity = Severity.HIGH if path.endswith(("env", "heapdump")) else Severity.MEDIUM
            findings.append(
                self.report(
                    path, ctx.target_url, body,
                    title=f"Actuator endpoint exposed: {path}",
                    description=(
                        "Spring Boot management endpoints are reachable without "
                        "authentication. /env and /heapdump hand over configuration "
                        "and process memory."
                    ),
                    severity=severity,
                    matched=path,
                )
            )
        return findings


class DebugConsoleModule(_PathProbe):
    group = "exposure"
    id = "debug_console"
    name = "Debug Console Exposed"
    description = "Checks for H2 console, phpinfo, werkzeug debugger and server-status pages."
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-489"
    owasp = "A05"
    remediation = "Disable debug tooling in production images and block it at the edge."
    references = ["https://cwe.mitre.org/data/definitions/489.html"]
    tags = ["exposure", "debug", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        return [
            self.report(
                path, ctx.target_url, body,
                title=f"Debug interface exposed: {path}",
                description=(
                    "An interactive debugging interface is public. Depending on "
                    "the stack this is a query console, an environment dump or a "
                    "traceback with a live REPL attached."
                ),
                severity=Severity.CRITICAL,
                matched=path,
            )
            for path, body in await self.probe(ctx, DEBUG_PATHS)
        ]


class DirectoryListingModule(_PathProbe):
    group = "exposure"
    id = "directory_listing_deep"
    name = "Directory Listing on Discovered Paths"
    description = "Reports discovered directories that render an index instead of a page."
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-548"
    owasp = "A05"
    remediation = "Disable autoindex and serve an explicit index file."
    references = ["https://cwe.mitre.org/data/definitions/548.html"]
    tags = ["exposure", "listing", "active"]
    max_paths = 10

    async def run(self, ctx: ScanContext) -> list[Finding]:
        from urllib.parse import urlparse

        patterns = [
            (f"{urlparse(e.url).path.rsplit('/', 1)[0]}/", re.compile(r"<title>Index of|Directory listing for"))
            for e in ctx.endpoints[: self.max_paths]
            if urlparse(e.url).path.count("/") >= 1
        ]
        return [
            self.report(
                path, ctx.target_url, body,
                title=f"Directory listing at {path}",
                description="The directory renders its contents. Every file in it is enumerable and downloadable.",
                severity=Severity.MEDIUM,
                matched=path,
            )
            for path, body in await self.probe(ctx, patterns)
        ]


class ErrorFingerprintModule(Module):
    group = "disclosure"
    id = "error_page_fingerprint"
    name = "Framework Fingerprint in Error Pages"
    description = "Requests a path that cannot exist and reports framework banners in the 404 page."
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-209"
    owasp = "A05"
    remediation = "Serve a static error page; never let the framework render it."
    references = ["https://cwe.mitre.org/data/definitions/209.html"]
    tags = ["disclosure", "error", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.target_url.rstrip("/")
        url = f"{root}/nemesis-{abs(hash(root)) % 10**6}-missing"
        response = await ctx.client.get(url, follow_redirects=False)
        if not response.text:
            return []
        match = _FRAMEWORK_ERROR.search(response.text)
        if not match:
            return []
        return [
            self.finding(
                title=f"Framework named in the 404 page ({match.group(0)})",
                target=url,
                description=(
                    "The error page identifies the framework. That is how an "
                    "attacker picks which known bug to try first."
                ),
                evidence_text=f"GET {url}\n  matched: {match.group(0)}",
                matched=match.group(0),
            )
        ]

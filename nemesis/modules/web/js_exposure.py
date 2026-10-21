"""What a shipped front end tells the world: keys, sources and sitemaps."""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Patterns that are specific enough to be a finding rather than a hunch.
_KEY_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("Stripe secret key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("SendGrid key", re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}")),
]

#: Paths that a robots file disallows and that nobody should be able to fetch.
_SENSITIVE = re.compile(
    r"(admin|backup|config|private|internal|staging|debug|\.git|db|sql|dump|secret)",
    re.IGNORECASE,
)


class SecretsInJavascriptModule(Module):
    """Scan served JavaScript for credentials the build should have removed."""

    group = "disclosure"

    id = "secrets_in_javascript"
    name = "Secrets in Client-Side JavaScript"
    description = (
        "Reads every script the crawler fetched and reports credential "
        "patterns that belong on a server, not in a bundle."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.PASSIVE
    cwe = "CWE-798"
    owasp = "A07"
    remediation = (
        "Never ship a secret to a browser. Rotate anything that already was, "
        "then inject server-side only."
    )
    references = ["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"]
    tags = ["secrets", "javascript", "passive"]

    def _scripts(self, ctx: ScanContext) -> list:
        out = []
        for response in ctx.responses:
            url = getattr(response, "url", "") or ""
            text = getattr(response, "text", "") or ""
            if not text:
                continue
            if urlparse(url).path.endswith((".js", ".mjs", ".jsx")) or "javascript" in str(
                getattr(response, "headers", {})
            ).lower():
                out.append(response)
        return out

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for response in self._scripts(ctx):
            text = response.text or ""
            for label, pattern in _KEY_PATTERNS:
                for match in pattern.finditer(text):
                    value = match.group(0)
                    if value in seen:
                        continue
                    seen.add(value)
                    findings.append(
                        self.finding(
                            title=f"{label} in {getattr(response, 'url', 'script')}",
                            target=getattr(response, "url", ctx.target_url),
                            description=(
                                f"A {label} was found in JavaScript served to the "
                                f"browser. Anyone who loads the page has it."
                            ),
                            evidence_text=(
                                f"GET {getattr(response, 'url', '')}\n"
                                f"  {label}: {value[:12]}...{value[-4:]}"
                            ),
                            matched=value[:8] + "...",
                            kind=label,
                        )
                    )
        return findings


class SourceMapModule(Module):
    """A published .map hands back the original source, comments included."""

    group = "disclosure"

    id = "source_map_exposure"
    name = "Source Map Exposed"
    description = (
        "Requests the source map for each script the crawler fetched and "
        "reports the ones that return original sources."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-540"
    owasp = "A05"
    remediation = "Do not publish .map files in production, or gate them behind authentication."
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]
    tags = ["disclosure", "javascript", "active"]

    max_maps: int = 6

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        scripts: list[str] = []
        for response in ctx.responses:
            url = getattr(response, "url", "") or ""
            if urlparse(url).path.endswith((".js", ".mjs")) and url not in scripts:
                scripts.append(url)

        for script in scripts[: self.max_maps]:
            map_url = f"{script}.map"
            response = await ctx.client.get(map_url, follow_redirects=False)
            if response.status != 200 or not response.text:
                continue
            try:
                document = json.loads(response.text)
            except (ValueError, TypeError):
                continue
            if not isinstance(document, dict) or "mappings" not in document:
                continue
            sources = document.get("sources") or []
            findings.append(
                self.finding(
                    title=f"Source map published: {map_url}",
                    target=map_url,
                    description=(
                        f"The build shipped its source map, which reconstructs "
                        f"{len(sources)} original file(s) - internal paths, "
                        f"comments and logic included."
                    ),
                    evidence_text=(
                        f"GET {map_url}\n"
                        f"  sources: {sources[:5]}"
                    ),
                    matched="mappings present",
                    source_count=len(sources),
                )
            )
        return findings


class RobotsDisclosureModule(Module):
    """robots.txt is a list of the paths somebody wanted hidden."""

    group = "exposure"

    id = "robots_disclosure"
    name = "Sensitive Paths in robots.txt"
    description = (
        "Reads robots.txt, requests the disallowed paths that look sensitive, "
        "and reports the ones the server actually serves."
    )
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.DISCLOSURE
    capability = Capability.HTTP
    cwe = "CWE-200"
    owasp = "A05"
    remediation = (
        "Do not rely on robots.txt for secrecy; require authentication on the "
        "paths it names."
    )
    references = ["https://www.rfc-editor.org/rfc/rfc9309"]
    tags = ["exposure", "active"]

    max_paths: int = 10

    async def run(self, ctx: ScanContext) -> list[Finding]:
        root = ctx.target_url.rstrip("/")
        response = await ctx.client.get(f"{root}/robots.txt", follow_redirects=False)
        if response.status != 200 or not response.text:
            return []

        disallowed = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line.lower().startswith("disallow:"):
                continue
            path = line.split(":", 1)[1].strip()
            if path and path != "/" and _SENSITIVE.search(path):
                disallowed.append(path)
        disallowed = disallowed[: self.max_paths]

        findings: list[Finding] = []
        reachable: list[str] = []
        for path in disallowed:
            probe = await ctx.client.get(urljoin(root + "/", path.lstrip("/")), follow_redirects=False)
            if probe.status == 200:
                reachable.append(path)
        if reachable:
            findings.append(
                self.finding(
                    title="robots.txt lists paths that are publicly served",
                    target=f"{root}/robots.txt",
                    description=(
                        f"{len(reachable)} disallowed path(s) answer with 200. The "
                        f"file is a map for anyone crawling the site: it names the "
                        f"areas worth looking at first."
                    ),
                    evidence_text=(
                        f"GET {root}/robots.txt\n"
                        "  reachable: " + ", ".join(reachable)
                    ),
                    matched=", ".join(reachable)[:200],
                    paths=reachable,
                )
            )
        return findings

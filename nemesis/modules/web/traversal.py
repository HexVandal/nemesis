"""Path traversal, directory listing and exposed file modules."""

from __future__ import annotations

from urllib.parse import urljoin

from ...crawler.parser import EXPOSED_PATHS
from ...knowledge.signatures import DIRECTORY_LISTING_SIGNATURES, match_signatures
from ...models import Capability, Category, Confidence, Finding, Severity
from ...verify.verifier import score_disclosure
from ..base import Module, ScanContext
from ..http_helper import HttpModule


class PathTraversalModule(HttpModule):
    """Detect local file inclusion through directory traversal."""
    group = "traversal"

    id = "path_traversal"
    name = "Path Traversal / Local File Inclusion"
    description = (
        "Attempts to read well-known system files through traversal sequences "
        "and reports only when the file content actually appears."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.TRAVERSAL
    cwe = "CWE-22"
    owasp = "A01"
    tags = ["traversal", "lfi", "active"]
    remediation = (
        "Resolve user-supplied paths against a fixed base directory and reject "
        "any input containing path separators or '..'."
    )
    references = [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://portswigger.net/web-security/file-path-traversal",
    ]
    max_params = 18
    max_payloads = 12

    #: Files whose content is unmistakable when disclosed.
    _TARGET_FILES = [
        ("../../../../../../etc/passwd", "root:x:0:0"),
        ("....//....//....//....//etc/passwd", "root:x:0:0"),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:x:0:0"),
        ("..%252f..%252f..%252fetc%252fpasswd", "root:x:0:0"),
        ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
        ("/etc/passwd", "root:x:0:0"),
        ("file:///etc/passwd", "root:x:0:0"),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        if not targets:
            return findings

        for target in targets:
            for payload, marker in self._TARGET_FILES:
                delta = await self.probe(ctx, target, payload)
                confidence, reason = score_disclosure(delta, marker)
                if confidence != Confidence.CONFIRMED:
                    continue
                findings.append(
                    self.finding(
                        title=f"Path traversal in parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} allows "
                            f"local files to be read. {reason}."
                        ),
                        confidence=confidence,
                        evidence_text=(
                            f"Payload: {payload}\n"
                            f"Probe  : {delta.probe.summary()}\n"
                            f"Reason : {reason}"
                        ),
                        matched=payload,
                        parameter=target.param,
                    )
                )
                break
            if len(findings) >= 20:
                break
        return findings


class DirectoryListingModule(Module):
    """Detect directory listings exposed by the web server."""
    group = "traversal"

    id = "directory_listing"
    name = "Directory Listing Enabled"
    description = "Detects autoindex-style directory listings that expose file names."
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.PASSIVE
    cwe = "CWE-548"
    owasp = "A05"
    tags = ["disclosure", "config", "passive"]
    remediation = (
        "Disable directory indexing (`autoindex off` in nginx, `Options -Indexes` "
        "in Apache)."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for response in ctx.responses:
            if not response.ok:
                continue
            hits = match_signatures(response.text, DIRECTORY_LISTING_SIGNATURES)
            if not hits:
                continue
            label, matched = hits[0]
            findings.append(
                self.finding(
                    title="Directory listing is enabled",
                    target=response.url,
                    description=(
                        f"{response.url} returns a directory index ({label}). Any file "
                        "in that directory can be enumerated and downloaded."
                    ),
                    evidence_text=f"GET {response.url}\n{matched[:200]}",
                    matched=matched,
                )
            )
        return findings


class ExposedFilesModule(HttpModule):
    """Look for sensitive files and directories left in the web root."""
    group = "exposure"

    id = "exposed_files"
    name = "Exposed Sensitive Files"
    description = (
        "Probes for version control directories, environment files, database "
        "dumps, backup archives and other artefacts that should never be served."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    cwe = "CWE-538"
    owasp = "A05"
    tags = ["disclosure", "exposure", "active"]
    remediation = (
        "Remove these files from the web root, block access to dotfiles and "
        "backup extensions at the web server, and never commit secrets to VCS."
    )
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]
    max_params = 0  # this module does not use parameters

    #: Paths that are especially damaging when readable.
    _HIGH_VALUE = {
        "/.env": Severity.CRITICAL,
        "/.git/config": Severity.CRITICAL,
        "/.git/HEAD": Severity.HIGH,
        "/id_rsa": Severity.CRITICAL,
        "/wp-config.php.bak": Severity.CRITICAL,
        "/dump.sql": Severity.CRITICAL,
        "/database.sql": Severity.CRITICAL,
        "/config.php.bak": Severity.HIGH,
        "/.npmrc": Severity.CRITICAL,
        "/.pypirc": Severity.CRITICAL,
    }

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        base = ctx.target_url.rstrip("/") + "/"
        seen: set[str] = set()

        for path in EXPOSED_PATHS:
            if path in seen:
                continue
            seen.add(path)
            url = urljoin(base, path.lstrip("/"))
            if not ctx.scope.allows(url):
                continue
            response = await ctx.client.get(url)
            if response.status != 200 or not response.ok:
                continue
            if not response.text.strip():
                continue
            # A 200 that is really a soft-404 is a classic false positive.
            if _looks_like_soft_404(response, ctx):
                continue

            severity = self._HIGH_VALUE.get(path, Severity.MEDIUM)
            findings.append(
                self.finding(
                    title=f"Exposed file: {path}",
                    target=url,
                    description=(
                        f"{url} is publicly readable and returned {response.length} "
                        "bytes. If it contains credentials or source code, this is a "
                        "critical exposure."
                    ),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"GET {url} -> {response.status} ({response.length} bytes)\n"
                        f"{response.text[:1500]}"
                    ),
                    matched=path,
                )
            )
            if len(findings) >= 40:
                break
        return findings


def _looks_like_soft_404(response, ctx: ScanContext) -> bool:
    """Heuristic: does this 200 actually look like a not-found page?"""
    text = response.text[:4000].lower()
    markers = ["404", "not found", "page doesn't exist", "does not exist"]
    if not any(m in text for m in markers):
        return False
    # Compare with a known-missing path on the same host.
    for other in ctx.responses:
        if other.status == 404 and abs(other.length - response.length) < 50:
            return True
    return False

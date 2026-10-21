"""Example plugin: a local, non-invasive check.

Copy this file, rename it, change the ``id`` and the logic, and nemesis
will pick it up on the next run. Nothing needs to be registered anywhere.

Run it with::

    nemesis scan https://app.example.com
"""

from __future__ import annotations

from nemesis.models import Capability, Category, Confidence, Finding, Severity
from nemesis.modules.base import Module, ScanContext


class VerboseServerBannerModule(Module):
    """Flags servers that advertise their exact version in a banner."""

    id = "verbose_server_banner"
    name = "Verbose Server Banner"
    description = (
        "Detects Server or X-Powered-By headers that disclose the exact "
        "software version, which lets an attacker match known CVEs directly."
    )
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.PASSIVE
    group = "headers"
    tags = ["banner", "disclosure", "version"]
    cwe = "CWE-200"
    owasp = "A05"
    remediation = (
        "Suppress the version in the Server header and remove the "
        "X-Powered-By header at the web server or reverse proxy."
    )

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        # A banner is a property of the *origin*, not of each URL. Reporting
        # it once per page would bury the interesting findings in noise, so
        # collect the affected URLs and report once.
        affected: dict[tuple[str, str], list[str]] = {}

        for response in ctx.responses:
            for header in ("server", "x-powered-by", "x-aspnet-version"):
                value = response.header(header)
                if not value:
                    continue
                # A bare product name is fine; a version is not.
                if not any(char.isdigit() for char in value):
                    continue
                affected.setdefault((header, value), []).append(response.url)
                break

        for (header, value), urls in affected.items():
            origin = urls[0].split("/")[0]
            findings.append(
                self.finding(
                    title=f"Version disclosed in the {header} header",
                    target=f"{origin}/",
                    description=(
                        f"The {header} header reports '{value}', which "
                        f"discloses the exact running version. It was present "
                        f"on {len(urls)} response(s)."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_text=f"{header}: {value}\nSeen on {len(urls)} response(s)",
                    matched=value[:120],
                    remediation=self.remediation,
                )
            )
        return findings

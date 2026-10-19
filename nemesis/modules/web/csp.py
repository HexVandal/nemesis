"""Content Security Policy analysis.

Reports the gaps in a policy rather than deviations from the spec: a
policy that is merely unusual is not a finding, a policy that does not stop
an attack is.
"""

from __future__ import annotations

from ...knowledge.csp import analyse, parse_policy
from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

_SEVERITY = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class CspAnalyzerModule(Module):
    """Parses the Content-Security-Policy and reports what it fails to stop."""

    group = "headers"
    id = "csp_analyzer"
    name = "Content Security Policy Analysis"
    description = (
        "Parses the Content-Security-Policy, resolves its directives, and "
        "reports the gaps that matter: unsafe-inline, unsafe-eval, "
        "wildcards, data: in script-src, and missing frame-ancestors and "
        "object-src."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-1021"
    owasp = "A05"
    tags = ["csp", "headers", "xss", "policy"]
    remediation = (
        "Tighten the policy: remove 'unsafe-inline' and 'unsafe-eval', "
        "replace wildcards with an explicit allowlist, and add "
        "frame-ancestors and object-src 'none'."
    )
    references = [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        "https://portswigger.net/web-security/cross-site-scripting/content-security-policy",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for response in ctx.responses:
            header = response.header("content-security-policy")
            if not header:
                continue

            policy = parse_policy(header)
            for gap in analyse(policy):
                key = (gap.directive, gap.kind)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    self.finding(
                        title=gap.title,
                        target=response.url,
                        description=(
                            f"{gap.detail} The policy in force on "
                            f"{response.url} is: {header[:300]}"
                        ),
                        severity=_SEVERITY.get(gap.severity, Severity.LOW),
                        confidence=Confidence.HIGH,
                        evidence_text=(
                            f"URL      : {response.url}\n"
                            f"Policy   : {header}\n"
                            f"Directives:\n"
                            + "\n".join(
                                f"  {d.name} {' '.join(d.sources)}".rstrip()
                                for d in policy.directives
                            )
                            + f"\nGap      : {gap.detail}"
                        ),
                        matched=gap.kind,
                        remediation=gap.remediation,
                    )
                )
        return findings

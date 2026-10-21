"""Browser policy: who may read the response, what may run, what may be used."""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import make_marker

_SENSITIVE_FEATURES = ("camera", "microphone", "geolocation", "usb", "payment")


def _header(response, name: str) -> str:
    for key, value in getattr(response, "headers", {}).items():
        if key.lower() == name.lower():
            return value
    return ""


class CorsOriginReflectionModule(Module):
    """Reflecting any Origin is not a wildcard, but it is worse in one way.

    ``*`` cannot be combined with credentials; a reflected origin can. This
    check sends an origin that cannot exist and looks for it coming back.
    """

    group = "config"
    id = "cors_origin_reflection"
    name = "CORS Reflects Arbitrary Origin"
    description = "Sends a unique Origin and reports the endpoints that echo it back."
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-942"
    owasp = "A05"
    remediation = "Compare Origin against an allowlist; never echo it."
    references = ["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"]
    tags = ["cors", "browser", "active"]

    max_targets: int = 4

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        marker = f"https://{make_marker('cors')}.invalid"
        for endpoint in ctx.endpoints[: self.max_targets]:
            response = await ctx.client.get(
                endpoint.url, headers={"Origin": marker}, follow_redirects=False
            )
            allow_origin = _header(response, "access-control-allow-origin")
            if not allow_origin or marker not in allow_origin:
                continue
            credentials = _header(response, "access-control-allow-credentials")
            findings.append(
                self.finding(
                    title="CORS reflects an arbitrary Origin",
                    target=endpoint.url,
                    description=(
                        "The response echoes the Origin we sent and "
                        + ("permits credentials. Any site can read authenticated "
                           "responses from this endpoint."
                           if credentials.lower() == "true"
                           else "allows it explicitly. Any site can read this "
                                "endpoint's responses on the user's behalf.")
                    ),
                    severity=Severity.HIGH if credentials.lower() == "true" else Severity.MEDIUM,
                    evidence_text=(
                        f"GET {endpoint.url}\n"
                        f"  Origin: {marker}\n"
                        f"  Access-Control-Allow-Origin: {allow_origin}\n"
                        f"  Access-Control-Allow-Credentials: {credentials or '-'}"
                    ),
                    matched=allow_origin,
                    credentials=credentials or "",
                )
            )
        return findings


class CspReportOnlyModule(Module):
    """Report-only means nothing is blocked. It is a log, not a control."""

    group = "headers"
    id = "csp_report_only"
    name = "CSP Is Report-Only"
    description = "Reports pages that send a CSP in report-only mode with no enforcing policy."
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-693"
    owasp = "A05"
    remediation = "Promote the policy to Content-Security-Policy once the reports are clean."
    references = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy-Report-Only"]
    tags = ["csp", "headers", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()
        for response in ctx.responses:
            enforcing = _header(response, "content-security-policy")
            report_only = _header(response, "content-security-policy-report-only")
            url = getattr(response, "url", ctx.target_url)
            if not report_only or enforcing or url in reported:
                continue
            reported.add(url)
            findings.append(
                self.finding(
                    title="CSP enforced in report-only mode",
                    target=url,
                    description=(
                        "A policy is present but only reports. No violation is "
                        "blocked, so the page is as exposed as one with no CSP - "
                        "the difference is that the team has telemetry."
                    ),
                    evidence_text=f"GET {url}\n  {report_only[:200]}",
                    matched=report_only[:120],
                )
            )
        return findings


class PermissionsPolicyModule(Module):
    """Which powerful browser features this page can reach."""

    group = "headers"
    id = "permissions_policy_gaps"
    name = "Permissions-Policy Missing or Permissive"
    description = "Reports pages with no Permissions-Policy, or one that grants sensitive features to all."
    severity = Severity.LOW
    confidence = Confidence.CONFIRMED
    category = Category.CONFIG
    capability = Capability.PASSIVE
    cwe = "CWE-693"
    owasp = "A05"
    remediation = "Send Permissions-Policy and disable features the page does not use."
    references = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"]
    tags = ["headers", "privacy", "passive"]

    _WILDCARD = re.compile(r"(camera|microphone|geolocation|usb|payment)\s*=\s*\*", re.IGNORECASE)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()
        for response in ctx.responses:
            url = getattr(response, "url", ctx.target_url)
            if url in reported:
                continue
            reported.add(url)
            policy = _header(response, "permissions-policy")
            if policy:
                match = self._WILDCARD.search(policy)
                if not match:
                    continue
                findings.append(
                    self.finding(
                        title=f"Permissions-Policy grants {match.group(1)} to every origin",
                        target=url,
                        description=(
                            "The policy sets a sensitive feature to *, so any "
                            "frame the page embeds can use it."
                        ),
                        evidence_text=f"GET {url}\n  {policy[:200]}",
                        matched=match.group(0),
                    )
                )
                continue
            findings.append(
                self.finding(
                    title="No Permissions-Policy header",
                    target=url,
                    description=(
                        "The page sends no Permissions-Policy, so embedded frames "
                        "may request the camera, microphone, geolocation and "
                        "payment APIs by default."
                    ),
                    evidence_text=f"GET {url}\n  Permissions-Policy: absent",
                    matched="header absent",
                )
            )
        return findings[:10]

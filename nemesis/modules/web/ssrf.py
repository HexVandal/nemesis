"""Server-side request forgery detection."""

from __future__ import annotations

from ...knowledge.signatures import SSRF_PAYLOADS
from ...models import Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule

#: Responses that prove the server fetched a loopback address.
_LOOPBACK_SIGNATURES = [
    (r"redis|redis_version|\+OK", "Redis"),
    (r"SSH-2\.0-OpenSSH", "OpenSSH"),
    (r"^\*?\s*HTTP/1\.[01]\s+\d{3}", "HTTP service"),
    (r"\"error\"\s*:\s*\"index not found\"", "Elasticsearch"),
    (r"^EPLD", "PostgreSQL"),
    (r"^220", "SMTP"),
    (r"^\\x00\\x00\\x00", "MySQL handshake"),
]

#: Cloud metadata endpoints that prove a successful SSRF.
_METADATA_MARKERS = [
    "ami-id",
    "instance-id",
    "AccessKeyId",
    "Metadata",
    "computeMetadata",
    "latest/meta-data",
    "projectId",
]


class SsrfModule(HttpModule):
    """Detect server-side request forgery by making the server fetch loopback."""
    group = "ssrf"

    id = "ssrf"
    name = "Server-Side Request Forgery"
    description = (
        "Supplies URLs pointing at loopback, link-local and cloud metadata "
        "addresses and reports when the server's response proves it fetched "
        "the resource itself."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.SSRF
    cwe = "CWE-918"
    owasp = "A10"
    tags = ["ssrf", "active", "cloud"]
    remediation = (
        "Validate outbound URLs against an allowlist of permitted hosts, resolve "
        "the hostname and reject private, loopback and link-local addresses, and "
        "re-check after every redirect."
    )
    references = [
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://portswigger.net/web-security/ssrf",
    ]
    max_params = 18
    max_payloads = 12

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        if not targets:
            return findings

        for target in targets:
            for payload in SSRF_PAYLOADS[: self.max_payloads]:
                delta = await self.probe(ctx, target, payload, _LOOPBACK_SIGNATURES)

                reason = ""
                if delta.new_signatures:
                    reason = (
                        f"the server returned a {_LOOPBACK_SIGNATURES and delta.new_signatures[0][0]} "
                        "response that the baseline did not"
                    )
                else:
                    for marker in _METADATA_MARKERS:
                        if marker.lower() in delta.probe.text.lower() and marker.lower() not in delta.baseline.text.lower():
                            reason = f"cloud metadata key {marker!r} appeared in the response"
                            break

                if not reason:
                    continue

                findings.append(
                    self.finding(
                        title=f"Server-side request forgery in parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} causes the "
                            f"server to issue requests to attacker-chosen URLs - "
                            f"{reason}."
                        ),
                        severity=self.severity,
                        confidence=Confidence.CONFIRMED,
                        evidence_text=(
                            f"Payload: {payload}\n"
                            f"Baseline: {delta.baseline.summary()}\n"
                            f"Probe   : {delta.probe.summary()}\n"
                            f"Reason  : {reason}"
                        ),
                        matched=payload,
                        parameter=target.param,
                    )
                )
                break
            if len(findings) >= 20:
                break
        return findings

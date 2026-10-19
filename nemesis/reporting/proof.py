"""Proof extraction.

A nemesis finding records an *experiment*, not a request: the baseline
request, the payload, the probe request, and what changed between them.
That is richer than a raw request, and it is what makes the finding
trustworthy - but a person reading a disclosure report or a write-up
wants the request they can paste into a proxy.

This module turns one into the other, so every generator presents the
proof the same way.
"""

from __future__ import annotations

from ..models import Finding

#: HTTP methods, used to pull the method and URL out of a recorded probe.
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")

#: The markers of a recorded proof line.
BASELINE_MARKER = "Baseline:"
PAYLOAD_MARKER = "Payload"
PROBE_MARKER = "Probe"


def request_evidence(finding: Finding) -> str:
    """The request that proves the finding, as an HTTP request line.

    The probe line of a recorded proof is the request that carried the
    payload, which is exactly what a triager needs to reproduce the
    issue.
    """
    if finding.evidence.request:
        return finding.evidence.request

    text = finding.evidence.response or ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(PROBE_MARKER):
            continue
        _, _, rest = stripped.partition(":")
        parts = rest.strip().split()
        if len(parts) >= 3 and parts[1].upper() in HTTP_METHODS:
            method, url = parts[1].upper(), parts[2]
            return f"{method} {url} HTTP/1.1"

    if finding.evidence.matched:
        return (
            f"GET {finding.target} HTTP/1.1\n"
            f"\n# payload: {finding.evidence.matched[:200]}"
        )
    return f"GET {finding.target} HTTP/1.1"


def proof_lines(finding: Finding) -> list[str]:
    """The recorded proof, split into its parts.

    Returns an empty list when the finding carries no proof.
    """
    text = finding.evidence.response or ""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        for marker in (BASELINE_MARKER, PAYLOAD_MARKER, PROBE_MARKER, "Delta"):
            if stripped.startswith(marker):
                lines.append(stripped)
                break
    return lines

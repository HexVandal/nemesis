"""The claims inside a token, as opposed to the signature on it.

``jwt_weakness`` owns the signature. These two own what the token promises:
who it is for, and how long it lives.
"""

from __future__ import annotations

import time

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .jwt import decode_token, tokens_from_response


def _tokens(ctx: ScanContext) -> list[tuple[str, dict, dict]]:
    found: list[tuple[str, dict, dict]] = []
    seen: set[str] = set()
    for response in ctx.responses[:400]:
        for token in tokens_from_response(response):
            if token in seen:
                continue
            seen.add(token)
            decoded = decode_token(token)
            if decoded:
                header, payload, _ = decoded
                found.append((token, header, payload))
    return found


class JwtAudienceModule(Module):
    """A token with no audience is a token any service will accept."""

    group = "auth"
    id = "jwt_audience_missing"
    name = "JWT Without Audience Claim"
    description = "Decodes issued tokens and reports the ones that name no audience."
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.PASSIVE
    cwe = "CWE-287"
    owasp = "A07"
    remediation = "Set aud on issue and reject a token whose aud is not this service."
    references = ["https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3"]
    tags = ["jwt", "claims", "passive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for token, header, payload in _tokens(ctx):
            if "aud" in payload:
                continue
            findings.append(
                self.finding(
                    title="Issued JWT names no audience",
                    target=ctx.target_url,
                    description=(
                        "The token carries no aud claim. Any service that shares "
                        "the signing key will accept it as its own, so a token "
                        "minted for a low-value app works on the high-value one."
                    ),
                    evidence_text=(
                        f"token   : [REDACTED]\n"
                        f"header  : {header}\n"
                        f"claims  : {sorted(payload)}"
                    ),
                    matched="aud absent",
                )
            )
            break
        return findings


class JwtLifetimeModule(Module):
    """A token that outlives the password reset cannot be revoked."""

    group = "auth"
    id = "jwt_lifetime_excessive"
    name = "JWT Lifetime Excessive"
    description = "Reports tokens valid for more than 30 days, or with no expiry at all."
    severity = Severity.MEDIUM
    confidence = Confidence.CONFIRMED
    category = Category.AUTH
    capability = Capability.PASSIVE
    cwe = "CWE-613"
    owasp = "A07"
    remediation = "Keep access tokens short-lived, and pair them with a revocable refresh token."
    references = ["https://cwe.mitre.org/data/definitions/613.html"]
    tags = ["jwt", "claims", "passive"]

    window: int = 30 * 24 * 3600

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        now = int(time.time())
        for token, header, payload in _tokens(ctx):
            if "exp" not in payload:
                # Covered by jwt_weakness; do not double-report.
                continue
            try:
                expires = int(payload["exp"])
            except (TypeError, ValueError):
                continue
            lifetime = expires - int(payload.get("iat", now))
            if lifetime <= self.window:
                continue
            findings.append(
                self.finding(
                    title=f"JWT valid for {lifetime // 86400} days",
                    target=ctx.target_url,
                    description=(
                        f"The token lives for {lifetime // 86400} days. A stolen "
                        f"token cannot be revoked without a server-side denylist, "
                        f"so a session stolen today works for months."
                    ),
                    evidence_text=(
                        f"token    : [REDACTED]\n"
                        f"lifetime : {lifetime} seconds\n"
                        f"expires  : {expires}"
                    ),
                    matched=f"{lifetime // 86400} days",
                    lifetime_days=lifetime // 86400,
                )
            )
            break
        return findings

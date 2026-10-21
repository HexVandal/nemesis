"""JSON Web Token weaknesses.

A JWT is a claim the server is supposed to verify. These are the ways it
usually doesn't:

* ``alg: none`` - the token is unsigned and the server accepts it anyway
* an empty signature segment
* the signing key is a word you could guess (``secret``, ``changeme``)
* ``kid`` is used to build a file path or a query, so it can be steered

Every finding here is proven against the token the application actually
issued. Cracking ``HS256`` is not a heuristic: if the HMAC of the header and
payload, under the recovered key, equals the signature on the wire, the key is
the key. There is nothing left to argue about.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: A JWT is three base64url segments; the first always decodes to JSON
#: containing "alg", which is why it almost always starts with ``eyJ``.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")

#: Keys that real applications have actually shipped.
WEAK_SECRETS = (
    "secret",
    "password",
    "changeme",
    "change-me",
    "123456",
    "12345678",
    "jwt",
    "jwtsecret",
    "secretkey",
    "secret-key",
    "supersecret",
    "your-256-bit-secret",
    "your_jwt_secret",
    "admin",
    "test",
    "dev",
    "development",
    "key",
    "private",
    "token",
)

#: Anything here inside ``kid`` means the value is being used as a path or a
#: query fragment rather than an opaque identifier.
_KID_DANGER = ("../", "..\\", "/", "\\", "|", ";", "'", '"', "\x00")


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_token(token: str) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """Return (header, payload, signature) or None if this is not a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts[2]


def recover_secret(header: dict[str, Any], payload: dict[str, Any], signature: str) -> str:
    """Return the HMAC key if one of the common secrets produced this signature."""
    alg = str(header.get("alg", "")).upper()
    if alg not in ("HS256", "HS384", "HS512"):
        return ""
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    signing_input = (
        b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    )
    for candidate in WEAK_SECRETS:
        computed = hmac.new(candidate.encode(), signing_input.encode(), digest).digest()
        if hmac.compare_digest(b64url_encode(computed), signature):
            return candidate
    return ""


def tokens_in(text: str) -> list[str]:
    return _JWT_RE.findall(text or "")


def tokens_from_response(response: Any) -> list[str]:
    """Every token a response carried, in headers and in the body."""
    found: list[str] = []
    for name, value in (getattr(response, "headers", {}) or {}).items():
        if str(name).lower() in ("set-cookie", "authorization", "x-auth-token", "x-access-token"):
            found.extend(tokens_in(str(value)))
    found.extend(tokens_in(getattr(response, "text", "") or ""))
    return found


class JwtWeaknessModule(Module):
    """Reports JWTs that are unsigned, insecurely signed or path-steerable."""

    group = "auth"
    id = "jwt_weakness"
    name = "JSON Web Token Weaknesses"
    description = (
        "Decodes every JWT the application issues and checks the things an "
        "attacker checks: is it signed at all, is the key a dictionary word, "
        "can 'kid' be steered, does it ever expire."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.AUTH
    capability = Capability.PASSIVE
    cwe = "CWE-347"
    owasp = "A02"
    tags = ["jwt", "auth", "token", "crypto", "session"]
    remediation = (
        "Verify the signature with a key you control and reject 'none'. Never "
        "accept the algorithm from the token header - pin it server-side. "
        "Treat 'kid' as an opaque index, never as a path. Use a 256-bit random "
        "secret, rotate it, and always set 'exp'."
    )
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
        "https://cwe.mitre.org/data/definitions/347.html",
    ]

    max_tokens = 40

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for response in list(getattr(ctx, "responses", []) or [])[:400]:
            for token in tokens_from_response(response):
                if token in seen:
                    continue
                seen.add(token)
                if len(seen) > self.max_tokens:
                    break
                finding = self._inspect(ctx, token)
                if finding is not None:
                    findings.append(finding)
        return findings

    # -- analysis ---------------------------------------------------------
    def _inspect(self, ctx: ScanContext, token: str) -> Finding | None:
        decoded = decode_token(token)
        if decoded is None:
            return None
        header, payload, signature = decoded
        alg = str(header.get("alg", "")).lower()

        if alg == "none" or not signature:
            return self._finding(
                ctx,
                title="Unsigned JWT accepted by the application",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                detail=(
                    "The token carries alg='none' or an empty signature, and the "
                    "application issued it. Any client can rewrite the claims - "
                    "including the subject and any role - and the server has no "
                    "way to tell."
                ),
                token=token,
                header=header,
                payload=payload,
            )

        secret = recover_secret(header, payload, signature)
        if secret:
            return self._finding(
                ctx,
                title=f"JWT signed with a guessable secret ('{secret}')",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                detail=(
                    f"The {alg.upper()} signature was reproduced exactly with the "
                    f"key '{secret}'. This is not a guess about key strength: the "
                    f"HMAC matches, so the key is known, and a forged token with "
                    f"any claims will verify as legitimate."
                ),
                token=token,
                header=header,
                payload=payload,
                secret=secret,
            )

        kid = str(header.get("kid", ""))
        if kid and any(char in kid for char in _KID_DANGER):
            return self._finding(
                ctx,
                title="JWT 'kid' header is used as a path",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                detail=(
                    f"The token's kid is '{kid}'. A kid containing path "
                    f"separators or traversal means the claim is being turned "
                    f"into a filesystem or query lookup, which is how an "
                    f"attacker points verification at a key they control."
                ),
                token=token,
                header=header,
                payload=payload,
            )

        if "exp" not in payload:
            return self._finding(
                ctx,
                title="JWT has no expiry",
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                detail=(
                    "The token carries no 'exp' claim, so a stolen token stays "
                    "valid until the signing key is rotated."
                ),
                token=token,
                header=header,
                payload=payload,
            )
        return None

    def _finding(
        self,
        ctx: ScanContext,
        *,
        title: str,
        severity: Severity,
        confidence: Confidence,
        detail: str,
        token: str,
        header: dict[str, Any],
        payload: dict[str, Any],
        **extra: Any,
    ) -> Finding:
        shown = token if len(token) <= 220 else token[:217] + "..."
        return self.finding(
            title=title,
            target=ctx.target_url,
            description=detail,
            severity=severity,
            confidence=confidence,
            evidence_text=(
                f"token   : {shown}\n"
                f"header  : {json.dumps(header, sort_keys=True)}\n"
                f"payload : {json.dumps(payload, sort_keys=True)}"
            ),
            matched=json.dumps(header, sort_keys=True),
            **extra,
        )


__all__ = ["JwtWeaknessModule", "decode_token", "recover_secret", "tokens_in"]

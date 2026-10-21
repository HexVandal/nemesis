"""Checks that need to make the application *do* something.

Both of these send traffic a passive scan never sends: one hammers a login
form, the other writes into a form. Neither reports unless it observed the
effect with its own eyes.
"""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import make_marker

#: Fields that identify the person logging in.
_IDENTITY_HINTS = ("user", "email", "login", "account", "name", "phone")
#: Fields that carry the secret.
_SECRET_HINTS = ("pass", "secret", "pin", "otp", "code")

#: What a server says when it is deliberately slowing an attacker down. A
#: 429 or 423 is checked separately; this catches the soft lockouts.
_THROTTLE = re.compile(
    r"(too many (?:attempts|requests|tries)|rate[ -]?limit|ratelimit|slow down|"
    r"try again (?:later|in \d+)|captcha|account (?:is )?(?:locked|temporarily blocked)|"
    r"locked out|temporarily disabled)",
    re.IGNORECASE,
)


def _has_secret_field(form) -> bool:
    return any(
        any(hint in name.lower() for hint in _SECRET_HINTS) for name in form.raw_fields
    )


def _identity_field(form) -> str | None:
    for name in form.raw_fields:
        if any(hint in name.lower() for hint in _IDENTITY_HINTS):
            return name
    return None


def _secret_field(form) -> str | None:
    for name in form.raw_fields:
        if any(hint in name.lower() for hint in _SECRET_HINTS):
            return name
    return None


class RateLimitingModule(Module):
    """Establish whether a login form stops guessing after a few failures.

    The check uses identities that cannot exist (``nms_probe@invalid.test``),
    so it never burns a real account, and it stops the moment the application
    shows any sign of throttling. The absence of that sign after every
    attempt is the finding - which is why it is reported as medium
    confidence, not as proof of exploitability.
    """

    group = "auth"

    id = "rate_limiting"
    name = "Missing Login Throttling"
    description = (
        "Submits a short series of failed logins for accounts that cannot "
        "exist and reports the form that never slows down, locks out or "
        "issues a challenge."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-307"
    owasp = "A07"
    remediation = (
        "Rate-limit by account and by source, add an escalating delay, and "
        "require a challenge after repeated failures."
    )
    references = ["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"]
    tags = ["auth", "brute-force", "active"]

    #: Deliberately small: enough to prove the absence of a limit, few enough
    #: that a real login form is not meaningfully stressed.
    attempts: int = 8
    max_forms: int = 2

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        candidates = [f for f in ctx.forms if _has_secret_field(f)][: self.max_forms]

        for form in candidates:
            identity = _identity_field(form)
            secret = _secret_field(form)
            if not identity or not secret:
                continue

            tried = 0
            throttled = False
            for index in range(self.attempts):
                body = {
                    key: (value if value else "nemesis")
                    for key, value in form.fields.items()
                }
                body[identity] = f"nms_probe_{index}@invalid.test"
                body[secret] = f"wrong-{index}-{make_marker('pw')}"
                response = await ctx.client.post(
                    form.action, data=body, follow_redirects=False
                )
                tried += 1
                if response.status in (423, 429) or (
                    response.text and _THROTTLE.search(response.text)
                ):
                    throttled = True
                    break

            if throttled or tried < self.attempts:
                continue

            findings.append(
                self.finding(
                    title=f"No throttling on {form.action} after {tried} failed logins",
                    target=form.action,
                    description=(
                        f"{tried} consecutive failed logins for distinct, "
                        f"non-existent accounts were all answered normally - no "
                        f"429, no lockout, no challenge. An attacker can guess "
                        f"passwords as fast as the network allows."
                    ),
                    evidence_text=(
                        f"POST {form.action}\n"
                        f"  attempts      : {tried}\n"
                        f"  identity field: {identity}\n"
                        f"  throttled     : no"
                    ),
                    matched="no 429/423 and no lockout text in any response",
                    attempts=tried,
                )
            )
        return findings


class StoredXssModule(Module):
    """Write a marker into a form and look for it again, unescaped, later.

    Reflected XSS is already covered. This checks the other half: whether the
    value survives a round trip through storage and is rendered as markup on
    a different page. It is destructive - it writes a row - so it runs only
    with ``--allow-destructive``.
    """

    group = "injection"

    id = "stored_xss"
    name = "Stored Cross-Site Scripting"
    description = (
        "Submits a unique marker into ordinary text fields, then re-reads the "
        "page and its neighbours looking for the marker served back as markup."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.XSS
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-79"
    owasp = "A03"
    remediation = (
        "Encode on output, in the context the value lands in, and validate on "
        "input as a second layer."
    )
    references = ["https://owasp.org/www-community/attacks/xss/"]
    tags = ["xss", "stored", "destructive"]

    max_forms: int = 3
    max_fields: int = 2

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms[: self.max_forms]:
            if form.method.lower() != "post" or _has_secret_field(form):
                continue
            text_fields = [
                name
                for name in form.raw_fields
                if not any(hint in name.lower() for hint in _SECRET_HINTS)
            ][: self.max_fields]
            if not text_fields:
                continue

            marker = make_marker("xss")
            payload = f"<{marker}>"
            body = {
                key: (value if value else "nemesis") for key, value in form.fields.items()
            }
            for field in text_fields:
                body[field] = payload

            submitted = await ctx.client.post(
                form.action, data=body, follow_redirects=False
            )
            if submitted.status >= 400:
                continue

            # The submission response itself is reflection, not storage. Look
            # at the page the form came from, and the action's own GET view.
            for page in {form.source_url, form.action, ctx.target_url}:
                if not page:
                    continue
                response = await ctx.client.get(page, follow_redirects=False)
                if payload in response.text:
                    findings.append(
                        self.finding(
                            title=f"Stored XSS on {form.action} via '{field}'",
                            target=form.action,
                            description=(
                                f"The value submitted for '{field}' was later served "
                                f"back from {page} with its angle brackets intact, so "
                                f"the browser parses it as markup. This persists: it "
                                f"reached a different request than the one that "
                                f"carried it."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            evidence_text=(
                                f"POST {form.action}  {field}={payload}\n"
                                f"GET  {page}\n"
                                f"  body contains: {payload}"
                            ),
                            matched=payload,
                            field=field,
                            rendered_on=page,
                        )
                    )
                    break
        return findings

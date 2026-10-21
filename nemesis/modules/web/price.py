"""Price tampering in carts, payment gateways and product pages.

The weakness: the client sends the price, and the server believes it.

This module is deliberately narrow and evidence-driven. It does not report a
parameter merely because the response changed - a changed response proves
nothing about money. It reports when a number the *attacker chose* reappears
as a total the server is prepared to charge, which is the actual proof of a
tampered price.

Three contexts are covered:

* **product page** - a priced value in the query string (``?price=``)
* **cart / checkout** - hidden inputs in a POST form (``price``, ``qty``)
* **payment gateway** - a JSON body sent to an API endpoint (``{"amount":...}``)

Anything that echoes the attacker's number back as the amount due is reported
as CRITICAL and confirmed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule, ParamTarget, build_form_body, replace_param

#: Parameters that carry money or quantity. A match here is the *candidate*
#: signal; it is never the finding on its own.
PRICE_PARAMS = {
    "price", "unit_price", "unitprice", "amount", "total", "subtotal",
    "line_total", "grand_total", "cost", "fee", "shipping", "tax",
    "discount", "coupon", "voucher", "credit", "balance", "payable",
    "qty", "quantity", "units", "seats", "item_price", "sale_price",
}

#: Parameters where the interesting movement is *downwards* (a cheaper price).
PRICE_LIKE = {
    "price", "unit_price", "unitprice", "amount", "total", "subtotal",
    "line_total", "grand_total", "cost", "fee", "shipping", "tax", "payable",
    "item_price", "sale_price",
}

#: Quantity and discount parameters move the total by arithmetic, not by
#: replacing it, so they get their own payloads.
QTY_LIKE = {"qty", "quantity", "units", "seats"}
DISCOUNT_LIKE = {"discount", "coupon", "voucher", "credit"}

#: Payloads, per parameter class.
PRICE_PAYLOADS = ("-1", "0", "0.01", "1")
QTY_PAYLOADS = ("-1", "0", "999999")
DISCOUNT_PAYLOADS = ("100", "999", "-50")

#: A number as it appears in a rendered page or a JSON document.
_NUMBER = r"-?\d[\d,\s]*(?:\.\d{1,2})?"

#: "total ... 100.00", "amount due: $100.00", `"total": 100.0`
_LABELLED = re.compile(
    r"(?i)\b(total|amount|price|subtotal|cost|due|charge|balance|payable|"
    r"discount|savings)\b[^0-9\-]{0,24}(" + _NUMBER + r")"
)

_URL_IS_GATEWAY = re.compile(
    r"(?i)/(pay|payment|payments|billing|purchase|transaction|charge|gateway)"
)

_URL_IS_CART = re.compile(
    r"(?i)/(cart|basket|checkout|order|orders|bag)"
)


@dataclass
class _Observation:
    """What the server said the price was."""

    label: str
    value: float
    raw: str

    def __str__(self) -> str:
        return f"{self.label}={self.raw}"


def _typed(value: str) -> object:
    """Turn a numeric string into a JSON number, leaving anything else alone."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return value
    return int(number) if number.is_integer() else number


def _to_float(raw: str) -> float | None:
    cleaned = raw.replace(",", "").replace(" ", "")
    try:
        return float(cleaned)
    except ValueError:
        return None


def labelled_numbers(text: str) -> list[_Observation]:
    """Every money-shaped labelled number in *text*, in document order."""
    found: list[_Observation] = []
    for match in _LABELLED.finditer(text or ""):
        value = _to_float(match.group(2))
        if value is None:
            continue
        found.append(_Observation(match.group(1).lower(), value, match.group(2).strip()))
    return found[:12]


def _total_of(observations: list[_Observation]) -> _Observation | None:
    """The most total-shaped observation, preferring 'total' then 'amount'."""
    if not observations:
        return None
    for preferred in ("total", "amount", "payable", "due", "balance", "subtotal", "price", "cost"):
        for obs in observations:
            if obs.label == preferred:
                return obs
    return observations[0]


class PriceTamperingModule(HttpModule):
    """Proves whether the server accepts a client-supplied price."""

    group = "business"
    id = "price_tampering"
    name = "Price Tampering (cart, checkout, gateway)"
    description = (
        "Sends a price, quantity or amount the client should not control - "
        "negative, zero, a penny - and reports it when the server's own "
        "total follows the attacker's number."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-472"
    owasp = "A04"
    tags = ["business-logic", "price", "ecommerce", "payment", "tampering"]
    remediation = (
        "Never accept a monetary amount from the client. Send a product or "
        "line-item identifier and a quantity, then recompute price, tax, "
        "shipping and discount server-side from authoritative data. Validate "
        "that the amount charged equals the amount recomputed before capture."
    )
    references = [
        "https://owasp.org/www-community/attacks/Web_Parameter_Tampering",
        "https://portswigger.net/web-security/logic-flaws/examples",
        "https://cwe.mitre.org/data/definitions/472.html",
    ]

    #: Deliberately conservative: money bugs are rare and expensive, so the
    #: module spends its request budget on the parameters that carry them.
    max_params = 25
    max_payloads = 4

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[tuple[str, str]] = set()

        for target in self._price_targets(ctx):
            key = (target.url, target.param.lower())
            if key in reported:
                continue

            payloads = self._payloads_for(target.param)
            if not payloads:
                continue

            found = None
            for fetcher, label in self._fetchers(target):
                found = await self._attempt(ctx, target, fetcher, payloads, label)
                if found is not None:
                    break
            if found is None:
                continue

            (
                severity,
                confidence,
                reason,
                payload,
                probe_total,
                context,
                base_total,
            ) = found
            findings.append(
                self.finding(
                    title=(
                        f"Price tampering: '{target.param}' changes the "
                        f"amount due ({context})"
                    ),
                    target=target.url,
                    description=(
                        f"The {context} accepted a client-supplied "
                        f"'{target.param}'. Sending '{payload}' moved the "
                        f"server's own figure from {base_total} to "
                        f"{probe_total}. {reason} An attacker can set what "
                        f"they are charged."
                    ),
                    severity=severity,
                    confidence=confidence,
                    evidence_text=(
                        f"{target.method} {target.url}\n"
                        f"  parameter : {target.param}\n"
                        f"  baseline  : {target.param}={self._original_value(target)!r} "
                        f"-> {base_total}\n"
                        f"  tampered  : {target.param}={payload!r} -> {probe_total}\n"
                        f"  encoding  : {context}"
                    ),
                    matched=f"{target.param}={payload} -> {probe_total}",
                    context=context,
                    baseline=str(base_total),
                    tampered=str(probe_total),
                    payload=payload,
                )
            )
            reported.add(key)

        return findings

    # -- target discovery -------------------------------------------------
    def _price_targets(self, ctx: ScanContext) -> list[ParamTarget]:
        """Form targets first: a checkout form is a stronger signal than a URL."""
        targets: list[ParamTarget] = []
        seen: set[tuple[str, str]] = set()

        for form in ctx.forms:
            for name in form.raw_fields:
                lowered = name.lower()
                if lowered not in PRICE_PARAMS:
                    continue
                key = (form.action, lowered)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    ParamTarget(
                        url=form.action,
                        param=name,
                        method=form.method.upper() or "POST",
                        fields=dict(form.fields),
                    )
                )

        for endpoint in ctx.endpoints:
            for name in endpoint.params:
                lowered = name.lower()
                if lowered not in PRICE_PARAMS:
                    continue
                key = (endpoint.url, lowered)
                if key in seen:
                    continue
                seen.add(key)
                targets.append(ParamTarget(url=endpoint.url, param=name, method="GET"))

        return targets[: self.max_params]

    @staticmethod
    def _payloads_for(param: str) -> tuple[str, ...]:
        lowered = param.lower()
        if lowered in QTY_LIKE:
            return QTY_PAYLOADS
        if lowered in DISCOUNT_LIKE:
            return DISCOUNT_PAYLOADS
        if lowered in PRICE_LIKE:
            return PRICE_PAYLOADS
        return ()

    @staticmethod
    def _context_of(target: ParamTarget) -> str:
        url = target.url or ""
        if target.method == "GET":
            return "product page"
        if _URL_IS_GATEWAY.search(url):
            return "payment gateway"
        if _URL_IS_CART.search(url):
            return "cart / checkout"
        return "form submission"

    @staticmethod
    def _original_value(target: ParamTarget) -> str:
        if target.fields and target.param in target.fields:
            return str(target.fields[target.param])
        return ""

    # -- requests ---------------------------------------------------------
    async def _fetch_original(self, ctx: ScanContext, target: ParamTarget):
        """Send the page exactly as the browser would have sent it."""
        original = self._original_value(target)
        if original:
            return await self._fetch(ctx, target, original)
        return await self._fetch(ctx, target, "1")

    async def _fetch(self, ctx: ScanContext, target: ParamTarget, value: str):
        """One request with the parameter overridden, never following redirects."""
        try:
            if target.method == "GET" or not target.fields:
                return await ctx.client.get(
                    replace_param(target.url, target.param, value),
                    follow_redirects=False,
                )
            body = build_form_body(target.fields, (target.param, value))
            return await ctx.client.post(
                target.url, data=body, follow_redirects=False
            )
        except Exception:  # a dead endpoint is not a finding
            return None

    def _fetchers(self, target: ParamTarget):
        """Encodings to try. A real gateway ignores form encoding entirely."""
        yield self._fetch, ""
        if target.method != "GET" and _URL_IS_GATEWAY.search(target.url or ""):
            yield self._fetch_json, " (JSON)"

    async def _fetch_json(self, ctx: ScanContext, target: ParamTarget, value: str):
        """Send the same parameters as a JSON body, numbers typed as numbers."""
        payload: dict[str, object] = {}
        for key, original in (target.fields or {}).items():
            payload[key] = _typed(original)
        payload[target.param] = _typed(value)
        try:
            return await ctx.client.post(
                target.url, json=payload, follow_redirects=False
            )
        except Exception:
            return None

    async def _attempt(self, ctx, target, fetcher, payloads, label):
        """Try every payload through one encoding; return the first proof.

        The baseline is fetched with the *same* encoding as the probe. A
        baseline obtained by form-POST and a probe sent as JSON are not
        comparable, and comparing them is how scanners write fiction.
        """
        baseline = await fetcher(ctx, target, self._original_value(target) or "1")
        if baseline is None or baseline.status >= 400:
            return None
        base_total = _total_of(labelled_numbers(baseline.text))
        if base_total is None:
            return None

        for payload in payloads[: self.max_payloads]:
            probe = await fetcher(ctx, target, payload)
            if probe is None or probe.status >= 400:
                continue
            probe_total = _total_of(labelled_numbers(probe.text))
            if probe_total is None:
                continue
            verdict = self._judge(payload, base_total, probe_total)
            if verdict is None:
                continue
            severity, confidence, reason = verdict
            return (
                severity,
                confidence,
                reason,
                payload,
                probe_total,
                self._context_of(target) + label,
                base_total,
            )
        return None

    # -- the judgement ----------------------------------------------------
    @staticmethod
    def _judge(
        payload: str,
        base: _Observation,
        probe: _Observation,
    ) -> tuple[Severity, Confidence, str] | None:
        """Decide whether the movement of the number proves tampering."""
        try:
            sent = float(payload)
        except ValueError:
            return None

        same = abs(probe.value - base.value) < 0.005
        if same:
            return None

        # The server adopted the attacker's number as its own total.
        if abs(probe.value - sent) < 0.005 and abs(base.value - sent) >= 0.005:
            return (
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"The server echoed the submitted value '{payload}' back as its own {probe.label}.",
            )

        # A total that went negative or free.
        if probe.value <= 0 < base.value:
            return (
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                "The server produced a non-positive amount due.",
            )

        # A total that collapsed by more than half.
        if base.value > 0 and probe.value < base.value * 0.5:
            return (
                Severity.HIGH,
                Confidence.HIGH,
                f"The {probe.label} fell by more than half in response to a "
                f"client-supplied value.",
            )

        # It moved, but downwards only slightly: still client-controlled money,
        # just weaker evidence.
        if probe.value < base.value:
            return (
                Severity.MEDIUM,
                Confidence.MEDIUM,
                f"The {probe.label} moved with a client-supplied value.",
            )
        return None


__all__ = ["PriceTamperingModule", "labelled_numbers"]

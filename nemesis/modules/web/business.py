"""Business logic and workflow vulnerabilities.

These are the weaknesses a payload scanner cannot find, because there is no
payload - the attack is a *valid* request. A price the client controls, a
discount applied twice, a step that is skipped, a one-time action that can
be replayed.

What nemesis can do is narrow the search enormously: find the parameters
that carry a quantity, a price, an amount, a step, a state or a discount,
and test whether the server's response depends on them in a way that lets
the client drive the outcome.
"""

from __future__ import annotations

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule

#: Parameter names that usually carry a business decision.
BUSINESS_PARAMS = (
    "price", "amount", "quantity", "qty", "count", "total", "discount",
    "coupon", "promo", "voucher", "credit", "balance", "value", "cost",
    "fee", "shipping", "tax", "points", "score", "level", "rank",
    "quantity", "units", "seats", "days", "duration", "plan", "tier",
    "role", "admin", "is_admin", "verified", "approved", "state", "status",
    "step", "stage", "phase", "page", "skip", "bypass", "override",
    "limit", "offset", "id", "uid", "user_id", "account_id", "order_id",
)

#: Values that a client might try in place of a price or a quantity.
NEGATIVE_VALUES = ("-1", "-100", "-0.01", "-99999")
#: Values that a client might try in place of a limit or a count.
BOUNDARY_VALUES = ("0", "1", "999999999", "2147483647", "-0")


class BusinessLogicModule(HttpModule):
    """Probes parameters that carry a business decision."""

    group = "business"
    id = "business_logic"
    name = "Business Logic Vulnerabilities"
    description = (
        "Probes the parameters that carry a commercial decision - price, "
        "quantity, discount, role, state, step - and reports the ones the "
        "server appears to take from the client without validation."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-840"
    owasp = "A04"
    tags = ["business-logic", "workflow", "logic", "tampering"]
    remediation = (
        "Never trust a client-supplied price, quantity, role or state. "
        "Recompute the value server-side, validate the state transition, "
        "and make one-time actions non-replayable."
    )
    references = [
        "https://owasp.org/www-community/attacks/Business_logic_vulnerabilities",
        "https://portswigger.net/web-security/logic-flaws",
    ]

    max_params = 20
    max_payloads = 6

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        reported: set[str] = set()

        for target in self.collect_targets(ctx):
            if target.param.lower() not in BUSINESS_PARAMS:
                continue
            if target.param.lower() in reported:
                continue

            for payload in NEGATIVE_VALUES + BOUNDARY_VALUES:
                delta = await self.probe(ctx, target, payload)
                # A size gate misses the most common tampering shape: `1`
                # replaced by `-1` leaves the page almost exactly the same
                # length. If the injected value itself appears in the new
                # body and not in the old one, the server is repeating
                # attacker input back as its own number.
                echoed = payload in delta.probe.text and payload not in delta.baseline.text
                if not delta.has_behaviour_change and not echoed:
                    continue
                if (
                    delta.status_delta == 0
                    and abs(delta.length_ratio - 1.0) < 0.3
                    and not echoed
                ):
                    continue

                reported.add(target.param.lower())
                findings.append(
                    self.finding(
                        title=f"Client-controlled business parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"The parameter '{target.param}' changed the "
                            f"server's behaviour when it was set to "
                            f"'{payload}'. Parameters that carry a price, a "
                            f"quantity, a limit or a role are usually "
                            f"supposed to be recomputed or validated "
                            f"server-side; when the response follows the "
                            f"client's value, the client is making the "
                            f"decision."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        evidence_text=delta.describe(),
                        matched=f"{target.param}={payload}",
                    )
                )
                break
        return findings

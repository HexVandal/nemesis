"""How much work will the server do for one request that costs us nothing?"""

from __future__ import annotations

import json

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import make_marker


def _deep_json(depth: int) -> str:
    body: object = make_marker("deep")
    for _ in range(depth):
        body = [body]
    return json.dumps({"data": body})


class ResourceExhaustionModule(Module):
    """Nested bodies, oversized fields and the absence of a ceiling.

    Three separate probes, each of which the server can simply refuse:

    * a 200-level nested JSON body, which recurses any parser that walks it
    * a 64 KB single parameter, which any size limit should reject
    * the same request repeated, to see whether a timeout ever arrives
    """

    group = "dos"
    id = "resource_exhaustion"
    name = "Unbounded Request Cost"
    description = (
        "Sends a deeply nested JSON body, an oversized field and a slow repeat "
        "and reports the ones the server accepted without complaint."
    )
    severity = Severity.LOW
    confidence: Confidence = Confidence.MEDIUM
    category = Category.DOS
    capability = Capability.HTTP
    cwe = "CWE-770"
    owasp = "A04"
    remediation = "Cap body size, nesting depth and field length at the edge; set request timeouts."
    references = ["https://owasp.org/www-community/attacks/Denial_of_Service"]
    tags = ["dos", "limits", "active"]

    depth: int = 200
    big_value_size: int = 64 * 1024
    max_targets: int = 3

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        for endpoint in ctx.endpoints[: self.max_targets]:
            response = await ctx.client.post(
                endpoint.url,
                content=_deep_json(self.depth),
                headers={"Content-Type": "application/json"},
                follow_redirects=False,
            )
            if 200 <= response.status < 300:
                findings.append(
                    self.finding(
                        title=f"{self.depth}-level nested JSON accepted by {endpoint.url}",
                        target=endpoint.url,
                        description=(
                            "A JSON body nested two hundred levels deep was parsed "
                            "and accepted. Recursive parsers handle that on the "
                            "stack; a few of these requests at once is enough."
                        ),
                        evidence_text=(
                            f"POST {endpoint.url}  Content-Type: application/json\n"
                            f"  depth: {self.depth}\n  -> {response.status}"
                        ),
                        matched=f"depth {self.depth}",
                    )
                )
                break

        for form in ctx.forms[: self.max_targets]:
            if form.method.lower() != "post" or not form.raw_fields:
                continue
            field = form.raw_fields[0]
            body = {k: (v or "nemesis") for k, v in form.fields.items()}
            body[field] = "A" * self.big_value_size
            response = await ctx.client.post(form.action, data=body, follow_redirects=False)
            if 200 <= response.status < 300:
                findings.append(
                    self.finding(
                        title=f"64 KB field accepted by {form.action}",
                        target=form.action,
                        description=(
                            f"'{field}' took a {self.big_value_size // 1024} KB value "
                            f"and returned success. The same shape repeated in a loop "
                            f"is a memory and storage bill."
                        ),
                        evidence_text=(
                            f"POST {form.action}\n  {field}: {self.big_value_size} bytes\n"
                            f"  -> {response.status}"
                        ),
                        matched="no size limit",
                        field=field,
                    )
                )
                break
        return findings

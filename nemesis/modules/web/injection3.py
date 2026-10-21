"""Injection into things that are not SQL, and a token that never expires."""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import HttpModule

_XPATH_SIGNATURES = re.compile(
    r"(XPathException|SimpleXMLElement|DOMXPath|lxml\.etree\.XPathError|"
    r"XPath syntax error|Invalid expression|unterminated (?:literal|string)|"
    r"xmlXPathCompOpEval|System\.Xml\.XPath)",
    re.IGNORECASE,
)

#: The server-side include directive. If the engine runs it, it replaces the
#: comment with the value - a fact that needs no interpretation.
_SSI_PAYLOAD = '<!--#printenv -->'
_SSI_SIGNATURES = re.compile(
    r"(DOCUMENT_ROOT|SERVER_SOFTWARE|SCRIPT_FILENAME|HTTP_USER_AGENT|"
    r"UNIQUE_ID=|REMOTE_ADDR|SERVER_ADDR)",
)


class XPathInjectionModule(HttpModule):
    group = "injection"

    id = "xpath_injection"
    name = "XPath Injection"
    description = (
        "Sends XPath metacharacters and reports the parameters that produce an "
        "XPath parser error the baseline did not."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-643"
    owasp = "A03"
    remediation = (
        "Use parameterised XPath (XPathVariableResolver) or escape quotes and "
        "brackets before the expression is built."
    )
    references = ["https://owasp.org/www-community/attacks/XPATH_Injection"]
    tags = ["xpath", "injection", "active"]

    max_params: int = 12
    max_payloads: int = 4
    payloads = ["'", "x' or '1'='1", "1)]|//*|//*[(", "count(//*)>0 or '"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx):
            for payload in self.payloads[: self.max_payloads]:
                baseline = await self.fetch(ctx, target, self.benign_equivalent(payload))
                probe = await self.fetch(ctx, target, payload)
                match = _XPATH_SIGNATURES.search(probe.text or "")
                if not match:
                    continue
                if baseline.text and _XPATH_SIGNATURES.search(baseline.text):
                    continue
                findings.append(
                    self.finding(
                        title=f"XPath injection in '{target.param}'",
                        target=target.url,
                        description=(
                            f"'{target.param}' reaches an XPath expression: the "
                            f"payload produced '{match.group(0)}', which the "
                            f"length-matched baseline did not. The query tree can "
                            f"be rewritten to return nodes it was not meant to."
                        ),
                        evidence_text=(
                            f"{target.method} {target.url}\n"
                            f"  {target.param} = {payload!r}\n"
                            f"  signature    : {match.group(0)}"
                        ),
                        matched=match.group(0),
                        param=target.param,
                    )
                )
                break
        return findings


class SsiInjectionModule(HttpModule):
    group = "injection"

    id = "ssi_injection"
    name = "Server-Side Includes Injection"
    description = (
        "Submits an SSI directive and reports the pages where the server "
        "executed it and printed its own environment back."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-97"
    owasp = "A03"
    remediation = "Turn off SSI for user-influenced content, or stop echoing it into a page."
    references = ["https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection"]
    tags = ["ssi", "injection", "active"]

    max_params: int = 10
    max_payloads: int = 2

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx):
            baseline = await self.fetch(ctx, target, self.benign_equivalent(_SSI_PAYLOAD))
            probe = await self.fetch(ctx, target, _SSI_PAYLOAD)
            match = _SSI_SIGNATURES.search(probe.text or "")
            if not match:
                continue
            if baseline.text and _SSI_SIGNATURES.search(baseline.text):
                continue
            findings.append(
                self.finding(
                    title=f"SSI injection in '{target.param}'",
                    target=target.url,
                    description=(
                        "The server executed an SSI directive supplied through "
                        f"'{target.param}' and printed '{match.group(0)}' into the "
                        "response. Any SSI directive works from here, including "
                        "one that reads a file or runs a command."
                    ),
                    evidence_text=(
                        f"{target.method} {target.url}\n"
                        f"  {target.param} = {_SSI_PAYLOAD}\n"
                        f"  leaked       : {match.group(0)}"
                    ),
                    matched=match.group(0),
                    param=target.param,
                )
            )
        return findings


_TOKEN_FIELDS = ("csrf", "token", "_token", "authenticity_token", "nonce")


class CsrfTokenReuseModule(Module):
    """A token that works twice is not a token.

    Submitting the same token to the same action twice tests the property that
    actually matters; presence is already covered by ``csrf_missing``.
    """

    group = "auth"

    id = "csrf_token_reuse"
    name = "CSRF Token Reuse"
    description = (
        "Submits a form twice with an identical token and reports the actions "
        "that accept both."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.AUTH
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-352"
    owasp = "A01"
    remediation = (
        "Bind each token to the session, consume it on use, and issue a fresh "
        "one per form render."
    )
    references = ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"]
    tags = ["csrf", "session", "destructive"]

    _FAILURE = re.compile(r"(invalid|expired|already used|csrf|token mismatch)", re.IGNORECASE)

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms[:3]:
            token_field = None
            for name in form.raw_fields:
                if any(hint in name.lower() for hint in _TOKEN_FIELDS):
                    token_field = name
                    break
            if not token_field:
                continue
            token = form.fields.get(token_field, "")
            if not token:
                continue

            body = {k: (v or "nemesis") for k, v in form.fields.items()}
            first = await ctx.client.post(form.action, data=body, follow_redirects=False)
            second = await ctx.client.post(form.action, data=body, follow_redirects=False)
            if first.status >= 400 or second.status >= 400:
                continue
            if self._FAILURE.search(second.text or ""):
                continue

            findings.append(
                self.finding(
                    title=f"CSRF token accepted twice on {form.action}",
                    target=form.action,
                    description=(
                        f"The {token_field} value was accepted by two consecutive "
                        f"submissions. A token that is not consumed cannot stop a "
                        f"replayed request, so the protection is decorative."
                    ),
                    evidence_text=(
                        f"POST {form.action} (twice, same {token_field})\n"
                        f"  first  status: {first.status}\n"
                        f"  second status: {second.status}"
                    ),
                    matched=token_field,
                    field=token_field,
                )
            )
        return findings

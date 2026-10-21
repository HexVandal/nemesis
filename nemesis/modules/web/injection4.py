"""Parser edges: expression languages, duplicate keys, pathological input."""

from __future__ import annotations

import time

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule, replace_param


class ElInjectionModule(HttpModule):
    """Expression languages evaluate arithmetic too - and say so out loud."""

    group = "injection"
    id = "expression_language_injection"
    name = "Expression Language Injection"
    description = (
        "Sends SpEL, OGNL, MVEL and JSP-EL arithmetic and reports the pages "
        "where the expression was evaluated."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-917"
    owasp = "A03"
    remediation = "Never build an expression from user input; if you must, use a sandboxed context."
    references = ["https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection"]
    tags = ["injection", "el", "active"]

    max_params: int = 12
    max_payloads: int = 4
    payloads = ["${7*7}", "#{7*7}", "%{7*7}", "<%= 7*7 %>"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx):
            for payload in self.payloads[: self.max_payloads]:
                baseline = await self.fetch(ctx, target, self.benign_equivalent(payload))
                probe = await self.fetch(ctx, target, payload)
                if "49" not in (probe.text or ""):
                    continue
                if "49" in (baseline.text or ""):
                    continue
                findings.append(
                    self.finding(
                        title=f"Expression language evaluated in '{target.param}'",
                        target=target.url,
                        description=(
                            f"The payload {payload} came back as 49. The server "
                            f"evaluated it as an expression, which means the same "
                            f"parser can reach objects, not just arithmetic."
                        ),
                        evidence_text=(
                            f"{target.method} {target.url}\n"
                            f"  {target.param} = {payload}\n"
                            f"  response contains 49 where the baseline did not"
                        ),
                        matched="49",
                        param=target.param,
                    )
                )
                break
        return findings


class ParameterPollutionModule(HttpModule):
    """What happens when the same key arrives twice."""

    group = "injection"
    id = "http_parameter_pollution"
    name = "HTTP Parameter Pollution"
    description = (
        "Sends a parameter twice with different values and reports endpoints "
        "whose answer depends on which copy wins."
    )
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-235"
    owasp = "A03"
    remediation = "Reject duplicate parameters, or define precedence explicitly."
    references = ["https://owasp.org/www-community/attacks/HTTP_Parameter_Pollution"]
    tags = ["hpp", "injection", "active"]

    max_params: int = 8

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx)[: self.max_params]:
            if target.method != "GET":
                continue
            single = await self.fetch(ctx, target, "nmsfirst")
            doubled_url = (
                replace_param(target.url, target.param, "nmsfirst")
                + f"&{target.param}=nmssecond"
            )
            doubled = await ctx.client.get(doubled_url, follow_redirects=False)
            if single.status != 200 or doubled.status != 200:
                continue
            if single.text == doubled.text:
                continue
            findings.append(
                self.finding(
                    title=f"Duplicate '{target.param}' changes the response",
                    target=target.url,
                    description=(
                        "Sending the parameter twice produced a different body "
                        "than sending it once. Different layers will disagree "
                        "about which copy counts, which is how filter bypasses "
                        "are built."
                    ),
                    evidence_text=(
                        f"GET {target.url}  {target.param}=nmsfirst\n"
                        f"GET {doubled_url}\n"
                        f"  bodies differ: {len(single.text)} vs {len(doubled.text)} bytes"
                    ),
                    matched="duplicate key",
                    param=target.param,
                )
            )
        return findings
class RedosModule(HttpModule):
    """A regular expression can be a denial-of-service primitive."""

    group = "injection"
    id = "redos_probe"
    name = "ReDoS Susceptibility"
    description = (
        "Times a pathological input against a benign one and reports large "
        "slowdowns on parameters that clearly reach a matcher."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.LOW
    category = Category.DOS
    capability = Capability.HTTP
    cwe = "CWE-1333"
    owasp = "A04"
    remediation = "Bound the input, use a linear-time matcher, and set a timeout."
    references = ["https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS"]
    tags = ["dos", "regex", "active"]

    max_params: int = 6
    payload = "a" * 3000 + "!"
    #: Slowdown required before it is worth reporting: 3 s and 5x.
    floor_seconds: float = 3.0
    factor: float = 5.0

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx)[: self.max_params]:
            started = time.monotonic()
            await self.fetch(ctx, target, "a" * 3000)
            baseline = time.monotonic() - started

            started = time.monotonic()
            await self.fetch(ctx, target, self.payload)
            probe = time.monotonic() - started

            if probe < self.floor_seconds or probe < baseline * self.factor:
                continue
            findings.append(
                self.finding(
                    title=f"Pathological input slows '{target.param}' by {probe / max(baseline, 0.01):.0f}x",
                    target=target.url,
                    description=(
                        f"A 3,000-character input took {probe:.1f}s against "
                        f"{baseline:.2f}s for a benign one. That curve is a "
                        f"backtracking matcher; a handful of requests will park "
                        f"a worker."
                    ),
                    evidence_text=(
                        f"{target.method} {target.url}\n"
                        f"  benign     : {baseline:.2f}s\n"
                        f"  pathological: {probe:.2f}s"
                    ),
                    matched=f"{probe:.1f}s",
                )
            )
        return findings


class NullByteModule(HttpModule):
    """A value the filter rejected, accepted once a NUL byte is attached."""

    group = "injection"
    id = "null_byte_handling"
    name = "Null-Byte Handling"
    description = (
        "Compares a rejected value against the same value followed by a NUL "
        "and reports the pairs where only the second is accepted."
    )
    severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-158"
    owasp = "A03"
    remediation = "Reject NUL bytes outright; never pass them to a C library."
    references = ["https://cwe.mitre.org/data/definitions/158.html"]
    tags = ["injection", "nullbyte", "active"]

    max_params: int = 10

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx)[: self.max_params]:
            rejected = await self.fetch(ctx, target, "../nms_forbidden")
            accepted = await self.fetch(ctx, target, "../nms_forbidden\x00.png")
            if rejected.status < 400:
                continue
            if accepted.status >= 400 or not accepted.text:
                continue
            findings.append(
                self.finding(
                    title=f"NUL byte changes validation on '{target.param}'",
                    target=target.url,
                    description=(
                        f"The value was rejected with {rejected.status} and the same "
                        f"value with a trailing NUL returned {accepted.status}. A "
                        f"filter that truncates at NUL and a parser that does not "
                        f"disagree about what the string is."
                    ),
                    evidence_text=(
                        f"{target.method} {target.url}\n"
                        f"  control -> {rejected.status}\n"
                        f"  + NUL   -> {accepted.status}"
                    ),
                    matched="NUL accepted",
                )
            )
        return findings


class UnicodeNormalizationModule(HttpModule):
    """Observe whether the application folds Unicode before comparing."""

    group = "injection"
    id = "unicode_normalization"
    name = "Unicode Normalisation Observed"
    description = (
        "Sends a value and its full-width equivalent and reports endpoints that "
        "treat them as the same string."
    )
    severity = Severity.INFO
    confidence = Confidence.MEDIUM
    category = Category.CONFIG
    capability = Capability.HTTP
    cwe = "CWE-176"
    owasp = "A03"
    remediation = "Normalise to NFKC before any security comparison, and reject confusables in identifiers."
    references = ["https://unicode.org/reports/tr15/"]
    tags = ["unicode", "observation", "active"]

    max_params: int = 6

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self.collect_targets(ctx)[: self.max_params]:
            plain = await self.fetch(ctx, target, "admin")
            wide = await self.fetch(ctx, target, "ａｄｍｉｎ")
            if plain.status != wide.status:
                continue
            if plain.text == wide.text:
                continue
            findings.append(
                self.finding(
                    title=f"Full-width and ASCII input answered differently on '{target.param}'",
                    target=target.url,
                    description=(
                        "The ASCII and full-width forms of the same word produced "
                        "different responses, so the application is comparing after "
                        "some normalisation. Any blocklist written against ASCII "
                        "should be reviewed against its confusables."
                    ),
                    evidence_text=(
                        f"GET {target.url}  {target.param}=admin\n"
                        f"GET {target.url}  {target.param}=ａｄｍｉｎ\n"
                        f"  body lengths: {len(plain.text)} vs {len(wide.text)}"
                    ),
                    matched="normalisation observed",
                )
            )
        return findings

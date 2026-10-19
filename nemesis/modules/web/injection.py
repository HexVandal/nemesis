"""Active injection modules: SQL, XSS, command, template and NoSQL.

Every module here follows the same discipline:

1. send a benign baseline request for the parameter
2. send the same request with a payload
3. diff the two responses
4. only report when the difference is *explained*

A parameter that behaves identically with and without a payload is not a
finding, and a payload that comes back HTML-escaped is not an XSS.
"""

from __future__ import annotations

from ...knowledge.signatures import (
    COMMAND_PAYLOADS,
    COMMAND_SIGNATURES,
    NOSQL_PAYLOADS,
    SQL_ERROR_SIGNATURES,
    SQLI_PAYLOADS,
    TEMPLATE_SIGNATURES,
    XSS_PAYLOADS,
)
from ...models import Category, Confidence, Finding, Severity
from ...verify.verifier import score_blind_time, score_error_based, score_reflection
from ..base import ScanContext
from ..http_helper import HttpModule


class SqlInjectionModule(HttpModule):
    """Detect SQL injection via error signatures and behavioural differences."""
    group = "injection"

    id = "sqli"
    name = "SQL Injection"
    description = (
        "Probes parameters with SQL metacharacters and error-based, boolean and "
        "time-based payloads, then verifies the response actually changed."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    cwe = "CWE-89"
    owasp = "A03"
    tags = ["injection", "sqli", "active"]
    remediation = (
        "Use parameterised queries or prepared statements for every value that "
        "reaches a database, and never build SQL by string concatenation."
    )
    references = [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://portswigger.net/web-security/sql-injection",
    ]
    max_params = 20
    max_payloads = 14

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        if not targets:
            return findings

        for target in targets:
            async for payload, delta in self.iter_deltas(
                ctx, target, SQLI_PAYLOADS, signatures=SQL_ERROR_SIGNATURES
            ):
                confidence, reason = score_error_based(delta)

                if confidence.rank < Confidence.MEDIUM.rank:
                    continue

                # Time-based blind detection: a stable, long delay on the
                # sleep payloads is the signature of a blind SQLi.
                if "sleep" in payload.lower() or "waitfor" in payload.lower():
                    blind_confidence, blind_reason = score_blind_time(delta)
                    if blind_confidence.rank > confidence.rank:
                        confidence, reason = blind_confidence, blind_reason

                severity = self.severity if confidence == Confidence.CONFIRMED else Severity.HIGH
                findings.append(
                    self.finding(
                        title=f"SQL injection in parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} responds "
                            f"differently to SQL metacharacters. {reason}."
                        ),
                        severity=severity,
                        confidence=confidence,
                        evidence_text=(
                            f"Baseline: {delta.baseline.summary()}\n"
                            f"Payload : {payload}\n"
                            f"Probe   : {delta.probe.summary()}\n"
                            f"Delta   : status {delta.status_delta:+d}, "
                            f"length {delta.length_delta:+d} bytes "
                            f"({delta.length_ratio:.2f}x), time {delta.time_delta:+.2f}s"
                        ),
                        matched=payload,
                        parameter=target.param,
                        reason=reason,
                    )
                )
                break  # one confirmed injection per parameter is enough
            if len(findings) >= 30:
                break
        return findings


class XssModule(HttpModule):
    """Detect reflected cross-site scripting with context-aware analysis."""
    group = "injection"

    id = "xss"
    name = "Reflected Cross-Site Scripting"
    description = (
        "Injects script-bearing payloads and analyses where they land. Only "
        "reports when the payload is reflected verbatim in an executable "
        "context, so HTML-encoded reflections are not flagged."
    )
    severity = Severity.HIGH
    confidence = Confidence.CONFIRMED
    category = Category.XSS
    cwe = "CWE-79"
    owasp = "A03"
    tags = ["xss", "injection", "active"]
    remediation = (
        "Apply context-aware output encoding on every untrusted value and add a "
        "Content-Security-Policy as a second layer."
    )
    references = [
        "https://owasp.org/www-community/attacks/xss/",
        "https://portswigger.net/web-security/cross-site-scripting",
    ]
    max_params = 20
    max_payloads = 10

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        if not targets:
            return findings
        reported: set[str] = set()

        for target in targets:
            async for payload, delta in self.iter_deltas(
                ctx, target, XSS_PAYLOADS, stop_on_hit=False
            ):
                confidence, reason = score_reflection(delta)
                if confidence.rank < Confidence.MEDIUM.rank:
                    continue

                reflection = delta.reflections[0] if delta.reflections else None
                context = reflection.context.value if reflection else "unknown"

                # The same weakness across many URLs is one weakness.
                dedupe_key = f"{ctx.host}:{target.param}"
                if dedupe_key in reported:
                    break
                reported.add(dedupe_key)

                # A reflection in an error page is still unescaped output, but
                # it is far less likely to be rendered by a victim's browser.
                if not (200 <= delta.probe.status < 300) and confidence == Confidence.CONFIRMED:
                    confidence = Confidence.MEDIUM

                findings.append(
                    self.finding(
                        title=f"Reflected XSS in parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} reflects "
                            f"attacker-controlled input into a {context} context. "
                            f"{reason}."
                        ),
                        severity=self.severity if confidence == Confidence.CONFIRMED else Severity.MEDIUM,
                        confidence=confidence,
                        evidence_text=(
                            f"GET {target.url} (parameter: {target.param})\n"
                            f"Payload: {payload}\n"
                            f"Status : {delta.probe.status} | length {delta.probe.length}B\n"
                            f"Context: {context} | verbatim={reflection.verbatim if reflection else 'n/a'}"
                        ),
                        matched=payload,
                        parameter=target.param,
                        context=context,
                    )
                )
                break
            if len(findings) >= 25:
                break
        return findings


class CommandInjectionModule(HttpModule):
    """Detect OS command injection via output and timing signatures."""
    group = "injection"

    id = "command_injection"
    name = "OS Command Injection"
    description = (
        "Sends shell metacharacters and looks for command output or a delayed "
        "response that the baseline does not produce."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    cwe = "CWE-78"
    owasp = "A03"
    tags = ["injection", "rce", "active"]
    remediation = (
        "Never pass user input to a shell. Use an argument array with "
        "`subprocess.run([...], shell=False)` and validate input against an "
        "allowlist."
    )
    references = [
        "https://owasp.org/www-community/attacks/Command_Injection",
        "https://portswigger.net/web-security/os-command-injection",
    ]
    max_params = 15
    max_payloads = 12

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        if not targets:
            return findings

        for target in targets:
            async for payload, delta in self.iter_deltas(
                ctx, target, COMMAND_PAYLOADS, signatures=COMMAND_SIGNATURES
            ):
                confidence, reason = score_error_based(delta)
                if "sleep" in payload.lower():
                    blind_confidence, blind_reason = score_blind_time(delta)
                    if blind_confidence.rank > confidence.rank:
                        confidence, reason = blind_confidence, blind_reason
                if confidence.rank < Confidence.MEDIUM.rank:
                    continue

                findings.append(
                    self.finding(
                        title=f"OS command injection in parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} appears to "
                            f"pass input to a shell. {reason}."
                        ),
                        severity=self.severity if confidence == Confidence.CONFIRMED else Severity.HIGH,
                        confidence=confidence,
                        evidence_text=(
                            f"Baseline: {delta.baseline.summary()}\n"
                            f"Payload : {payload}\n"
                            f"Probe   : {delta.probe.summary()}\n"
                            f"Delta   : length {delta.length_delta:+d} bytes, "
                            f"time {delta.time_delta:+.2f}s"
                        ),
                        matched=payload,
                        parameter=target.param,
                        reason=reason,
                    )
                )
                break
            if len(findings) >= 20:
                break
        return findings


class TemplateInjectionModule(HttpModule):
    """Detect server-side template injection (SSTI)."""
    group = "injection"

    id = "template_injection"
    name = "Server-Side Template Injection"
    description = (
        "Probes for template expression evaluation across common engines "
        "(Jinja2, Twig, Freemarker, Velocity, ERB, EL)."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = Category.INJECTION
    cwe = "CWE-1336"
    owasp = "A03"
    tags = ["injection", "ssti", "active"]
    remediation = (
        "Never evaluate user input as a template. Use a logic-less template "
        "engine, or render user data as a plain string value."
    )
    references = ["https://portswigger.net/web-security/server-side-template-injection"]
    max_params = 15
    max_payloads = 10

    #: Payloads whose *evaluated* result is a recognisable value.
    _EXPRESSION_PAYLOADS = [
        ("{{7*7}}", "49"),
        ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"),
        ("#{7*7}", "49"),
        ("${{7*7}}", "49"),
        ("{{7*'7'}}", "7777777"),
        ("{{config}}", ""),
        ("{{self}}", ""),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        if not targets:
            return findings

        for target in targets:
            for payload, expected in self._EXPRESSION_PAYLOADS:
                delta = await self.probe(ctx, target, payload, TEMPLATE_SIGNATURES)

                evaluated = expected and expected in delta.probe.text
                signature_hit = bool(delta.new_signatures)

                if not (evaluated or signature_hit):
                    continue

                if evaluated:
                    confidence = Confidence.CONFIRMED
                    reason = (
                        f"the template expression {payload!r} was evaluated and the "
                        f"result {expected!r} appeared in the response"
                    )
                else:
                    confidence = Confidence.HIGH
                    label, matched = delta.new_signatures[0]
                    reason = f"a {label} error appeared only in the injected request: {matched[:120]!r}"

                findings.append(
                    self.finding(
                        title=f"Server-side template injection in '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} is evaluated "
                            f"as a template expression. {reason}."
                        ),
                        confidence=confidence,
                        evidence_text=(
                            f"Payload: {payload}\n"
                            f"Probe  : {delta.probe.summary()}\n"
                            f"Reason : {reason}"
                        ),
                        matched=payload,
                        parameter=target.param,
                        reason=reason,
                    )
                )
                break
            if len(findings) >= 20:
                break
        return findings


class NoSqlInjectionModule(HttpModule):
    """Detect NoSQL injection through operator injection."""
    group = "injection"

    id = "nosql_injection"
    name = "NoSQL Injection"
    description = (
        "Tests MongoDB-style operators such as `$ne` and `$gt` that can bypass "
        "authentication or widen query results."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.INJECTION
    cwe = "CWE-943"
    owasp = "A03"
    tags = ["injection", "nosql", "active"]
    remediation = (
        "Validate the type of every user-supplied value before it reaches the "
        "query layer, and reject objects where scalars are expected."
    )
    references = ["https://owasp.org/www-community/attacks/NoSQL_Injection"]
    max_params = 20
    max_payloads = 8

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        targets = self.collect_targets(ctx)
        if not targets:
            return findings

        for target in targets:
            for payload in NOSQL_PAYLOADS[: self.max_payloads]:
                delta = await self.probe(ctx, target, payload)
                if not delta.has_behaviour_change:
                    continue
                # A NoSQL operator must change the *shape* of the result set,
                # not merely the echoed length of the parameter. Require a
                # status change, a large structural change, or a JSON API
                # whose content changed.
                is_json = "json" in delta.probe.content_type
                structural = abs(delta.length_ratio - 1.0) >= 0.4
                if delta.status_delta == 0 and not (structural and is_json):
                    continue
                findings.append(
                    self.finding(
                        title=f"NoSQL operator injection in parameter '{target.param}'",
                        target=target.url,
                        description=(
                            f"Parameter '{target.param}' on {target.url} behaves "
                            f"differently when a NoSQL operator is supplied "
                            f"({delta.status_delta:+d} status, "
                            f"{delta.length_ratio:.2f}x length)."
                        ),
                        confidence=Confidence.MEDIUM,
                        evidence_text=(
                            f"Payload: {payload}\n"
                            f"Baseline: {delta.baseline.summary()}\n"
                            f"Probe   : {delta.probe.summary()}"
                        ),
                        matched=payload,
                        parameter=target.param,
                    )
                )
                break
            if len(findings) >= 20:
                break
        return findings

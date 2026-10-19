"""Correctness and reliability bugs.

The user asked for "any kind of bug", not just security bugs. This module
covers the classic defect patterns that static analysis can catch with high
precision and near-zero false positives.
"""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .common import relative, scan_patterns

#: (rule, regex, severity, description, remediation)
_BUG_RULES: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    (
        "Mutable default argument",
        re.compile(r"^\s*def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))"),
        Severity.HIGH,
        "A mutable default is shared across every call, so state leaks between invocations.",
        "Use `None` as the default and create the collection inside the function.",
    ),
    (
        "Bare except swallows all errors",
        re.compile(r"except\s*:\s*(?:pass|continue)?"),
        Severity.MEDIUM,
        "A bare except hides programming errors, including KeyboardInterrupt handling bugs.",
        "Catch the specific exception types you expect.",
    ),
    (
        "Comparison to None with ==",
        re.compile(r"==\s*None\b"),
        Severity.LOW,
        "Use `is None`; `==` can be overloaded and may behave unexpectedly.",
        "Use identity comparison with `is` / `is not`.",
    ),
    (
        "Comparison to True/False with ==",
        re.compile(r"==\s*(?:True|False)\b"),
        Severity.LOW,
        "Use `is True` / `is False` to compare with the singleton.",
        "Use identity comparison.",
    ),
    (
        "Exceptional catch-all return",
        re.compile(r"except\s+Exception[^\n]*:\s*\n\s*return\s+(?:None|0|\"\"|''|\{\}|\[\])"),
        Severity.MEDIUM,
        "Catching Exception and returning an empty value hides the failure from the caller.",
        "Log the exception and re-raise, or return a typed error.",
    ),
    (
        "Assert used for runtime validation",
        re.compile(r"^\s*assert\s+.*(?:status|user|token|auth|perm)"),
        Severity.LOW,
        "Assertions are removed under `python -O`, so the check disappears in production.",
        "Raise an explicit exception.",
    ),
    (
        "f-string used directly in a logger call",
        re.compile(r"\.(?:debug|info|warning|error|critical|log)\s*\(\s*f[\"']"),
        Severity.LOW,
        "The f-string is evaluated even when the log level is disabled, wasting cycles and sometimes leaking data.",
        "Use lazy `%s` or `{}` formatting in the logging call.",
    ),
    (
        "SQL string built with an f-string",
        re.compile(r"(?i)(?:execute|query|executemany)\s*\(\s*f[\"'][^\"']*\b(?:select|insert|update|delete)\b"),
        Severity.HIGH,
        "An f-string injects values straight into the SQL text.",
        "Use parameter binding: `execute(sql, params)`.",
    ),
    (
        "Floating point used for currency",
        re.compile(r"(?i)\b(?:price|amount|total|cost|balance)\s*=\s*\d+\.\d{1,2}\b"),
        Severity.MEDIUM,
        "Binary floating point cannot represent most decimal currency values exactly.",
        "Use `decimal.Decimal` for money.",
    ),
    (
        "Unbounded loop over a network call",
        re.compile(r"while\s+True\s*:\s*(?:#[^\n]*)?\n\s+(?:requests|httpx|urllib|fetch|axios)"),
        Severity.MEDIUM,
        "An infinite loop containing a network call can exhaust the connection pool.",
        "Bound the loop and add a timeout.",
    ),
    (
        "Broad exception re-raise losing the cause",
        re.compile(r"except\s+\w+Exception\s*:\s*\n\s*raise\s+\w+Error\s*\("),
        Severity.LOW,
        "Re-raising without `from` hides the original traceback.",
        "Use `raise NewError(...) from exc`.",
    ),
    (
        "Empty except block",
        re.compile(r"except[^\n]*:\s*\n\s*pass\s*$"),
        Severity.LOW,
        "The error is silently discarded, making failures very hard to diagnose.",
        "At minimum, log the error.",
    ),
    (
        "Division without a zero guard",
        re.compile(r"=\s*\w+\s*/\s*\w+\s*$"),
        Severity.INFO,
        "Division by zero raises at runtime; make sure the denominator is validated.",
        "Guard the divisor or use a safe division helper.",
    ),
    (
        "Shell command built with an f-string",
        re.compile(r"(?i)(?:subprocess\.(?:run|call|check_output|Popen)|os\.system|os\.popen)\s*\(\s*f[\"']"),
        Severity.CRITICAL,
        "Interpolating values into a command string hands the shell to the attacker.",
        "Pass an argument list instead of a formatted string.",
    ),
    (
        "Unescaped HTML built into a template",
        re.compile(r"(?i)(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=\s*[^;]*(?:params|query|search|input|user)"),
        Severity.HIGH,
        "Assigning untrusted data to innerHTML is a direct XSS sink.",
        "Use `textContent`, or sanitise the HTML first.",
    ),
]


class LogicBugsModule(Module):
    """Detect correctness and reliability defects in source code."""
    group = "code"

    id = "logic_bugs"
    name = "Correctness Bugs"
    description = (
        "Detects defect patterns that are bugs rather than vulnerabilities: "
        "mutable default arguments, swallowed exceptions, missing `is None` "
        "comparisons, float currency and unsafe interpolation."
    )
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = Category.BUG
    capability = Capability.CODE
    cwe = "CWE-670"
    owasp = "A04"
    tags = ["code", "sast", "bugs", "quality"]
    remediation = "See each finding: the fix is specific to the pattern."
    references = ["https://owasp.org/www-project-web-security-testing-guide/"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = ctx.code_path
        patterns = [(regex, rule) for rule, regex, *_ in _BUG_RULES]
        hits = scan_patterns(root, patterns, limit=300)

        by_rule = {rule: (severity, description, fix)
                   for rule, _, severity, description, fix in _BUG_RULES}

        findings: list[Finding] = []
        for hit in hits:
            severity, description, fix = by_rule[hit.rule]
            rel = relative(hit.path, root)
            findings.append(
                self.finding(
                    title=hit.rule,
                    target=rel,
                    description=f"{description} Found at {rel}:{hit.line_number}.",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence_text=f"{rel}:{hit.line_number}\n{hit.line}",
                    matched=hit.rule,
                    file=rel,
                    line=hit.line_number,
                    rule=hit.rule,
                    fix=fix,
                )
            )
        return findings

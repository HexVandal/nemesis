"""Dangerous code patterns and weak cryptography."""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .common import relative, scan_patterns

#: (rule, regex, severity, description, remediation)
_RULES: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    (
        "Command execution with shell=True",
        re.compile(r"(?i)subprocess\.(?:run|call|check_output|Popen)\s*\([^)]*shell\s*=\s*True"),
        Severity.CRITICAL,
        "The command string is built by the shell, so any metacharacter in user input becomes code execution.",
        "Pass an argument list and set `shell=False`.",
    ),
    (
        "os.system call",
        re.compile(r"\bos\.system\s*\("),
        Severity.HIGH,
        "`os.system` always invokes a shell.",
        "Use `subprocess.run([...], shell=False)`.",
    ),
    (
        "eval on runtime data",
        re.compile(r"(?<![\w.])eval\s*\("),
        Severity.HIGH,
        "`eval` executes arbitrary Python from its argument.",
        "Use `ast.literal_eval` for data, or an explicit parser.",
    ),
    (
        "exec on runtime data",
        re.compile(r"(?<![\w.])exec\s*\("),
        Severity.HIGH,
        "`exec` executes arbitrary Python from its argument.",
        "Remove dynamic execution; dispatch through an explicit mapping.",
    ),
    (
        "Unsafe YAML load",
        re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.(?:Safe|CS)Loader)"),
        Severity.HIGH,
        "`yaml.load` without a safe loader can construct arbitrary Python objects.",
        "Use `yaml.safe_load`, or `yaml.load(..., Loader=yaml.SafeLoader)`.",
    ),
    (
        "pickle deserialisation",
        re.compile(r"\b(?:pickle|cPickle|dill)\.(?:loads?|load)\s*\("),
        Severity.CRITICAL,
        "Unpickling untrusted data executes arbitrary code.",
        "Use JSON, or restrict the unpickler with `find_class`.",
    ),
    (
        "marshal deserialisation",
        re.compile(r"\bmarshal\.loads?\s*\("),
        Severity.HIGH,
        "`marshal` is not safe for untrusted input.",
        "Use JSON for interchange formats.",
    ),
    (
        "XML parsing with resolved entities",
        re.compile(r"(?i)(?:etree|minidom|sax)\.parse\w*\([^)]*\)"),
        Severity.MEDIUM,
        "`xml.etree` is reasonably safe, but `lxml` and `defusedxml` are preferable for untrusted input.",
        "Use `defusedxml.ElementTree` for untrusted XML.",
    ),
    (
        "MD5 used for passwords",
        re.compile(r"(?i)\b(?:md5|sha1)\s*\([^)]*\)"),
        Severity.MEDIUM,
        "MD5 and SHA-1 are broken for any security purpose, including password hashing.",
        "Use bcrypt, scrypt or Argon2 for passwords and SHA-256+ for digests.",
    ),
    (
        "TLS verification disabled",
        re.compile(r"(?i)(?:verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False|rejectUnauthorized\s*:\s*false)"),
        Severity.HIGH,
        "Certificate validation is disabled, so the connection can be intercepted.",
        "Leave verification enabled and install the correct CA bundle.",
    ),
    (
        "Hardcoded secret in source",
        re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*=\s*[\"'][^\"'\n$]{6,}[\"']"),
        Severity.HIGH,
        "A literal credential is embedded in the source tree.",
        "Read the value from configuration or a secret manager.",
    ),
    (
        "SQL built by concatenation",
        re.compile(r"(?i)(?:select|insert|update|delete)\s+[^;\"']*?\+\s*\w+"),
        Severity.HIGH,
        "SQL built by string concatenation allows injection.",
        "Use parameterised queries or an ORM with bound parameters.",
    ),
    (
        "Template rendering with autoescape off",
        re.compile(r"(?i)autoescape\s*=\s*False|mark_safe\s*\(|\|\s*safe\b"),
        Severity.HIGH,
        "Marking content safe disables output encoding and enables XSS.",
        "Escape by default and only mark trusted values safe.",
    ),
    (
        "Insecure randomness for a token",
        re.compile(r"(?i)\b(?:Math\.random|random\.random|rand\(\))\s*\([^)]*\)"),
        Severity.LOW,
        "Predictable randomness is not suitable for tokens, session ids or keys.",
        "Use `secrets` (Python) or `crypto.randomBytes` (Node).",
    ),
    (
        "assert used for validation",
        re.compile(r"^\s*assert\s+\w+"),
        Severity.LOW,
        "`assert` is stripped when Python runs with -O, disabling the check.",
        "Raise an exception explicitly.",
    ),
    (
        "Requests call without timeout",
        re.compile(r"(?i)\brequests\.(?:get|post|put|delete|head|patch)\s*\((?![^)]*timeout\s*=)"),
        Severity.MEDIUM,
        "A request without a timeout can hang a worker forever.",
        "Pass an explicit `timeout=`.",
    ),
    (
        "Path built from user input",
        re.compile(r"(?i)os\.path\.join\s*\([^)]*(?:request|params|argv|input|user)"),
        Severity.MEDIUM,
        "Joining untrusted input into a path can escape the intended directory.",
        "Resolve the path and confirm it stays inside the allowed root.",
    ),
]

#: One specific file is allowed to contain the pattern, per rule.
_EXCEPTIONS: dict[str, tuple[str, ...]] = {}


class DangerousPatternsModule(Module):
    """Detect dangerous API usage in source code."""
    group = "code"

    id = "dangerous_patterns"
    name = "Dangerous Code Patterns"
    description = (
        "Greps for constructs that are dangerous in context: shell execution, "
        "dynamic evaluation, unsafe deserialisation, disabled TLS verification "
        "and concatenated SQL."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.INJECTION
    capability = Capability.CODE
    cwe = "CWE-78"
    owasp = "A03"
    tags = ["code", "sast", "patterns"]
    remediation = "See the individual finding: each carries a specific fix."
    references = ["https://owasp.org/www-project-top-ten/"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = ctx.code_path
        patterns = [(regex, rule) for rule, regex, *_ in _RULES]
        hits = scan_patterns(root, patterns, limit=400)

        by_rule = {rule: (regex, severity, description, fix)
                   for rule, regex, severity, description, fix in _RULES}

        findings: list[Finding] = []
        for hit in hits:
            rule = hit.rule
            _, severity, description, fix = by_rule[rule]
            rel = relative(hit.path, root)
            findings.append(
                self.finding(
                    title=rule,
                    target=rel,
                    description=f"{description} Found at {rel}:{hit.line_number}.",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence_text=f"{rel}:{hit.line_number}\n{hit.line}",
                    matched=rule,
                    file=rel,
                    line=hit.line_number,
                    rule=rule,
                    fix=fix,
                )
            )
        return findings


class CryptoMisuseModule(Module):
    """Detect cryptographic misuse."""
    group = "code"

    id = "crypto_misuse"
    name = "Cryptographic Misuse"
    description = (
        "Detects ECB mode, static IVs, hardcoded keys, weak hash functions for "
        "passwords and low-iteration key derivation."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.CRYPTO
    capability = Capability.CODE
    cwe = "CWE-327"
    owasp = "A02"
    tags = ["code", "sast", "crypto"]
    remediation = "Use vetted libraries with authenticated modes and a managed key lifecycle."

    _RULES: list[tuple[str, re.Pattern[str], Severity, str]] = [
        (
            "AES in ECB mode",
            re.compile(r"(?i)['\"]?(?:aes|des)[\w\-]*(?:-|\s)?ecb"),
            Severity.HIGH,
            "ECB encrypts identical plaintext blocks to identical ciphertext, leaking structure.",
        ),
        (
            "Static IV with a block cipher",
            re.compile(r"(?i)\biv\s*=\s*[\"'][0-9a-f]{16,}[\"']"),
            Severity.HIGH,
            "A fixed IV with a deterministic mode makes ciphertext predictable.",
        ),
        (
            "MD5 for integrity",
            re.compile(r"(?i)hashlib\.md5\s*\(|createHash\(\s*[\"']md5[\"']"),
            Severity.MEDIUM,
            "MD5 is collision-broken and must not be used for integrity.",
        ),
        (
            "SHA-1 for integrity",
            re.compile(r"(?i)hashlib\.sha1\s*\(|createHash\(\s*[\"']sha1[\"']"),
            Severity.MEDIUM,
            "SHA-1 is collision-broken and must not be used for integrity.",
        ),
        (
            "Low PBKDF2 iteration count",
            re.compile(r"(?i)(?:pbkdf2|iterations)\s*[=(:]\s*(\d{1,5})\b"),
            Severity.HIGH,
            "Fewer than 100000 PBKDF2 iterations is far too weak against GPU cracking.",
        ),
        (
            "Hardcoded encryption key",
            re.compile(r"(?i)\b(?:secret_?key|encryption_?key|signing_?key)\s*=\s*[\"'][^\"'\n]{8,}[\"']"),
            Severity.CRITICAL,
            "A hardcoded key is extractable from the source and cannot be rotated.",
        ),
        (
            "DES / 3DES / RC4 used",
            re.compile(r"(?i)['\"]?(?:des|des-ede3|rc4|rc2)['\"]?(?:\b|\s*,)"),
            Severity.HIGH,
            "DES, 3DES and RC4 are broken and must not be used.",
        ),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = ctx.code_path
        findings: list[Finding] = []
        for rule, regex, severity, description in self._RULES:
            hits = scan_patterns(root, [(regex, rule)], limit=40)
            for hit in hits:
                rel = relative(hit.path, root)
                if rule == "Low PBKDF2 iteration count":
                    match = regex.search(hit.line)
                    if match and int(match.group(1)) >= 100000:
                        continue
                findings.append(
                    self.finding(
                        title=rule,
                        target=rel,
                        description=f"{description} Found at {rel}:{hit.line_number}.",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        evidence_text=f"{rel}:{hit.line_number}\n{hit.line}",
                        matched=rule,
                        file=rel,
                        line=hit.line_number,
                        rule=rule,
                    )
                )
        return findings

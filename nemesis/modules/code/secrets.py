"""Secret detection in source code.

Combines high-confidence provider patterns with an entropy heuristic, so a
random-looking 40-character string in a config file is flagged while test
fixtures and hashes are not.
"""

from __future__ import annotations

import re
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .common import iter_source_files, read_lines, relative, shannon_entropy

#: (rule, regex, severity). Order matters - the first match wins per line.
_PROVIDER_RULES: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS Access Key ID", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), Severity.CRITICAL),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_?secret_?access_?key\s*[=:]\s*[\"']?([A-Za-z0-9/+=]{40})"), Severity.CRITICAL),
    ("GitHub Personal Access Token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), Severity.CRITICAL),
    ("GitHub App Token", re.compile(r"\b(github_pat_[A-Za-z0-9_]{50,255})\b"), Severity.CRITICAL),
    ("GitHub OAuth Token", re.compile(r"\b(gho_[A-Za-z0-9]{36,})\b"), Severity.CRITICAL),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), Severity.CRITICAL),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,}"), Severity.HIGH),
    ("Stripe Live Key", re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})\b"), Severity.CRITICAL),
    ("Stripe Restricted Key", re.compile(r"\b(rk_live_[A-Za-z0-9]{20,})\b"), Severity.HIGH),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), Severity.HIGH),
    ("Firebase URL", re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"), Severity.LOW),
    ("OpenAI API Key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})\b"), Severity.CRITICAL),
    ("Anthropic API Key", re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), Severity.CRITICAL),
    ("OpenAI Admin Key", re.compile(r"\b(sk-admin-[A-Za-z0-9_\-]{20,})\b"), Severity.CRITICAL),
    ("Heroku API Key", re.compile(r"heroku[a-z0-9_\-]{8,}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"), Severity.HIGH),
    ("Twilio Account SID", re.compile(r"\b(AC[a-f0-9]{32})\b"), Severity.MEDIUM),
    ("Twilio Auth Token", re.compile(r"(?i)twilio[_-]?(?:auth)?[_-]?token\s*[=:]\s*[\"']?([0-9a-f]{32})"), Severity.CRITICAL),
    ("SendGrid API Key", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), Severity.CRITICAL),
    ("Mailgun API Key", re.compile(r"\b(key-[0-9a-f]{32})\b"), Severity.HIGH),
    ("Mailchimp API Key", re.compile(r"\b([0-9a-f]{32}-us[0-9]{1,2})\b"), Severity.HIGH),
    ("npm Token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), Severity.CRITICAL),
    ("PyPI Token", re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"), Severity.CRITICAL),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("JWT", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), Severity.MEDIUM),
    ("Basic Auth in URL", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@"), Severity.HIGH),
    ("Slack Webhook Legacy", re.compile(r"https://hooks\.slack\.com/T[A-Za-z0-9_/]{20,}"), Severity.HIGH),
    ("Discord Webhook", re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"), Severity.HIGH),
]

#: Generic assignment of a secret-looking name to a literal.
_GENERIC = re.compile(
    r"""(?ix)
    \b(?:
        api[_-]?key|apikey|secret[_-]?key|secret|client[_-]?secret|
        access[_-]?token|auth[_-]?token|refresh[_-]?token|
        private[_-]?key|passwd|password|passphrase|credentials?
    )\b
    \s*[:=]\s*
    ["']([^"'\n]{8,120})["']
    """
)

#: Values that are obviously placeholders.
_PLACEHOLDERS = {
    "password", "changeme", "example", "placeholder", "your_password",
    "yourpassword", "xxxxx", "todo", "fixme", "null", "none", "test",
    "secret", "hunter2", "admin", "letmein", "changethis", "default",
    "notarealsecret", "replace_me", "your_token_here", "insert_key_here",
}

#: Paths where a secret is expected and a finding is not useful.
_ALLOWED_PATH_PARTS = {
    "test", "tests", "spec", "specs", "example", "examples", "fixtures",
    "mocks", "__mocks__", "e2e", "cypress", "sample", "samples", "demo",
}


class SecretsModule(Module):
    """Detect credentials committed to source control."""
    group = "code"

    id = "secrets"
    name = "Hardcoded Secrets"
    description = (
        "Finds API keys, tokens, private keys and passwords committed to "
        "source control using provider-specific patterns plus an entropy "
        "heuristic."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.CODE
    cwe = "CWE-798"
    owasp = "A07"
    tags = ["secrets", "code", "sast"]
    remediation = (
        "Revoke and rotate every exposed credential immediately, remove them "
        "from the repository history, and load secrets from a secret manager or "
        "environment variables at runtime."
    )
    references = [
        "https://owasp.org/www-community/attacks/Use_of_hard-coded_password",
        "https://docs.github.com/en/code-security/secret-scanning",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = ctx.code_path
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()

        for path in iter_source_files(root):
            relative_path = relative(path, root)
            if any(part.lower() in _ALLOWED_PATH_PARTS for part in Path(relative_path).parts):
                continue
            lines = read_lines(path)
            for number, line in enumerate(lines, start=1):
                if len(line) > 4000:
                    line = line[:4000]
                for rule, regex, severity in _PROVIDER_RULES:
                    match = regex.search(line)
                    if not match:
                        continue
                    secret = match.group(1) if match.groups() else match.group(0)
                    key = (relative_path, number)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.finding(
                            title=f"Hardcoded {rule}",
                            target=relative_path,
                            description=(
                                f"A {rule} is hardcoded in {relative_path} at line "
                                f"{number}. Anyone with repository access can use it, "
                                "and it will remain in git history even after deletion."
                            ),
                            severity=severity,
                            confidence=Confidence.HIGH,
                            evidence_text=(
                                f"{relative_path}:{number}\n"
                                f"{line.strip()[:200]}\n"
                                f"Matched value: {secret[:24]}{'...' if len(secret) > 24 else ''}"
                            ),
                            matched=secret[:24],
                            file=relative_path,
                            line=number,
                            rule=rule,
                        )
                    )
                    break

                # Generic assignment with high entropy.
                generic = _GENERIC.search(line)
                if generic:
                    value = generic.group(1)
                    if (
                        value.lower() not in _PLACEHOLDERS
                        and not value.startswith(("http://", "https://", "<", "{", "$"))
                        and shannon_entropy(value) >= 3.6
                        and len(value) >= 12
                    ):
                        key = (relative_path, number)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            self.finding(
                                title="High-entropy value assigned to a secret-like name",
                                target=relative_path,
                                description=(
                                    f"{relative_path}:{number} assigns a high-entropy "
                                    f"value to a secret-looking name (entropy "
                                    f"{shannon_entropy(value):.2f} bits/char). This is "
                                    "likely a real credential."
                                ),
                                severity=Severity.HIGH,
                                confidence=Confidence.MEDIUM,
                                evidence_text=(
                                    f"{relative_path}:{number}\n{line.strip()[:200]}"
                                ),
                                matched=value[:16],
                                file=relative_path,
                                line=number,
                                rule="Generic secret assignment",
                            )
                        )
            if len(findings) >= 100:
                break
        return findings

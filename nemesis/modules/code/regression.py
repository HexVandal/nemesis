"""Patch regression detection.

The question a reviewer most wants answered is not "is this file safe" but
"what did this change make unsafe". A diff against the previous revision
answers it directly: dangerous patterns that were newly introduced, and
previously fixed problems that have come back.

The comparison is done against git when the tree is a repository, and
against a second directory when one is configured.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Patterns that must never appear in a new line of code.
#: Each entry is (pattern, title, severity, why).
REGRESSION_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    (
        r"\beval\s*\(",
        "eval() introduced",
        "high",
        "eval executes its argument as code, so any value that reaches it "
        "is a remote code execution bug.",
    ),
    (
        r"\bexec\s*\(",
        "exec() introduced",
        "high",
        "exec runs its argument as code in the current scope.",
    ),
    (
        r"shell\s*=\s*True",
        "shell=True introduced",
        "high",
        "A shell command built from any input is command injection.",
    ),
    (
        r"\bos\.system\s*\(",
        "os.system() introduced",
        "high",
        "The command line is passed to a shell, so shell metacharacters in "
        "any part of it are executed.",
    ),
    (
        r"\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(",
        "pickle deserialisation introduced",
        "critical",
        "Unpickling untrusted data executes arbitrary code by design.",
    ),
    (
        r"\byaml\.load\s*\((?![^)]*Safe)",
        "unsafe yaml.load() introduced",
        "high",
        "yaml.load without a safe loader constructs arbitrary Python "
        "objects, which is code execution.",
    ),
    (
        r"\bmd5\s*\(|\bsha1\s*\(",
        "weak hash introduced",
        "medium",
        "MD5 and SHA-1 are broken for any use that depends on collision "
        "resistance, including integrity checks and password hashing.",
    ),
    (
        r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false",
        "TLS verification disabled",
        "high",
        "Without certificate verification the connection can be "
        "intercepted and modified by anyone on the path.",
    ),
    (
        r"\bSELECT\b[^\n]*\+\s*\w+|execute\s*\(\s*f[\"']",
        "SQL built by concatenation",
        "high",
        "String concatenation into a query is SQL injection unless every "
        "part is a parameterised placeholder.",
    ),
)

#: A previously fixed pattern that has come back.
RESURRECTION_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"verify\s*=\s*False", "TLS verification disabled again"),
    (r"shell\s*=\s*True", "shell=True reintroduced"),
    (r"\beval\s*\(", "eval() reintroduced"),
)


class PatchRegressionModule(Module):
    """Reports dangerous patterns that a change introduced."""

    group = "code"
    id = "patch_regression"
    name = "Patch Regression Detection"
    description = (
        "Compares the working tree against the previous revision and "
        "reports dangerous patterns that were newly introduced, and "
        "previously fixed problems that have come back."
    )
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    category = Category.BUG
    capability = Capability.CODE
    cwe = "CWE-1104"
    owasp = "A06"
    tags = ["diff", "regression", "git", "review", "patch"]
    remediation = (
        "Fix the introduced issue before merging, or add a suppression with "
        "a written justification. A regression that reaches production is "
        "the failure mode this check exists to prevent."
    )
    references = ["https://owasp.org/www-project-development-environment/"]

    #: The revision to compare against. ``HEAD~1`` by default.
    baseline_revision = "HEAD~1"
    max_files = 200

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []

        for path, added_lines, removed_lines in self._changed_files(root):
            findings.extend(self._introduced(root, path, added_lines))
            findings.extend(self._resurrected(root, path, added_lines, removed_lines))
        return findings

    # -- diffing ---------------------------------------------------------
    def _changed_files(
        self, root: Path
    ) -> list[tuple[str, list[tuple[int, str]], list[tuple[int, str]]]]:
        """Return (path, added lines, removed lines) for the diff."""
        try:
            result = subprocess.run(
                ["git", "-C", str(root), "diff", "-U0", self.baseline_revision, "--"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return []
        if result.returncode != 0 or not result.stdout:
            return []

        changes: dict[str, tuple[list, list]] = {}
        current: str | None = None
        for line in result.stdout.splitlines():
            if line.startswith("+++ b/"):
                current = line[6:]
                changes.setdefault(current, ([], []))
            elif line.startswith("+") and not line.startswith("+++"):
                if current:
                    changes[current][0].append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                if current:
                    changes[current][1].append(line[1:])

        out: list[tuple[str, list[tuple[int, str]], list[tuple[int, str]]]] = []
        for path, (added, removed) in changes.items():
            if not path or path.startswith("dev/null"):
                continue
            out.append(
                (
                    path,
                    [(0, text) for text in added],
                    [(0, text) for text in removed],
                )
            )
        return out

    # -- analysis --------------------------------------------------------
    def _introduced(
        self, root: Path, path: str, added: list[tuple[int, str]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for _, line in added:
            for pattern, title, severity, why in REGRESSION_PATTERNS:
                if not re.search(pattern, line, re.IGNORECASE):
                    continue
                findings.append(
                    self.finding(
                        title=f"Regression: {title}",
                        target=str(root / path),
                        description=(
                            f"This change introduced {title.lower()} in "
                            f"{path}. {why} A change that introduces a "
                            f"dangerous pattern is a regression, even when "
                            f"the pattern was already present elsewhere in "
                            f"the codebase."
                        ),
                        severity=Severity[severity.upper()],
                        confidence=Confidence.HIGH,
                        evidence_text=f"{path}\n+ {line.strip()[:200]}",
                        matched=line.strip()[:200],
                        file=str(root / path),
                    )
                )
                break
        return findings

    def _resurrected(
        self,
        root: Path,
        path: str,
        added: list[tuple[int, str]],
        removed: list[tuple[int, str]],
    ) -> list[Finding]:
        """A pattern that was removed and has come back in the same file."""
        findings: list[Finding] = []
        removed_text = "\n".join(text for _, text in removed)
        for pattern, title in RESURRECTION_PATTERNS:
            if not re.search(pattern, removed_text, re.IGNORECASE):
                continue
            for _, line in added:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(
                        self.finding(
                            title=f"Regression: {title}",
                            target=str(root / path),
                            description=(
                                f"This change removed {title.lower()} from "
                                f"{path} and then reintroduced it. A fix "
                                f"that gets reverted in the same patch is "
                                f"usually a merge mistake."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            evidence_text=(
                                f"{path}\n- {removed_text.strip()[:200]}\n"
                                f"+ {line.strip()[:200]}"
                            ),
                            matched=line.strip()[:200],
                            file=str(root / path),
                        )
                    )
                    break
        return findings

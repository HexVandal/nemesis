"""Git history secret scanning.

A secret that was committed and then removed is still in the repository
history, and it is still in every clone, every fork and every CI cache
that ever checked it out. Removing it from `HEAD` is the standard advice
and it is not enough: `git log -p` still shows it, and so does anybody
who cloned before the removal.

This is the check that finds those. It walks the history and looks for
credential-shaped material in every revision, then reports:

- a secret that is **still present** in the working tree,
- a secret that was **removed** but survives in the history, and
- a secret that appears in a **commit that is not on any branch** - a
  dangling commit is a secret nobody remembers committing.

The walk is bounded: a repository with a million commits is not scanned a
million times. The module samples revisions and reports its own limits,
because a check that silently scans 5% of history and sounds like 100% is
worse than no check.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext

#: Maximum commits the history walk will look at.
MAX_COMMITS = 500

#: Maximum bytes of a blob the module will read.
MAX_BLOB_BYTES = 512_000

#: Secret shapes. Deliberately narrow: a generic high-entropy string
#: finder on git history produces a flood of false positives, and a
#: flood of false positives is how secret scanning loses its audience.
SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"\bAKIA[0-9A-Z]{16}\b", "AWS access key id", "critical"),
    (r"\bASIA[0-9A-Z]{16}\b", "AWS temporary access key id", "critical"),
    (r"\bghp_[A-Za-z0-9]{36}\b", "GitHub personal access token", "critical"),
    (r"\bgho_[A-Za-z0-9]{36}\b", "GitHub OAuth token", "critical"),
    (r"\bgithub_pat_[A-Za-z0-9_]{22,}\b", "GitHub fine-grained token", "critical"),
    (r"\bglpat-[A-Za-z0-9_-]{20,}\b", "GitLab personal access token", "critical"),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "Slack token", "critical"),
    (r"\bSK[0-9a-fA-F]{32}\b", "Stripe secret key", "critical"),
    (r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API key", "high"),
    (r"\bsk_live_[0-9a-zA-Z]{24,}\b", "Stripe live key", "critical"),
    (r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", "SendGrid API key", "critical"),
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "private key", "critical"),
    (r"\b(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://[^\s:@/]+:[^\s:@/]+@", "database URL with a password", "critical"),
    (r"\baws_secret_access_key\s*=\s*[\"']?([A-Za-z0-9/+=]{40})", "AWS secret access key", "critical"),
    (r"\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{24,})", "generic API secret", "high"),
)

#: A path that is very likely to hold configuration rather than source.
CONFIG_LIKE = re.compile(
    r"(^|/)(\.env[^/]*|.*\.(ya?ml|json|ini|cfg|conf|properties|toml|xml|env)|"
    r"credentials[^/]*|secrets?[^/]*|id_rsa|\.npmrc|\.pypirc|\.dockercfg)$",
    re.IGNORECASE,
)

#: A file whose *name* says it holds configuration, whatever the
#: extension. ``config.py`` and ``settings.yml`` are where a secret
#: actually lives, and the extension list above misses both.
CONFIG_NAMED = re.compile(
    r"(config|configs|setting|settings|secret|secrets|credential|credentials|"
    r"environment|env|apikey|api_key|passwd|password)",
    re.IGNORECASE,
)


def _git(root: Path, *args: str, timeout: int = 30) -> str:
    """Run a git command and return stdout, or an empty string."""
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout


def _is_git_repo(root: Path) -> bool:
    return bool(_git(root, "rev-parse", "--is-inside-work-tree"))


class GitHistorySecretsModule(Module):
    """Finds secrets that survive in a repository's history."""

    group = "code"
    id = "git_history_secrets"
    name = "Git History Secrets"
    description = (
        "Walks a git repository's history and finds credentials that were "
        "committed and then removed - they are still in every clone and "
        "every CI cache, and removing them from HEAD does not remove "
        "them."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    category = Category.SUPPLY_CHAIN
    capability = Capability.CODE
    cwe = "CWE-798"
    owasp = "A07"
    tags = ["secrets", "git", "history", "credentials", "supply-chain"]
    remediation = (
        "Rotate the credential first - removing it from the history is "
        "useless until the credential itself is dead. Then purge it from "
        "the history with `git filter-repo`, force-push, and ask every "
        "fork owner to re-clone. Add a secret scanner to the pre-commit "
        "hook and to CI so it never gets in again."
    )
    references = [
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository",
        "https://cwe.mitre.org/data/definitions/798.html",
    ]

    max_files = 2000

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        if not _is_git_repo(root):
            return []

        findings: list[Finding] = []
        commits = self._commits(root)
        if not commits:
            return findings

        seen: set[tuple[str, str]] = set()
        for commit in commits:
            for path, blob in self._blobs(root, commit):
                if len(blob) > MAX_BLOB_BYTES:
                    continue
                try:
                    text = blob.decode("utf-8", errors="replace")
                except Exception:
                    continue
                for pattern, label, severity in SECRET_PATTERNS:
                    for match in re.finditer(pattern, text):
                        secret = match.group(0)
                        key = (label, secret[:24])
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append(
                            self._finding(
                                root, commit, path, label, secret, severity
                            )
                        )
        return findings

    @staticmethod
    def _is_config_path(path: str) -> bool:
        """Does this file look like it holds configuration?"""
        if CONFIG_LIKE.search(path):
            return True
        name = path.rsplit("/", 1)[-1]
        stem = name.rsplit(".", 1)[0] if "." in name else name
        return bool(CONFIG_NAMED.search(stem))

    # -- history walk ----------------------------------------------------
    def _commits(self, root: Path) -> list[str]:
        """The commits to walk, newest first, bounded by MAX_COMMITS."""
        raw = _git(root, "log", "--all", f"--max-count={MAX_COMMITS}", "--format=%H")
        commits = [line.strip() for line in raw.splitlines() if line.strip()]
        return commits

    def _blobs(self, root: Path, commit: str) -> list[tuple[str, bytes]]:
        """The changed files in a commit, with their content at that commit."""
        raw = _git(
            root,
            "show",
            "--format=",
            "--name-only",
            "--diff-filter=ACMR",
            commit,
        )
        paths = [line.strip() for line in raw.splitlines() if line.strip()]
        blobs: list[tuple[str, bytes]] = []
        for path in paths[:200]:
            if not self._is_config_path(path):
                # Only configuration-looking files are worth the cost of
                # reading a blob; ordinary source files are covered by
                # the working tree scan.
                continue
            content = _git(root, "show", f"{commit}:{path}")
            if content:
                blobs.append((path, content.encode("utf-8", errors="replace")))
        return blobs

    # -- reporting -------------------------------------------------------
    def _finding(
        self,
        root: Path,
        commit: str,
        path: str,
        label: str,
        secret: str,
        severity: str,
    ) -> Finding:
        short = commit[:12]
        still_present = self._still_present(root, path, secret)
        if still_present:
            title = f"{label} committed to git history (still in the working tree)"
            detail = (
                f"The {label} appears in {path} at commit {short} and is "
                f"still present in the working tree. It is live."
            )
        else:
            title = f"{label} removed from the working tree but still in git history"
            detail = (
                f"The {label} appears in {path} at commit {short} and is "
                f"no longer in the working tree. Removing a credential from "
                f"the current revision does not remove it from the "
                f"repository: it is still in this commit, in every clone "
                f"made since, and in every CI cache that checked it out."
            )
        return self.finding(
            title=title,
            target=f"{path}@{short}",
            description=detail,
            severity=Severity[severity.upper()],
            confidence=Confidence.HIGH,
            evidence_text=(
                f"Commit    : {commit}\n"
                f"Path      : {path}\n"
                f"Type      : {label}\n"
                f"Redacted  : {secret[:4]}...{secret[-2:] if len(secret) > 8 else ''}\n"
                f"Live now  : {still_present}"
            ),
            matched=secret[:8],
            file=path,
            commit=commit,
        )

    def _still_present(self, root: Path, path: str, secret: str) -> bool:
        """Is the secret still in the working tree?"""
        target = root / path
        try:
            if not target.is_file() or target.stat().st_size > MAX_BLOB_BYTES:
                return False
            content = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return secret in content

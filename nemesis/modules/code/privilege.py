"""Privilege escalation primitives.

Escalation is rarely one bug. It is a chain: a writable file, a permissive
sudo rule, a binary that runs as root, an environment variable that ends
up in a command line. This module looks for the individual links - in the
source of a project, and in the filesystem of the machine it is running on
when that machine is in scope.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from .common import iter_source_files, read_lines

#: Source patterns that indicate a privilege boundary being crossed.
#: Each entry is (pattern, title, severity, detail).
_PRIVESC_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    (
        r"\bos\.setuid\s*\(|\bos\.setgid\s*\(|\bsetresuid\s*\(",
        "Privilege change via setuid/setgid",
        "medium",
        "The process changes its user or group at runtime. Whatever controls "
        "the arguments to this call controls the privilege transition.",
    ),
    (
        r"\bchmod\s*\([^)]*0o?[47]7[0-7]{2}|\bchmod\s*\([^)]*\+s\b",
        "SUID or SGID bit set on a file",
        "medium",
        "A set-user-ID or set-group-ID bit makes a file run with the "
        "privileges of its owner, which is one of the oldest and still most "
        "common local escalation primitives.",
    ),
    (
        r"\bos\.chown\s*\([^)]*0\)|\bchown\s+root\b",
        "Ownership handed to root",
        "medium",
        "The code gives a file to root. Combined with a writable path, that "
        "is an escalation chain rather than a single bug.",
    ),
    (
        r"/etc/sudoers|visudo\b",
        "Direct manipulation of the sudoers file",
        "high",
        "Writing to the sudoers file is a direct route to root, and the "
        "file's syntax is famously easy to get wrong in a way that grants "
        "far more than intended.",
    ),
    (
        r"\benv\s*=\s*\[?['\"]PATH=|\bos\.environ\[['\"]PATH['\"]\]\s*=",
        "PATH environment variable is set from data",
        "high",
        "Overriding PATH before running a command lets the caller choose "
        "which binary is executed.",
    ),
    (
        r"\bsubprocess\.[a-z_]+\([^)]*shell\s*=\s*True",
        "Shell command execution with a caller-influenced argument",
        "high",
        "shell=True with any part of the command derived from input is "
        "command injection, and a command injection in a privileged "
        "context is an escalation.",
    ),
    (
        r"\bos\.system\s*\(|\bpopen\s*\(",
        "Command execution primitive",
        "medium",
        "This is the sink a privilege escalation is delivered through. "
        "Whatever reaches it decides the privilege the command runs with.",
    ),
    (
        r"\bLD_PRELOAD\b|\bLD_LIBRARY_PATH\b",
        "Dynamic linker path is influenced",
        "high",
        "The dynamic linker honours these variables, so a process that "
        "passes them through to a privileged child can be made to load a "
        "chosen shared object.",
    ),
    (
        r"\bcap_set_proc\b|\bsetcap\b|capabilities?\.set",
        "Linux file capabilities are modified",
        "medium",
        "File capabilities grant specific privileges without making the file "
        "fully privileged, which makes them easy to overlook in review.",
    ),
)

#: Directories that are searched for executables.
_PATH_DIRS = (
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
    "/sbin", "/bin",
)

#: World-writable files that a service reads.
_SENSITIVE_PATHS = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/etc/crontab", "/etc/ld.so.preload",
)


class PrivilegeEscalationModule(Module):
    """Looks for privilege escalation primitives in code and on disk."""

    group = "code"
    id = "privilege_escalation"
    name = "Privilege Escalation Primitives"
    description = (
        "Finds the building blocks of a local privilege escalation: SUID "
        "and file capabilities, writable files that privileged processes "
        "read, PATH manipulation, and dangerous calls in the source."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    category = Category.BUG
    capability = Capability.CODE
    cwe = "CWE-269"
    owasp = "A01"
    tags = ["privesc", "suid", "sudo", "permissions", "code"]
    remediation = (
        "Drop the set-user-ID bit from anything that does not need it, "
        "never run a shell with user-controlled arguments, keep "
        "/etc/sudoers and the service configuration owned by root and not "
        "group- or world-writable, and set an explicit PATH before "
        "execing anything."
    )
    references = [
        "https://gtfobins.github.io/",
        "https://owasp.org/www-project-web-security-testing-guide/",
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._scan_code(ctx))
        findings.extend(self._scan_filesystem(ctx))
        return findings

    # -- source ----------------------------------------------------------
    def _scan_code(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        findings: list[Finding] = []
        for path in iter_source_files(ctx.code_path):
            lines = read_lines(path)
            if not lines:
                continue
            text = "\n".join(lines)
            for pattern, title, severity, detail in _PRIVESC_PATTERNS:
                for match in re.finditer(pattern, text, re.IGNORECASE):
                    line_number = text.count("\n", 0, match.start()) + 1
                    line = _line_at(text, match.start())
                    findings.append(
                        self.finding(
                            title=title,
                            target=str(path),
                            description=(
                                f"{detail} Found at {path}:{line_number}."
                            ),
                            severity=Severity[severity.upper()],
                            confidence=Confidence.HIGH,
                            evidence_text=(
                                f"{path}:{line_number}\n{line.strip()[:200]}"
                            ),
                            matched=match.group(0)[:120],
                            file=str(path),
                            line=line_number,
                        )
                    )
                    break  # one finding per pattern per file is enough
        return findings

    # -- filesystem ------------------------------------------------------
    def _scan_filesystem(self, ctx: ScanContext) -> list[Finding]:
        """Inspect the local machine for escalation primitives.

        This only looks at the machine nemesis is running on. It is a
        developer workstation check, not a remote assessment, and it never
        writes anything.
        """
        findings: list[Finding] = []
        # This check is Linux-only: SUID bits and /etc/permissions have no
        # Windows equivalent, and os.geteuid does not exist there. Raise
        # nothing rather than crashing the whole scan on Windows.
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            return findings

        for directory in _PATH_DIRS:
            if not os.path.isdir(directory):
                continue
            try:
                entries = os.listdir(directory)
            except OSError:
                continue
            for name in entries:
                path = os.path.join(directory, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                mode = info.st_mode
                if mode & (stat.S_ISUID | stat.S_ISGID) and info.st_uid == 0:
                    findings.append(
                        self.finding(
                            title="Root-owned SUID or SGID binary in a PATH directory",
                            target=path,
                            description=(
                                f"{path} is owned by root and has the "
                                f"set-user-ID or set-group-ID bit set. It runs "
                                f"with root's privileges, and it is on the "
                                f"default PATH, so anything that can make it "
                                f"run is a route to root."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            evidence_text=(
                                f"Path : {path}\n"
                                f"Mode : {stat.filemode(mode)}\n"
                                f"Owner: uid={info.st_uid} gid={info.st_gid}"
                            ),
                            matched=stat.filemode(mode),
                        )
                    )

        for path in _SENSITIVE_PATHS:
            try:
                info = os.stat(path)
            except OSError:
                continue
            if info.st_mode & stat.S_IWOTH or info.st_mode & stat.S_IWGRP:
                findings.append(
                    self.finding(
                        title="World- or group-writable sensitive file",
                        target=path,
                        description=(
                            f"{path} is writable by group or world. If a "
                            f"privileged process reads it, then writing to "
                            f"it is a privilege escalation."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        evidence_text=(
                            f"Path : {path}\nMode : {stat.filemode(info.st_mode)}"
                        ),
                        matched=stat.filemode(info.st_mode),
                    )
                )
        return findings


def _line_at(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return text[start:end]


# Keep a reference so the import is not dropped by linters.
_ = Path

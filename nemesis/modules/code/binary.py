"""Binary triage and exploit-primitive modules.

``binary_triage`` reports what a binary *is* and what it is made of.
``binary_exploit_primitives`` reports the specific weaknesses that decide
whether a memory corruption bug would be exploitable: no stack canary, an
executable stack, no PIE, no RELRO, and imports of the unbounded string
functions.
"""

from __future__ import annotations

from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ...subsystems.binary import DANGEROUS_IMPORTS, BinaryInfo, triage
from ..base import Module, ScanContext

#: Suffixes and names that identify a binary worth triaging.
BINARY_SUFFIXES = (".so", ".bin", ".elf", ".exe", ".dll", ".dylib", ".o", ".a", ".ko")
BINARY_NAMES = ("a.out",)


def _binary_files(root: str | Path) -> list[Path]:
    """Find binaries under *root* without descending into vendor trees.

    A binary is identified either by its name or by its **magic bytes**.
    Name-based detection alone misses the common case: a compiled program
    called ``server`` or ``agent`` with no extension at all, which is
    exactly what ends up in a container image.
    """
    root = Path(root)
    skip = {
        ".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
        "dist", "build", ".mypy_cache", "site-packages", ".tox", ".pytest_cache",
    }
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in skip for part in path.relative_to(root).parts):
            continue
        name = path.name.lower()
        if name in BINARY_NAMES or path.suffix.lower() in BINARY_SUFFIXES:
            found.append(path)
            continue
        # Magic-byte detection for extensionless executables.
        if path.suffix == "" and _has_executable_magic(path):
            found.append(path)
    return found


def _has_executable_magic(path: Path) -> bool:
    """Does this file start with the magic bytes of a real executable?"""
    try:
        with path.open("rb") as handle:
            header = handle.read(4)
    except OSError:
        return False
    if header[:4] == b"\x7fELF":
        return True
    if header[:2] == b"MZ":
        return True
    # Mach-O, both endiannesses and the fat universal binary.
    return header[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    )


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"\x7fELF" or handle.read(2) == b"MZ"
    except OSError:
        return False


class BinaryTriageModule(Module):
    """Reports what a binary is and what it carries."""

    group = "code"
    id = "binary_triage"
    name = "Binary Triage"
    description = (
        "Parses ELF, PE and Mach-O binaries: architecture, hardening "
        "posture, imported dangerous functions, packer detection and "
        "credentials embedded in the binary."
    )
    severity = Severity.LOW
    confidence = Confidence.HIGH
    category = Category.DISCLOSURE
    capability = Capability.CODE
    cwe = "CWE-200"
    owasp = "A05"
    tags = ["binary", "elf", "pe", "triage", "reverse"]
    remediation = (
        "Strip debug symbols from release builds, remove embedded "
        "credentials and rotate any that were compiled in, and strip "
        "unnecessary dangerous imports."
    )
    references = ["https://cwe.mitre.org/data/definitions/200.html"]

    max_files = 100

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        findings: list[Finding] = []
        for path in _binary_files(ctx.code_path)[: self.max_files]:
            if not _is_binary(path):
                continue
            info = triage(path)
            if info.format == "unknown":
                continue
            findings.extend(self._report(path, info))
        return findings

    def _report(self, path: Path, info: BinaryInfo) -> list[Finding]:
        findings: list[Finding] = []

        if info.embedded_credentials:
            findings.append(
                self.finding(
                    title="Credential embedded in a compiled binary",
                    target=str(path),
                    description=(
                        f"{path} contains what looks like a credential. A "
                        f"credential compiled into a binary is not a secret "
                        f"any more - it ships to every user of the binary "
                        f"and is readable with a strings command."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"Binary : {path}\n"
                        f"Format : {info.format} {info.arch} {info.bits}-bit\n"
                        f"Found  : {', '.join(info.embedded_credentials[:5])}"
                    ),
                    matched=info.embedded_credentials[0],
                    file=str(path),
                )
            )

        if info.packer:
            findings.append(
                self.finding(
                    title="Binary is packed",
                    target=str(path),
                    description=(
                        f"{path} is packed with {info.packer}. Packing "
                        f"hides the real import table and strings, so any "
                        f"other analysis of this binary has to start by "
                        f"unpacking it."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    evidence_text=f"{path}\nPacker: {info.packer}",
                    matched=info.packer,
                    file=str(path),
                )
            )

        return findings


class BinaryExploitPrimitivesModule(Module):
    """Reports the memory-corruption primitives in a binary."""

    group = "code"
    id = "binary_exploit_primitives"
    name = "Binary Exploit Primitives"
    description = (
        "Reports whether a binary's mitigations are on - stack canary, "
        "NX, PIE, RELRO - and whether it imports the unbounded string "
        "functions that memory corruption bugs use."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.BUG
    capability = Capability.CODE
    cwe = "CWE-120"
    owasp = "A06"
    tags = ["binary", "exploit", "mitigation", "canary", "nx", "pie"]
    remediation = (
        "Compile with stack protector, non-executable stack, PIE and full "
        "RELRO, and replace the unbounded string functions with the "
        "length-checked ones."
    )
    references = [
        "https://wiki.ossec.org/wiki/Rule:Id:600",
        "https://madaware.gitlab.io/blog/post/2021/01/02/relro-and-canary/",
    ]

    max_files = 100

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        findings: list[Finding] = []
        for path in _binary_files(ctx.code_path)[: self.max_files]:
            if not _is_binary(path):
                continue
            info = triage(path)
            if info.format == "unknown":
                continue
            findings.extend(self._report(path, info))
        return findings

    def _report(self, path: Path, info: BinaryInfo) -> list[Finding]:
        findings: list[Finding] = []
        mitigations = [
            ("stack canary", info.has_canary, "the stack canary catches a "
             "stack overflow before the corrupted return address is used"),
            ("NX (non-executable stack)", info.has_nx, "without NX, injected "
             "shellcode on the stack runs directly"),
            ("PIE (position independent executable)", info.has_pie,
             "without PIE, the code and data addresses are fixed, so a "
             "gadget can be found once and reused"),
            ("RELRO", info.has_relro not in (None, ""), "without RELRO, the "
             "GOT can be overwritten to redirect a call"),
        ]

        missing = [name for name, present, _ in mitigations if present is False]
        if missing:
            findings.append(
                self.finding(
                    title=f"Binary is missing exploit mitigations: {', '.join(missing)}",
                    target=str(path),
                    description=(
                        f"{path} does not have: {', '.join(missing)}. "
                        f"Each of these turns a memory corruption bug from "
                        f"a crash into a controlled execution, and a stack "
                        f"buffer overflow that lands in an unprotected "
                        f"binary is reliably exploitable rather than "
                        f"reliably fatal."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"Binary   : {path}\n"
                        f"Format   : {info.format} {info.arch} {info.bits}-bit\n"
                        f"Canary   : {info.has_canary}\n"
                        f"NX       : {info.has_nx}\n"
                        f"PIE      : {info.has_pie}\n"
                        f"RELRO    : {info.has_relro}\n"
                        f"Stripped  : {info.is_stripped}\n"
                        + "\n".join(f"Note     : {n}" for n in info.notes)
                    ),
                    matched=", ".join(missing),
                    file=str(path),
                )
            )

        risky = [name for name in info.imports if name in DANGEROUS_IMPORTS]
        if risky:
            findings.append(
                self.finding(
                    title=f"Binary imports dangerous functions: {', '.join(sorted(risky))}",
                    target=str(path),
                    description=(
                        f"{path} imports {', '.join(sorted(risky))}. "
                        f"{'; '.join(sorted({DANGEROUS_IMPORTS[n] for n in risky}))}. "
                        f"Every one of these is a place where a memory "
                        f"corruption bug becomes code execution."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    evidence_text=(
                        f"Binary  : {path}\n"
                        f"Imports : {', '.join(sorted(risky))}"
                    ),
                    matched=", ".join(sorted(risky)),
                    file=str(path),
                )
            )
        return findings

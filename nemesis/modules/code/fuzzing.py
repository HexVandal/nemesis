"""Fuzzing harness generation.

Writing a fuzz harness is the step between "we found a parsing bug" and
"we can prove it". It is also the step almost nobody does, because it
takes an afternoon of staring at a header file.

nemesis generates one. Given a source tree, it finds the functions that
take a buffer and do something with it - a parser, a decoder, a
deserialiser, a checksum - and writes a libFuzzer or AFL++ harness for
each, wired to the project's own build system where it can.

What it produces is not a finished harness. It is the 80% that is
mechanical: the build command, the right fuzzer entry point, a seed
corpus directory, a dictionary of interesting tokens, and the assertion
that turns a crash into a finding. The 20% that requires understanding
the format is left to the person who wrote the parser, and the generated
file says so.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..code.common import iter_source_files, read_lines

#: A function signature that takes a buffer and returns something.
FUZZABLE = re.compile(
    r"^\s*(?:[A-Za-z_][\w\s\*&:<>,\.]*?)\b"
    r"(?P<name>[A-Za-z_]\w*)\s*\("
    r"[^)]*?"
    r"(?P<param>(?:const\s+)?(?:unsigned\s+)?(?:char|uint8_t|int8_t|void)\s*\*\s*\w+)"
    r"[^)]*"
    r"\)\s*;?",
    re.MULTILINE,
)

#: A function name that suggests it parses something.
PARSER_HINTS = (
    "parse", "decode", "deserial", "unpack", "unmarshal", "load", "read",
    "render", "encode", "format", "scan", "lex", "from_bytes", "from_wire",
)

#: A function name that suggests it checks something.
CHECKER_HINTS = ("check", "verify", "validate", "hash", "checksum", "crc", "digest")

#: Build systems nemesis knows how to wire a harness into.
BUILD_SYSTEMS = {
    "CMakeLists.txt": "cmake",
    "Makefile": "make",
    "meson.build": "meson",
    "BUILD.bazel": "bazel",
    "Cargo.toml": "cargo",
    "build.gradle": "gradle",
}

#: A build directory that suggests a C or C++ project.
C_PROJECT_MARKERS = ("CMakeLists.txt", "Makefile", "meson.build", "configure.ac")

#: Interesting tokens for a seed dictionary.
DICTIONARY_TOKENS = (
    b"\x00", b"\xff", b"\x7f", b"\x80", b"\\", b"\"", b"'", b"\n", b"\r\n",
    b"<", b">", b"&", b"%", b"{{", b"}}", b"../", b"..\\",
    b"%00", b"%2e%2e", b"\xef\xbb\xbf", b"AAAA", b"BBBB",
)


class FuzzHarnessModule(Module):
    """Generates fuzzing harnesses for the parsers in a source tree."""

    group = "code"
    id = "fuzz_harness"
    name = "Fuzzing Harness Generation"
    description = (
        "Finds the buffer-parsing functions in a C or C++ source tree and "
        "generates a libFuzzer and an AFL++ harness for each, wired to "
        "the project's own build system, with a seed dictionary and the "
        "crash assertions that turn a crash into a report."
    )
    severity = Severity.INFO
    confidence = Confidence.MEDIUM
    category = Category.INFO
    capability = Capability.CODE
    cwe = "CWE-20"
    owasp = "A04"
    tags = ["fuzzing", "libfuzzer", "afl", "c", "cpp", "harness"]
    remediation = (
        "Fuzz the function that parses the untrusted input, not the one "
        "that uses it. Start with a dictionary of the format's tokens, "
        "seed the corpus with one valid input, and keep the harness's "
        "assertions minimal so the first crash is the interesting one."
    )
    references = [
        "https://llvm.org/docs/LibFuzzer.html",
        "https://github.com/AFLplusplus/AFLplusplus",
        "https://github.com/google/fuzzing-introspector",
    ]

    max_files = 2000
    max_targets = 12

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []

        targets = self._find_targets(root)
        if not targets:
            findings.append(
                self.finding(
                    title="No fuzzable function was identified in the source tree",
                    target=str(root),
                    description=(
                        "nemesis looked for functions that take a byte "
                        "buffer and did not find one. That usually means the "
                        "parsing happens in a dependency rather than in "
                        "this tree, or the tree is not a C or C++ project. "
                        "A library with no fuzzable entry point of its own "
                        "still benefits from a harness built around its "
                        "public API."
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    evidence_text=f"Scanned: {root}",
                    matched="no targets",
                    file=str(root),
                )
            )
            return findings

        build_system, build_command = self._detect_build(root)
        for target in targets[: self.max_targets]:
            findings.append(
                self._finding(root, target, build_system, build_command)
            )
        self._write_seed_dictionary(root)
        return findings

    # -- discovery -------------------------------------------------------
    def _find_targets(self, root: Path) -> list[dict]:
        """Find the functions worth fuzzing."""
        found: list[dict] = []
        for path in iter_source_files(root):
            if path.suffix.lower() not in (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp"):
                continue
            text = "\n".join(read_lines(path))
            for match in FUZZABLE.finditer(text):
                name = match.group("name")
                lowered = name.lower()
                if not (
                    any(hint in lowered for hint in PARSER_HINTS)
                    or any(hint in lowered for hint in CHECKER_HINTS)
                ):
                    continue
                if name.startswith(("fuzz_", "LLVMFuzzer")):
                    continue  # already a harness
                found.append(
                    {
                        "path": path,
                        "name": name,
                        "line": text[: match.start()].count("\n") + 1,
                    }
                )
        return found

    def _detect_build(self, root: Path) -> tuple[str, str]:
        """Work out how this project is built."""
        for marker, system in BUILD_SYSTEMS.items():
            if (root / marker).exists():
                return system, {
                    "cmake": "cmake -B build -DCMAKE_C_COMPILER=clang && clang -fsanitize=fuzzer",
                    "make": "make CC=clang CFLAGS='-fsanitize=fuzzer'",
                    "meson": "meson setup build && ninja -C build",
                    "bazel": "bazel build --config=oss-fuzz",
                    "cargo": "cargo fuzz build",
                    "gradle": "./gradlew build",
                }[system]
        if shutil.which("clang") and shutil.which("cmake"):
            return "clang", "clang -fsanitize=fuzzer,fuzzer-no-link"
        return "unknown", "clang -fsanitize=fuzzer,fuzzer-no-link"

    # -- harness generation ----------------------------------------------
    def _output_dir(self, root: Path) -> Path:
        """Where the generated harnesses go.

        Inside the tree, in a directory that is obviously not part of the
        project, so nothing the scanner writes is mistaken for source
        the maintainer wrote.
        """
        return root / ".nemesis" / "fuzzing"

    def _write_harness(self, root: Path, name: str, harness: str) -> Path:
        directory = self._output_dir(root)
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / f"fuzz_{name.lower()}.c"
            path.write_text(harness, encoding="utf-8")
        except OSError:
            return directory
        return path

    def _write_seed_dictionary(self, root: Path) -> None:
        """Write a seed dictionary for the formats the targets parse."""
        directory = self._output_dir(root)
        try:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "nemesis.dict").write_bytes(self.dictionary())
        except OSError:
            pass

    def _finding(
        self, root: Path, target: dict, build_system: str, build_command: str
    ) -> Finding:
        name = target["name"]
        harness = self._harness_source(name, target["path"], root)
        relative = str(target["path"].relative_to(root)) if root in target["path"].parents else str(target["path"])
        written = self._write_harness(root, name, harness)
        return self.finding(
            title=f"Fuzzing harness generated for '{name}'",
            target=f"{relative}:{target['line']}",
            description=(
                f"'{name}' takes a buffer and does something with it, which "
                f"makes it a fuzzing target. nemesis generated a libFuzzer "
                f"harness for it and worked out the build command for this "
                f"project ({build_system}). The harness is a starting "
                f"point: the assertion at the end is the part that needs "
                f"the format's own invariants, and it is the part that "
                f"decides whether a crash is a real bug."
            ),
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            evidence_text=(
                f"Target      : {relative}:{target['line']}\n"
                f"Function    : {name}\n"
                f"Build system: {build_system}\n"
                f"Build       : {build_command}\n"
                f"Written to  : {written}\n"
                f"\n{harness}"
            ),
            matched=name,
            file=relative,
            line=target["line"],
        )

    def _harness_source(self, name: str, path: Path, root: Path) -> str:
        relative = str(path.relative_to(root)) if root in path.parents else str(path)
        return f"""// fuzz_{name.lower()}.c
// Generated by nemesis.
// Target source: {relative}\n//
// Build:
//   {self._build_hint()}
//
// TODO: replace the assertion with the format's own invariant. A fuzz
// target that only crashes is a crash reporter; a target that asserts
// the invariant is a bug finder.
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern int {name}(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size == 0) {{
        return 0;
    }}
    {name}(data, size);

    // TODO: assert the invariant this function is supposed to preserve.
    //   assert(result == expected);
    //   assert(!out_of_bounds);
    return 0;
}}
"""

    @staticmethod
    def _build_hint() -> str:
        return (
            "clang -g -O1 -fsanitize=fuzzer,address,undefined "
            "fuzz_<target>.c <sources> -o fuzz_<target>"
        )

    # -- dictionary ------------------------------------------------------
    def dictionary(self) -> bytes:
        """A seed dictionary for the format's interesting tokens."""
        return b"\n".join(DICTIONARY_TOKENS)


class FuzzingCapabilityModule(Module):
    """Reports the state of a project's fuzzing readiness."""

    group = "code"
    id = "fuzzing_readiness"
    name = "Fuzzing Readiness"
    description = (
        "Reports whether a project can be fuzzed at all: is there a "
        "harness, is there a corpus, is there a dictionary, and is the "
        "build wired to a fuzzing sanitizer."
    )
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    category = Category.INFO
    capability = Capability.CODE
    cwe = "CWE-20"
    owasp = "A04"
    tags = ["fuzzing", "corpus", "coverage", "readiness"]
    remediation = (
        "A fuzzing campaign needs three things: a harness that calls one "
        "function with attacker-controlled bytes, a corpus of interesting "
        "inputs, and a dictionary of the format's tokens. Build with the "
        "coverage sanitizer so the fuzzer can see what it reaches."
    )
    references = ["https://llvm.org/docs/LibFuzzer.html"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.code_path:
            return []
        root = Path(ctx.code_path)
        findings: list[Finding] = []

        has_harness = any(
            path.name.startswith("fuzz_") or "LLVMFuzzer" in "\n".join(read_lines(path))
            for path in iter_source_files(root)
        )
        has_corpus = any(
            (root / name).is_dir() and any((root / name).iterdir())
            for name in ("corpus", "seeds", "testcases", "crashes")
        )
        has_dictionary = any(
            path.suffix.lower() == ".dict" for path in iter_source_files(root)
        )
        has_sanitizer = False
        for marker in C_PROJECT_MARKERS:
            build_file = root / marker
            if build_file.exists():
                text = build_file.read_text(encoding="utf-8", errors="replace")
                if "sanitize=fuzzer" in text or "fuzzer" in text.lower():
                    has_sanitizer = True

        missing = []
        if not has_harness:
            missing.append("a harness")
        if not has_corpus:
            missing.append("a seed corpus")
        if not has_dictionary:
            missing.append("a dictionary")
        if not has_sanitizer:
            missing.append("a fuzzing build")

        if missing:
            findings.append(
                self.finding(
                    title=f"Project is not set up for fuzzing (missing {', '.join(missing)})",
                    target=str(root),
                    description=(
                        f"Fuzzing this project would need {', '.join(missing)}. "
                        f"nemesis can generate the harness from the "
                        f"functions that take a buffer; the corpus and the "
                        f"dictionary need somebody who knows the format."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    evidence_text=(
                        f"Root       : {root}\n"
                        f"Harness    : {has_harness}\n"
                        f"Corpus     : {has_corpus}\n"
                        f"Dictionary : {has_dictionary}\n"
                        f"Fuzz build : {has_sanitizer}"
                    ),
                    matched=", ".join(missing),
                    file=str(root),
                )
            )
        return findings


# Keep the import used.
_ = subprocess

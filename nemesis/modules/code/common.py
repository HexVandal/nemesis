"""Shared helpers for source-code modules."""

from __future__ import annotations

import math
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

#: Extensions worth reading for source analysis.
SOURCE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".java",
    ".rb", ".go", ".rs", ".cs", ".kt", ".kts", ".scala", ".swift", ".c", ".h",
    ".cc", ".cpp", ".hpp", ".sh", ".bash", ".zsh", ".ps1", ".pl", ".pm",
    ".lua", ".dart", ".vue", ".svelte", ".tf", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".env", ".conf", ".properties", ".json", ".xml", ".html", ".jsp",
    ".erb", ".twig", ".sql", ".graphql", ".gql",
}

#: Directories that never contain first-party source worth scanning.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__", ".venv",
    "venv", "env", "dist", "build", "out", "target", ".next", ".nuxt",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", ".gradle", ".idea", ".vscode", "bower_components",
    ".terraform", "Pods", ".cache",
}

#: Maximum size of a single file we will read.
MAX_FILE_BYTES = 2_000_000

#: Maximum number of files a code module will read.
MAX_FILES = 8000


@dataclass
class CodeHit:
    """One match inside a source file."""

    path: Path
    line_number: int
    line: str
    match: str
    rule: str = ""


def iter_source_files(root: str | Path) -> Iterator[Path]:
    """Yield every scannable source file under *root*."""
    root_path = Path(root).resolve()
    if root_path.is_file():
        yield root_path
        return

    count = 0
    for path in sorted(root_path.rglob("*")):
        if count >= MAX_FILES:
            return
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SOURCE_EXTENSIONS or path.name in {
            ".env", "Dockerfile", "Makefile", "Jenkinsfile"
        }:
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            yield path


def read_lines(path: Path) -> list[str]:
    """Read a file as text lines, tolerating encoding problems."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()


def scan_patterns(
    root: str | Path, patterns: list[tuple[str, str]], limit: int = 500
) -> list[CodeHit]:
    """Search files for compiled regexes.

    *patterns* is a list of ``(compiled_regex, rule_name)`` pairs.
    """
    hits: list[CodeHit] = []
    for path in iter_source_files(root):
        lines = read_lines(path)
        if not lines:
            continue
        for number, line in enumerate(lines, start=1):
            if len(line) > 4000:
                line = line[:4000]
            for regex, rule in patterns:
                if regex.search(line):
                    hits.append(CodeHit(path=path, line_number=number, line=line, match=line.strip()[:300], rule=rule))
                    if len(hits) >= limit:
                        return hits
                    break  # one hit per line keeps output readable
    return hits


def shannon_entropy(data: str) -> float:
    """Shannon entropy of *data* in bits per character."""
    if not data:
        return 0.0
    counts: dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def relative(path: Path, root: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(root).resolve()))
    except (ValueError, OSError):
        return str(path)

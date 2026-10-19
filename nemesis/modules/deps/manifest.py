"""Dependency manifest parsing.

Supports the ecosystems that cover the overwhelming majority of real
projects: Python, Node, Rust, Go, Java/Maven, Ruby, PHP and .NET.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

#: Manifest file name -> ecosystem name understood by OSV.dev.
MANIFEST_ECOSYSTEMS: dict[str, str] = {
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
    "Pipfile": "PyPI",
    "Pipfile.lock": "PyPI",
    "pyproject.toml": "PyPI",
    "poetry.lock": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    "go.mod": "Go",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
    "composer.json": "Packagist",
    "composer.lock": "Packagist",
    "packages.config": "NuGet",
    "Directory.Packages.props": "NuGet",
    "pubspec.yaml": "Pub",
    "mix.exs": "Hex",
}


@dataclass
class Dependency:
    """One resolved dependency."""

    name: str
    version: str
    ecosystem: str
    source_file: str
    dev: bool = False

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}"


_PEP508 = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._\-\[\]]+)\s*(?P<extras>\[[^\]]*\])?\s*"
    r"(?P<op>==|>=|<=|~=|!=|<|>)\s*(?P<version>[0-9][^\s,;#]*)?"
)


def _parse_requirements(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _PEP508.match(line)
        if not match:
            continue
        name = match.group("name")
        version = (match.group("version") or "").strip()
        operator = match.group("op")
        # Only exact pins give a version we can look up reliably.
        if operator != "==" or not version:
            continue
        deps.append(Dependency(name=name, version=version, ecosystem="PyPI", source_file=source))
    return deps


def _parse_pyproject(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        import tomllib

        data = tomllib.loads(text)
    except Exception:
        return deps

    project = data.get("project", {})
    for spec in project.get("dependencies", []) or []:
        match = _PEP508.match(spec.strip())
        if match and match.group("op") == "==" and match.group("version"):
            deps.append(
                Dependency(
                    name=match.group("name"),
                    version=match.group("version").strip(),
                    ecosystem="PyPI",
                    source_file=source,
                )
            )

    for group, items in (project.get("optional-dependencies") or {}).items():
        for spec in items or []:
            match = _PEP508.match(spec.strip())
            if match and match.group("op") == "==" and match.group("version"):
                deps.append(
                    Dependency(
                        name=match.group("name"),
                        version=match.group("version").strip(),
                        ecosystem="PyPI",
                        source_file=source,
                        dev=True,
                    )
                )

    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for name, spec in (poetry.get("dependencies") or {}).items():
        if name.lower() == "python" or not isinstance(spec, str):
            continue
        version = spec.lstrip("^~=>< ")
        if version:
            deps.append(
                Dependency(name=name, version=version, ecosystem="PyPI", source_file=source)
            )
    return deps


def _parse_package_json(text: str, source: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dependency] = []
    for name, spec in (data.get("dependencies") or {}).items():
        version = str(spec).lstrip("^~>=< ")
        if version and version[0].isdigit():
            deps.append(
                Dependency(name=name, version=version, ecosystem="npm", source_file=source)
            )
    for name, spec in (data.get("devDependencies") or {}).items():
        version = str(spec).lstrip("^~>=< ")
        if version and version[0].isdigit():
            deps.append(
                Dependency(
                    name=name, version=version, ecosystem="npm",
                    source_file=source, dev=True,
                )
            )
    return deps


def _parse_package_lock(text: str, source: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            name = meta.get("name") or (path.split("node_modules/")[-1] if "node_modules/" in path else None)
            version = meta.get("version")
            if not name or not version:
                continue
            deps.append(
                Dependency(
                    name=name, version=version, ecosystem="npm",
                    source_file=source, dev=bool(meta.get("dev")),
                )
            )
        return deps

    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict) and meta.get("version"):
            deps.append(
                Dependency(
                    name=name, version=meta["version"], ecosystem="npm",
                    source_file=source, dev=bool(meta.get("dev")),
                )
            )
    return deps


def _parse_cargo_toml(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        import tomllib

        data = tomllib.loads(text)
    except Exception:
        return deps
    for name, spec in (data.get("dependencies") or {}).items():
        if isinstance(spec, str):
            version = spec
        elif isinstance(spec, dict):
            version = spec.get("version", "")
        else:
            continue
        version = str(version).split(",")[0].lstrip("^~=>< ")
        if version and version[0].isdigit():
            deps.append(
                Dependency(name=name, version=version, ecosystem="crates.io", source_file=source)
            )
    for name, spec in (data.get("dev-dependencies") or {}).items():
        if isinstance(spec, str):
            version = spec.lstrip("^~=>< ")
            if version and version[0].isdigit():
                deps.append(
                    Dependency(
                        name=name, version=version, ecosystem="crates.io",
                        source_file=source, dev=True,
                    )
                )
    return deps


_GO_REQUIRE = re.compile(r"^\s*([\w.\-/~]+\.[\w.\-/~]+)\s+(v[\w.\-+]+)")


def _parse_go_mod(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        candidate = line[len("require "):] if line.startswith("require ") else (line if in_block else "")
        if not candidate:
            continue
        match = _GO_REQUIRE.match(candidate)
        if match:
            deps.append(
                Dependency(
                    name=match.group(1), version=match.group(2),
                    ecosystem="Go", source_file=source,
                )
            )
    return deps


_POM_ARTIFACT = re.compile(
    r"<groupId>\s*([^<]+?)\s*</groupId>.*?<artifactId>\s*([^<]+?)\s*</artifactId>.*?"
    r"<version>\s*([^<]+?)\s*</version>",
    re.DOTALL,
)


def _parse_pom(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for match in _POM_ARTIFACT.finditer(text):
        group, artifact, version = match.groups()
        if version.startswith("${"):
            continue
        deps.append(
            Dependency(
                name=f"{group}:{artifact}", version=version,
                ecosystem="Maven", source_file=source,
            )
        )
    return deps


def _parse_gemfile_lock(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for match in re.finditer(r"^\s{4}([\w\-.]+) \(([\d.]+[^)]*)\)", text, re.MULTILINE):
        deps.append(
            Dependency(
                name=match.group(1), version=match.group(2),
                ecosystem="RubyGems", source_file=source,
            )
        )
    return deps


def _parse_composer_lock(text: str, source: str) -> list[Dependency]:
    deps: list[Dependency] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return deps
    for package in data.get("packages", []) or []:
        if package.get("name") and package.get("version"):
            deps.append(
                Dependency(
                    name=package["name"], version=package["version"],
                    ecosystem="Packagist", source_file=source,
                )
            )
    return deps


_PARSERS = {
    "requirements.txt": _parse_requirements,
    "requirements-dev.txt": _parse_requirements,
    "Pipfile": _parse_requirements,
    "Pipfile.lock": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "poetry.lock": _parse_pyproject,
    "package.json": _parse_package_json,
    "package-lock.json": _parse_package_lock,
    "Cargo.toml": _parse_cargo_toml,
    "Cargo.lock": _parse_cargo_toml,
    "go.mod": _parse_go_mod,
    "pom.xml": _parse_pom,
    "build.gradle": _parse_pom,
    "build.gradle.kts": _parse_pom,
    "Gemfile.lock": _parse_gemfile_lock,
    "composer.lock": _parse_composer_lock,
}

#: Directory names that hold dependency directories worth scanning.
DEPENDENCY_DIRS = ("node_modules",)


def collect_dependencies(root: str | Path) -> list[Dependency]:
    """Find and parse every dependency manifest under *root*."""
    root_path = Path(root).resolve()
    found: list[Dependency] = []
    seen: set[str] = set()

    manifests = [
        path
        for path in root_path.rglob("*")
        if path.is_file() and path.name in MANIFEST_ECOSYSTEMS
    ]
    # lockfiles are preferred but manifests are also useful
    for path in sorted(manifests, key=lambda p: (p.name.endswith(".lock") is False, str(p))):
        if any(part in {"node_modules", ".git", "vendor"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        parser = _PARSERS.get(path.name)
        if not parser:
            continue
        try:
            deps = parser(text, str(path.relative_to(root_path)))
        except Exception:
            continue
        for dep in deps:
            if dep.key in seen:
                continue
            seen.add(dep.key)
            found.append(dep)

    # A lockfile wins over the loose manifest for the same package.
    by_name: dict[tuple[str, str], Dependency] = {}
    for dep in found:
        key = (dep.ecosystem, dep.name)
        existing = by_name.get(key)
        if existing is None:
            by_name[key] = dep
            continue
        # Prefer a source that looks like a lockfile.
        if _is_lockfile(dep.source_file) and not _is_lockfile(existing.source_file):
            by_name[key] = dep
    return list(by_name.values())


def _is_lockfile(name: str) -> bool:
    lowered = name.lower()
    return any(
        token in lowered
        for token in ("lock", "lockfile", "resolved")
    )

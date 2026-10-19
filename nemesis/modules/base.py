"""The module plugin system.

Every capability of nemesis is a :class:`Module`. Modules are discovered
automatically from the built-in packages, from the ``nemesis_plugins``
entry-point group, and from a ``plugins/`` directory in the working tree.

A module declares what it needs via :attr:`Module.capability`, which lets the
engine skip it cleanly: a source-code module is never handed a network
client, and an active module is never run when the operator asked for
passive-only mode.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import logging
import pkgutil
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import DESTRUCTIVE_MODULES, ScanConfig
from ..http.client import HttpClient
from ..models import Capability, Category, Confidence, Endpoint, Finding, Form, Severity, Technology
from ..scope import Scope

log = logging.getLogger("nemesis.modules")


@dataclass
class ScanContext:
    """Everything a module is allowed to touch.

    Modules receive this and must not reach for global state. That rule is
    what makes third-party plugins safe to load.
    """

    config: ScanConfig
    scope: Scope
    client: HttpClient
    target_url: str
    host: str
    endpoints: list[Endpoint] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    responses: list[Any] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    code_path: str | None = None
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def has_tech(self, *names: str) -> bool:
        lowered = {t.name.lower() for t in self.technologies}
        return any(n.lower() in lowered for n in names)

    def tech_version(self, name: str) -> str | None:
        for tech in self.technologies:
            if tech.name.lower() == name.lower():
                return tech.version
        return None

    def interesting_params(self) -> list[str]:
        """Parameter names that are historically worth attacking."""
        from ..crawler.parser import INTERESTING_PARAMS

        found: set[str] = set()
        for endpoint in self.endpoints:
            found.update(endpoint.params.keys())
        for form in self.forms:
            found.update(form.raw_fields)
        ranked = [p for p in found if p.lower() in INTERESTING_PARAMS]
        return sorted(ranked) or sorted(found)


class Module:
    """Base class for every nemesis check.

    Subclasses set the class attributes and implement :meth:`run`.
    """

    id: str = ""
    name: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    category: Category = Category.INFO
    capability: Capability = Capability.PASSIVE
    #: Family this module belongs to, e.g. "headers", "injection", "code".
    #: Profiles select by group using the ``group/*`` syntax.
    group: str = "web"
    cwe: str | None = None
    owasp: str | None = None
    remediation: str = ""
    references: list[str] = []
    tags: list[str] = []
    author: str = "nemesis"
    version: str = "1.0.0"
    enabled_by_default: bool = True
    #: Abstract bases are never registered as runnable modules.
    abstract: bool = False

    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    # -- helpers ----------------------------------------------------------
    @property
    def is_destructive(self) -> bool:
        return self.capability == Capability.DESTRUCTIVE or self.id in DESTRUCTIVE_MODULES

    def finding(
        self,
        *,
        title: str,
        target: str,
        description: str,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        evidence_text: str = "",
        matched: str = "",
        remediation: str | None = None,
        **extra: Any,
    ) -> Finding:
        """Build a finding pre-populated with this module's metadata.

        ``file`` and ``line`` are lifted out of the free-form keyword
        arguments onto the finding itself, because the fingerprint is
        computed from them - a code finding without its location would
        collide with every other code finding in the same file.
        """
        extra = dict(extra)
        file_path = extra.pop("file", None)
        line_number = extra.pop("line", None)
        finding = Finding(
            title=title,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            description=description,
            target=target,
            module=self.id,
            category=self.category,
            remediation=remediation or self.remediation,
            cwe=self.cwe,
            owasp=self.owasp,
            references=list(self.references),
            tags=list(self.tags),
            file=str(file_path) if file_path else None,
            line=int(line_number) if line_number else None,
            evidence=_evidence(evidence_text, matched, extra),
        )
        return finding

    # -- entry point ------------------------------------------------------
    async def run(self, ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<Module {self.id}>"


def _evidence(text: str, matched: str, extra: dict[str, Any]):
    from ..http.client import redact
    from ..models import Evidence

    return Evidence(
        request="",
        response=redact(text) if text else "",
        matched=matched[:400] if matched else "",
        extra=dict(extra),
    )


class ModuleRegistry:
    """Discovers, filters and runs modules."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._modules: dict[str, Module] = {}

    # -- discovery --------------------------------------------------------
    def load_builtin(self) -> None:
        """Import every module under ``nemesis.modules``."""
        from .. import modules as modules_pkg

        for module_info in pkgutil.walk_packages(
            modules_pkg.__path__, prefix="nemesis.modules."
        ):
            self._import_module(module_info.name)

    def load_entry_points(self) -> None:
        """Load third-party modules registered under ``nemesis_plugins``."""
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover
            return
        try:
            points = entry_points()
            selected = (
                points.select(group="nemesis_plugins")
                if hasattr(points, "select")
                else points.get("nemesis_plugins", [])  # type: ignore[union-attr]
            )
        except Exception:  # pragma: no cover - defensive
            return
        for entry in selected:
            try:
                obj = entry.load()
                self._register_object(obj)
            except Exception as exc:
                log.warning("failed to load plugin %s: %s", entry.name, exc)

    def load_directory(self, path: str | Path) -> None:
        """Load ``*.py`` files from a plugin directory.

        Files inside the nemesis package are imported as part of it, so
        relative imports work. Files in an arbitrary directory are loaded
        standalone, which means they must use absolute imports
        (``from nemesis.models import ...``).
        """
        directory = Path(path)
        if not directory.is_dir():
            return
        import sys

        package = self._package_for(directory)
        sys.path.insert(0, str(directory))
        try:
            for file in sorted(directory.glob("*.py")):
                if file.name.startswith("_"):
                    continue
                module_name = (
                    f"{package}.{file.stem}" if package else f"nemesis_plugin_{file.stem}"
                )
                try:
                    spec = importlib.util.spec_from_file_location(module_name, file)
                    if spec is None or spec.loader is None:
                        continue
                    mod = importlib.util.module_from_spec(spec)
                    # A standalone plugin has no package, so relative imports
                    # inside it would fail; give it a clear error instead.
                    if not package:
                        mod.__package__ = ""
                    spec.loader.exec_module(mod)
                    self._register_object(mod)
                except Exception as exc:
                    log.warning(
                        "failed to load plugin file %s: %s "
                        "(plugins outside the nemesis package must use "
                        "absolute imports, e.g. 'from nemesis.models import ...')",
                        file,
                        exc,
                    )
        finally:
            if sys.path and sys.path[0] == str(directory):
                sys.path.pop(0)

    @staticmethod
    def _package_for(directory: Path) -> str | None:
        """The dotted package name of *directory* if it is inside nemesis."""
        import nemesis

        root = Path(nemesis.__file__).resolve().parent
        try:
            relative = directory.resolve().relative_to(root)
        except ValueError:
            return None
        parts = list(relative.parts)
        if not parts:
            return None
        return ".".join(["nemesis", *parts])

    def _import_module(self, name: str) -> None:
        try:
            mod = importlib.import_module(name)
        except Exception as exc:
            log.warning("failed to import %s: %s", name, exc)
            return
        self._register_object(mod)

    def _register_object(self, obj: Any) -> None:
        """Register every Module subclass found in *obj*.

        *obj* may be a module (the common case) or a class directly.
        """
        candidates: list[type] = []
        if inspect.isclass(obj):
            candidates.append(obj)
        elif inspect.ismodule(obj):
            for member in vars(obj).values():
                if inspect.isclass(member):
                    candidates.append(member)

        for candidate in candidates:
            if candidate is Module or not issubclass(candidate, Module):
                continue
            # Skip intermediate base classes that never implement run().
            if candidate.run is Module.run:
                continue
            if getattr(candidate, "__abstractmethods__", None):
                continue
            if not candidate.id:
                candidate.id = candidate.__name__.lower()
            try:
                instance = candidate(self.config)
            except Exception as exc:
                log.warning("could not instantiate %s: %s", candidate, exc)
                continue
            if instance.id in self._modules:
                continue
            self._modules[instance.id] = instance

    # -- selection --------------------------------------------------------
    @staticmethod
    def _matches_pattern(candidates: list[str], pattern: str) -> bool:
        """Does *pattern* match any of the module's selector names?

        A module can be selected by its plain id (``sqli``) or by its
        qualified name (``injection/sqli``), so profiles can address whole
        families without forcing a naming convention on module authors.
        """
        import fnmatch

        for candidate in candidates:
            if pattern == candidate:
                return True
            if pattern.endswith("/*") and candidate.startswith(pattern[:-1]):
                return True
            if "*" in pattern and fnmatch.fnmatch(candidate, pattern):
                return True
        return False

    def selected(self) -> list[Module]:
        """Apply include/exclude filters and capability restrictions."""
        chosen: list[Module] = []
        for module in self._modules.values():
            if not module.enabled_by_default:
                continue
            if module.is_destructive and not self.config.allow_destructive:
                continue
            candidates = [module.id, f"{module.group}/{module.id}"]
            if self.config.exclude_modules and any(
                self._matches_pattern(candidates, p) for p in self.config.exclude_modules
            ):
                continue
            if self.config.include_modules and not any(
                self._matches_pattern(candidates, p) for p in self.config.include_modules
            ):
                continue
            if self.config.module_tags and not (set(module.tags) & set(self.config.module_tags)):
                continue
            chosen.append(module)
        return sorted(chosen, key=lambda m: (m.capability.value, m.id))

    def by_id(self, module_id: str) -> Module | None:
        return self._modules.get(module_id)

    def all(self) -> list[Module]:
        return sorted(self._modules.values(), key=lambda m: m.id)

    # -- execution --------------------------------------------------------
    async def run(self, modules: Iterable[Module], ctx: ScanContext) -> list[Finding]:
        """Run modules concurrently, collecting findings and errors."""
        modules = list(modules)
        results = await asyncio.gather(
            *(self._run_one(m, ctx) for m in modules), return_exceptions=True
        )
        findings: list[Finding] = []
        for module, result in zip(modules, results, strict=False):
            if isinstance(result, BaseException):
                log.warning("module %s failed: %s", module.id, result)
                ctx.stats.setdefault("module_errors", {})[module.id] = str(result)
                continue
            findings.extend(result)
        return findings

    async def _run_one(self, module: Module, ctx: ScanContext) -> list[Finding]:
        limit = max(1, self.config.max_findings_per_module)
        try:
            found = await asyncio.wait_for(module.run(ctx), timeout=600)
        except asyncio.TimeoutError:
            log.warning("module %s timed out", module.id)
            ctx.stats.setdefault("module_timeouts", []).append(module.id)
            return []
        return list(found)[:limit]

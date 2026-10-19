"""The capability registry.

This is the map of what nemesis can actually do, and it is validated
against the real module registry: a capability that claims a module which
does not exist is a bug, and the test suite says so.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable

from ..config import ScanConfig
from ..modules.base import ModuleRegistry
from .catalog import CAPABILITIES
from .model import DOMAINS, MATURITY_ORDER, Capability

log = logging.getLogger(__name__)


def component_exists(component: str) -> bool:
    """Check that a ``package.module:Attribute`` path really resolves.

    The capability catalogue is a promise, and a promise that names a
    function that does not exist is a lie. This function is what makes the
    promise checkable.
    """
    import importlib

    module_path, _, attribute = component.partition(":")
    if not module_path or not attribute:
        return False
    try:
        module = importlib.import_module(module_path)
    except ImportError:
        return False
    return hasattr(module, attribute)


class CapabilityRegistry:
    """Holds every capability and knows which modules back them."""

    def __init__(self, capabilities: Iterable[Capability] | None = None) -> None:
        self._capabilities: dict[str, Capability] = {}
        for capability in capabilities if capabilities is not None else CAPABILITIES:
            if capability.id in self._capabilities:
                raise ValueError(f"duplicate capability id: {capability.id}")
            self._capabilities[capability.id] = capability

    # -- access ----------------------------------------------------------
    def all(self) -> list[Capability]:
        return list(self._capabilities.values())

    def get(self, capability_id: str) -> Capability | None:
        return self._capabilities.get(capability_id)

    def by_domain(self, domain: str) -> list[Capability]:
        return [c for c in self._capabilities.values() if c.domain == domain]

    def by_maturity(self, maturity: str) -> list[Capability]:
        return [c for c in self._capabilities.values() if c.maturity == maturity]

    def search(self, term: str) -> list[Capability]:
        """Case-insensitive search across name, summary and keywords."""
        needle = term.lower().strip()
        if not needle:
            return self.all()
        hits: list[Capability] = []
        for capability in self._capabilities.values():
            haystack = " ".join(
                (
                    capability.name,
                    capability.summary,
                    capability.domain,
                    " ".join(capability.keywords),
                    " ".join(capability.modules),
                    " ".join(capability.tools),
                )
            ).lower()
            if needle in haystack:
                hits.append(capability)
        return hits

    # -- coverage --------------------------------------------------------
    def coverage(self, module_ids: Iterable[str] | None = None) -> dict:
        """How much of the catalogue is actually implemented.

        *module_ids* is the set of modules nemesis really ships. A
        capability counts as ``backed`` when at least one of the modules it
        names is present.
        """
        if module_ids is None:
            module_ids = self.available_module_ids()
        module_ids = set(module_ids)

        counts: Counter[str] = Counter()
        backed = 0
        for capability in self._capabilities.values():
            counts[capability.maturity] += 1
            has_module = bool(
                capability.modules and module_ids.intersection(capability.modules)
            )
            has_component = any(
                component_exists(component) for component in capability.components
            )
            if has_module or has_component:
                backed += 1

        total = len(self._capabilities)
        return {
            "total": total,
            "by_maturity": {
                maturity: counts.get(maturity, 0) for maturity in MATURITY_ORDER
            },
            "backed": backed,
            "backed_percent": round(100.0 * backed / total, 1) if total else 0.0,
            "native": sum(1 for c in self._capabilities.values() if c.maturity == "native"),
            "implementable": sum(
                1 for c in self._capabilities.values() if c.is_implemented
            ),
        }

    @staticmethod
    def available_module_ids() -> set[str]:
        """The module ids nemesis actually ships."""
        registry = ModuleRegistry(ScanConfig())
        registry.load_builtin()
        registry.load_entry_points()
        return {module.id for module in registry.all()}

    def validate(self, module_ids: Iterable[str] | None = None) -> list[str]:
        """Return the problems in the catalogue.

        An empty list means the catalogue is honest: every module and
        every component it names exists, and every capability claiming to
        be native has something real behind it.
        """
        if module_ids is None:
            module_ids = self.available_module_ids()
        module_ids = set(module_ids)

        problems: list[str] = []
        for capability in self._capabilities.values():
            if capability.domain not in DOMAINS:
                problems.append(
                    f"{capability.id}: unknown domain '{capability.domain}'"
                )
            if capability.maturity not in MATURITY_ORDER:
                problems.append(
                    f"{capability.id}: unknown maturity '{capability.maturity}'"
                )
            for module_id in capability.modules:
                if module_id not in module_ids:
                    problems.append(
                        f"{capability.id}: claims module '{module_id}', which does not exist"
                    )
            for component in capability.components:
                if not component_exists(component):
                    problems.append(
                        f"{capability.id}: claims component '{component}', "
                        f"which does not exist"
                    )
            if capability.maturity == "native" and not (
                capability.modules or capability.components
            ):
                problems.append(
                    f"{capability.id}: marked native but names no module or component"
                )
        return problems

    def domain_summary(self) -> dict[str, dict]:
        """Per-domain counts, strongest maturity first."""
        summary: dict[str, dict] = {}
        for capability in self._capabilities.values():
            entry = summary.setdefault(
                capability.domain,
                {"label": capability.domain_label, "total": 0, "strongest": "manual"},
            )
            entry["total"] += 1
            if capability.strength > MATURITY_ORDER.index(entry["strongest"]):
                entry["strongest"] = capability.maturity
        return summary

    def to_dict(self) -> dict:
        return {
            "capabilities": [c.to_dict() for c in self._capabilities.values()],
            "coverage": self.coverage(),
        }


#: A ready-to-use registry.
CAPABILITY_REGISTRY = CapabilityRegistry()

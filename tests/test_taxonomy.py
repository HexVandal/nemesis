"""The taxonomy denominator, and the rules that keep it honest.

A coverage claim is only worth the arithmetic behind it. These tests check
that the catalogue is complete, contiguous and points at modules that exist.
"""

from __future__ import annotations

from nemesis.config import ScanConfig
from nemesis.knowledge.taxonomy import (
    CATEGORIES,
    VERDICTS,
    all_classes,
    by_verdict,
    coverage_ratio,
)
from nemesis.modules.base import ModuleRegistry


class TestShape:
    def test_the_taxonomy_has_the_expected_size(self):
        assert all_classes() == 2883

    def test_every_class_is_accounted_for_exactly_once(self):
        """Ranges must be contiguous: 1..2883 with no gap and no overlap."""
        covered: list[int] = []
        for family in CATEGORIES:
            covered.extend(range(family.first_class, family.last_class + 1))
        assert covered == list(range(1, 2884))

    def test_family_numbers_are_unique(self):
        numbers = [f.number for f in CATEGORIES]
        assert len(numbers) == len(set(numbers))

    def test_every_family_has_a_known_verdict(self):
        for family in CATEGORIES:
            assert family.verdict in VERDICTS, f"{family.name}: {family.verdict}"

    def test_every_family_carries_a_reason(self):
        for family in CATEGORIES:
            assert family.note.strip(), f"{family.name} has no note"


class TestHonesty:
    def test_reachable_share_is_below_one_hundred(self):
        """A tool that claims the whole taxonomy is lying about the hardware rows."""
        assert 0 < coverage_ratio() < 100

    def test_some_families_are_declared_out_of_scope(self):
        assert any(f.verdict == "out-of-scope" for f in CATEGORIES)

    def test_verdict_counts_add_up(self):
        assert sum(by_verdict().values()) == all_classes()

    def test_scanner_engineering_is_measured_against_itself(self):
        family = next(f for f in CATEGORIES if f.number == 50)
        assert family.verdict == "self"


class TestModulesExist:
    def test_every_referenced_module_is_in_the_registry(self):
        registry = ModuleRegistry(ScanConfig())
        registry.load_builtin()
        missing = {
            module
            for family in CATEGORIES
            for module in family.modules
            if module not in registry._modules
        }
        assert not missing, f"taxonomy references modules that do not exist: {sorted(missing)}"

    def test_http_families_actually_have_modules(self):
        """A family claimed testable over HTTP must point at something."""
        for family in CATEGORIES:
            if family.verdict == "http":
                assert family.modules, f"{family.name} claims HTTP testing but names no module"

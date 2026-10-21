"""Tests for the capability registry.

The registry's whole value depends on it being honest, so the most
important test in this file is the one that asserts the catalogue names
nothing that does not exist.
"""

from __future__ import annotations

import pytest

from nemesis.capabilities import (
    CAPABILITY_REGISTRY,
    DOMAINS,
    MATURITY_LABELS,
    MATURITY_ORDER,
    Capability,
    CapabilityRegistry,
)
from nemesis.capabilities.registry import component_exists


def test_catalogue_is_honest():
    """Every module and component the catalogue names must really exist."""
    problems = CAPABILITY_REGISTRY.validate()
    assert problems == [], f"capability catalogue is dishonest: {problems}"


def test_every_capability_is_unique_and_counted():
    capabilities = CAPABILITY_REGISTRY.all()
    assert len(capabilities) == 108
    ids = [c.id for c in capabilities]
    assert len(set(ids)) == len(ids), "duplicate capability id"


def test_every_capability_has_a_known_domain_and_maturity():
    for capability in CAPABILITY_REGISTRY.all():
        assert capability.domain in DOMAINS
        assert capability.maturity in MATURITY_ORDER
        assert capability.maturity in MATURITY_LABELS
        assert capability.summary.strip()
        assert capability.name.strip()


def test_native_capabilities_name_something_real():
    """A 'native' claim with nothing behind it is a lie."""
    for capability in CAPABILITY_REGISTRY.by_maturity("native"):
        assert capability.modules or capability.components, (
            f"{capability.id} claims to be native but names nothing"
        )


def test_duplicate_capability_id_is_rejected():
    with pytest.raises(ValueError, match="duplicate"):
        CapabilityRegistry(
            [
                Capability(id="x", name="X", domain="web", maturity="manual", summary="s"),
                Capability(id="x", name="X", domain="web", maturity="manual", summary="s"),
            ]
        )


def test_search_finds_capabilities():
    hits = CAPABILITY_REGISTRY.search("smuggling")
    assert hits
    assert any("smuggl" in c.id for c in hits)

    assert CAPABILITY_REGISTRY.search("") == CAPABILITY_REGISTRY.all()
    assert CAPABILITY_REGISTRY.search("zzzznotathing") == []


def test_by_domain_and_by_maturity():
    web = CAPABILITY_REGISTRY.by_domain("web")
    assert web
    assert all(c.domain == "web" for c in web)

    native = CAPABILITY_REGISTRY.by_maturity("native")
    assert native
    assert all(c.maturity == "native" for c in native)


def test_coverage_reports_the_truth():
    coverage = CAPABILITY_REGISTRY.coverage()
    assert coverage["total"] == 108
    assert sum(coverage["by_maturity"].values()) == 108
    assert coverage["backed"] <= coverage["total"]
    # Every maturity level must appear in the breakdown.
    for level in MATURITY_ORDER:
        assert level in coverage["by_maturity"]


def test_coverage_rejects_a_bogus_module_set():
    """A capability cannot be backed by a module that does not exist."""
    coverage = CAPABILITY_REGISTRY.coverage(module_ids=set())
    # Components still back their capabilities, but nothing is module-backed.
    assert coverage["backed"] < CAPABILITY_REGISTRY.coverage()["backed"]


def test_domain_summary():
    summary = CAPABILITY_REGISTRY.domain_summary()
    assert set(summary) == set(DOMAINS)
    for domain, entry in summary.items():
        assert entry["total"] >= 1
        assert entry["strongest"] in MATURITY_ORDER


def test_component_exists_checks_real_imports():
    assert component_exists("nemesis.knowledge.cvss:CvssVector")
    assert not component_exists("nemesis.knowledge.cvss:NoSuchThing")
    assert not component_exists("nemesis.no.such.module:Thing")
    assert not component_exists("no-colon-here")


def test_to_dict_is_serialisable():
    data = CAPABILITY_REGISTRY.to_dict()
    assert "capabilities" in data
    assert "coverage" in data
    first = data["capabilities"][0]
    assert "maturity_label" in first
    assert "components" in first


def test_every_capability_area_has_a_library_resource():
    """The knowledge layer must not have holes.

    `nemesis knowledge --area <id>` is a documented command. An area with no
    resource prints an empty table, which reads as "there is nothing worth
    reading about this", not "the index is missing". Every capability area
    therefore has to name at least one resource.
    """
    from nemesis.knowledge.library import Library

    covered = {resource.area for resource in Library().all()}
    missing = sorted({c.id for c in CAPABILITY_REGISTRY.all()} - covered)
    assert missing == [], f"capability areas with no library resource: {missing}"


def test_library_entries_are_well_formed():
    """Ids are unique, kinds are known, and every entry has a URL and a note."""
    from nemesis.knowledge.library import KINDS, Library

    resources = Library().all()
    ids = [r.id for r in resources]
    assert len(ids) == len(set(ids)), "duplicate resource id"

    for resource in resources:
        assert resource.kind in KINDS, f"{resource.id} has an unknown kind"
        assert resource.url.startswith(("http://", "https://")), resource.id
        assert resource.note, f"{resource.id} has no note explaining why it matters"
        assert resource.hours >= 0, resource.id

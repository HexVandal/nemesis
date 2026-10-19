"""Tests for the report generators.

The reporting layer is where a scan becomes something a person can act
on: a YARA rule, a Sigma rule, a disclosure report, a public write-up, or
a triage worklist.

The property that matters most in all of them is **restraint**. A
generator that emits a detection rule for every finding produces a ruleset
nobody will maintain, and a report generator that says the same thing
about every finding produces a report nobody will read.
"""

from __future__ import annotations

import pytest

from nemesis.models import Category, Confidence, Evidence, Finding, Severity
from nemesis.reporting.disclosure import DisclosureReportBuilder
from nemesis.reporting.sigma import SigmaRuleBuilder
from nemesis.reporting.triage import TriageEngine
from nemesis.reporting.writeup import WriteupBuilder
from nemesis.reporting.yara import YaraRuleBuilder


def make_finding(**kwargs) -> Finding:
    defaults = {
        "title": "SQL injection in /search",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "description": "The q parameter is concatenated into a SQL query.",
        "target": "https://app.example.com/search?q=x",
        "module": "sqli",
        "category": Category.INJECTION,
        "remediation": "Use a parameterised query.",
        "cwe": "CWE-89",
        "owasp": "A03",
        "evidence": Evidence(
            request="GET /search?q=%27 HTTP/1.1",
            response="HTTP/1.1 500\nSQL syntax error near ''",
            matched="%27",
            extra={"payload": "%27 OR 1=1--"},
        ),
        "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        "tags": ["sqli", "injection"],
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# ----------------------------------------------------------------------
# YARA
# ----------------------------------------------------------------------
def test_yara_generates_a_rule_for_a_known_module():
    builder = YaraRuleBuilder()
    rules = builder.build([make_finding(module="dangerous_patterns")])
    assert rules
    text = builder.to_text(rules)
    assert "rule nemesis_" in text
    assert "meta:" in text
    assert "strings:" in text
    assert "condition:" in text


def test_yara_refuses_to_emit_a_rule_for_an_unknown_module():
    builder = YaraRuleBuilder()
    rules = builder.build([make_finding(module="headers_security")])
    assert rules == []
    assert builder.skipped


def test_yara_skips_indicators_that_are_too_short_to_be_specific():
    builder = YaraRuleBuilder()
    finding = make_finding(
        module="secrets",
        evidence=Evidence(matched="abc", extra={"secret": "abc"}),
    )
    rules = builder.build([finding])
    assert rules == []
    assert builder.skipped
    assert "short" in builder.skipped[0][1].lower()


def test_yara_skips_indicators_that_are_noise():
    builder = YaraRuleBuilder()
    finding = make_finding(
        module="secrets",
        evidence=Evidence(matched="the", extra={"secret": "the"}),
    )
    assert builder.build([finding]) == []
    assert builder.skipped


def test_yara_output_is_escaped():
    builder = YaraRuleBuilder()
    finding = make_finding(
        module="secrets",
        evidence=Evidence(matched='AKIA"quoted\\value', extra={"secret": 'AKIA"quoted\\value'}),
    )
    rules = builder.build([finding])
    text = builder.to_text(rules)
    # The raw quote must not break out of the YARA string literal.
    assert '\\"' in text


def test_yara_rule_names_are_valid_identifiers():
    builder = YaraRuleBuilder()
    rules = builder.build(
        [
            make_finding(
                module="secrets",
                evidence=Evidence(matched="AKIAIOSFODNN7EXAMPLE", extra={"secret": "AKIAIOSFODNN7EXAMPLE"}),
            )
        ]
    )
    for rule in rules:
        assert rule.name.replace("_", "").isalnum()
        assert not rule.name[0].isdigit()


# ----------------------------------------------------------------------
# Sigma
# ----------------------------------------------------------------------
def test_sigma_generates_a_rule_for_an_injection_finding():
    builder = SigmaRuleBuilder()
    rules = builder.build([make_finding()])
    assert rules
    text = builder.to_text(rules)
    assert "title:" in text
    assert "logsource:" in text
    assert "detection:" in text
    assert "condition: selection" in text
    assert "level: high" in text


def test_sigma_rule_is_valid_yaml_shape():
    builder = SigmaRuleBuilder()
    rules = builder.build([make_finding()])
    data = rules[0].to_dict()
    assert data["title"]
    assert data["id"]
    assert data["logsource"]["category"] == "webserver"
    assert "selection" in data["detection"]


def test_sigma_skips_findings_with_no_log_source():
    builder = SigmaRuleBuilder()
    rules = builder.build([make_finding(module="secrets")])
    assert rules == []
    assert builder.skipped
    assert "log source" in builder.skipped[0][1]


def test_sigma_ids_are_unique():
    builder = SigmaRuleBuilder()
    rules = builder.build([make_finding(), make_finding(target="https://other/x")])
    assert len({r.id for r in rules}) == len(rules)


# ----------------------------------------------------------------------
# Disclosure reports
# ----------------------------------------------------------------------
@pytest.mark.parametrize("programme", ["hackerone", "bugcrowd", "intigriti"])
def test_disclosure_report_has_the_required_sections(programme):
    builder = DisclosureReportBuilder(programme, asset="https://app.example.com")
    report = builder.build(make_finding())
    body = report.to_markdown()
    assert "## Summary" in body
    assert "## Severity" in body
    assert "## Steps to reproduce" in body
    assert "## Impact" in body
    assert "## Remediation" in body
    assert "## Disclosure" in body
    assert report.severity_label
    assert report.assets == ["https://app.example.com"]


def test_bugcrowd_uses_priority_labels():
    builder = DisclosureReportBuilder("bugcrowd")
    report = builder.build(make_finding(severity=Severity.CRITICAL))
    assert report.severity_label == "P1"
    assert "Priority" in report.fields


def test_hackerone_uses_weakness_field():
    builder = DisclosureReportBuilder("hackerone")
    report = builder.build(make_finding())
    assert report.fields["Weakness"] == "CWE-89"
    assert report.fields["Severity"] == "High"


def test_unknown_programme_is_rejected():
    with pytest.raises(ValueError, match="unknown programme"):
        DisclosureReportBuilder("cerberus")


def test_disclosure_report_serialises():
    builder = DisclosureReportBuilder("intigriti")
    data = builder.build(make_finding()).to_dict()
    assert data["programme"] == "intigriti"
    assert data["cwe"] == "CWE-89"
    assert data["body_markdown"]
    assert data["disclosure_deadline"]


def test_disclosure_html_escapes_the_title():
    builder = DisclosureReportBuilder("hackerone")
    finding = make_finding(title="<script>alert(1)</script>")
    html = builder.build(finding).to_html()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ----------------------------------------------------------------------
# Write-up
# ----------------------------------------------------------------------
def test_writeup_has_the_right_sections():
    builder = WriteupBuilder(author="tester")
    writeup = builder.build([make_finding()])
    body = writeup.to_markdown()
    assert "# " in body
    assert "## Methodology" in body
    assert "## Findings" in body
    assert "## Limitations" in body
    assert "## Conclusion" in body
    assert "Why it works" in body
    assert "tester" in body


def test_writeup_states_its_limits():
    """A write-up that claims completeness is making a claim it cannot support."""
    builder = WriteupBuilder()
    body = builder.build([make_finding()]).to_markdown()
    assert "not a census" in body
    assert "draft" in body.lower()


def test_writeup_handles_no_findings():
    builder = WriteupBuilder()
    writeup = builder.build([])
    assert writeup.body_markdown
    assert "no findings" in writeup.body_markdown.lower()


def test_writeup_groups_by_severity():
    builder = WriteupBuilder()
    findings = [
        make_finding(severity=Severity.CRITICAL, title="Critical thing"),
        make_finding(severity=Severity.LOW, title="Low thing"),
    ]
    body = builder.build(findings).to_markdown()
    assert body.index("Critical thing") < body.index("Low thing")


# ----------------------------------------------------------------------
# Triage
# ----------------------------------------------------------------------
def test_triage_ranks_a_proven_critical_above_an_unproven_medium():
    engine = TriageEngine()
    items = engine.triage(
        [
            make_finding(
                title="Medium but unproven",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
            ),
            make_finding(
                title="Critical and proven",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
            ),
        ]
    )
    assert items[0].finding.title == "Critical and proven"


def test_triage_collapses_duplicate_root_causes():
    engine = TriageEngine()
    findings = [
        make_finding(title="SQLi in /a", target="https://app.example.com/a"),
        make_finding(title="SQLi in /b", target="https://app.example.com/b"),
    ]
    plan = engine.plan(findings)
    assert plan["total_findings"] == 2
    assert plan["worklist_size"] == 1
    assert plan["collapsed"] == 1


def test_triage_bands_are_assigned():
    engine = TriageEngine()
    items = engine.triage([make_finding()])
    assert items[0].band in ("act-now", "schedule", "backlog", "note")


def test_triage_explains_itself():
    engine = TriageEngine()
    items = engine.triage([make_finding()])
    assert items[0].reasons
    assert any("impact" in reason for reason in items[0].reasons)
    assert any("confidence" in reason for reason in items[0].reasons)


def test_triage_penalises_weak_evidence():
    engine = TriageEngine()
    strong = engine.triage([make_finding(evidence=Evidence(response="SQL syntax error"))])
    weak = engine.triage([make_finding(evidence=Evidence(response="404 not found"))])
    assert strong[0].evidence > weak[0].evidence


def test_triage_plan_is_serialisable():
    engine = TriageEngine()
    plan = engine.plan([make_finding()])
    assert set(plan["bands"]) == {"act-now", "schedule", "backlog", "note"}
    assert plan["items"][0]["priority"] >= 0

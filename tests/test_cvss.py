"""Tests for the CVSS v3.1 base score calculation.

The expected values are taken from published CVSS v3.1 reference vectors.
"""

from __future__ import annotations

import dataclasses

import pytest

from nemesis.knowledge.cvss import CvssVector, parse_vector, score_of, severity_of


@pytest.mark.parametrize(
    "vector,expected",
    [
        # The canonical "worst case" vector.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        # Scope changed - the specification applies a 1.08 multiplier here.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N", 7.2),
        # The textbook reflected-XSS vector: 6.1 Medium.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        # Heartbleed, a well known 7.5.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ],
)
def test_base_scores(vector, expected):
    assert score_of(vector) == pytest.approx(expected, abs=0.05)


def test_score_is_zero_when_no_impact():
    assert score_of("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_parse_roundtrip():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    parsed = parse_vector(vector)
    assert parsed is not None
    assert parsed.vector == vector
    assert parsed.base_score == 9.8


def test_parse_without_prefix():
    parsed = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert parsed is not None
    assert parsed.base_score == 9.8


def test_parse_garbage_returns_none():
    assert parse_vector("not a vector") is None
    assert parse_vector("") is None
    assert score_of("nonsense") is None


@pytest.mark.parametrize(
    "vector,band",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CRITICAL"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "HIGH"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", "MEDIUM"),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", "LOW"),
    ],
)
def test_severity_bands(vector, band):
    assert severity_of(vector) == band


def test_vector_is_frozen():
    vector = CvssVector()
    with pytest.raises(dataclasses.FrozenInstanceError):
        vector.av = "L"  # type: ignore[misc]

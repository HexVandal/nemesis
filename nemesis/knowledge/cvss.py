"""CVSS v3.1 base score calculation.

External advisory feeds rarely give you a number - they give you a vector
string such as ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``. To map an
advisory onto a severity band you have to be able to evaluate the vector,
so this module implements the base score formula from the CVSS v3.1
specification.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

#: Attack Vector
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
#: Attack Complexity
_AC = {"L": 0.77, "H": 0.44}
#: Privileges Required, keyed by (scope changed, value)
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
#: User Interaction
_UI = {"N": 0.85, "R": 0.62}
#: Confidentiality / Integrity / Availability impact
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}

_VECTOR_RE = re.compile(r"(?:CVSS:3\.[01]/)?([A-Z]{1,2}:[A-Z])")


@dataclass(frozen=True)
class CvssVector:
    """A parsed CVSS v3.x base vector."""

    av: str = "N"
    ac: str = "L"
    pr: str = "N"
    ui: str = "N"
    scope: str = "U"
    c: str = "N"
    i: str = "N"
    a: str = "N"

    @property
    def vector(self) -> str:
        return (
            f"CVSS:3.1/AV:{self.av}/AC:{self.ac}/PR:{self.pr}/UI:{self.ui}/"
            f"S:{self.scope}/C:{self.c}/I:{self.i}/A:{self.a}"
        )

    @property
    def base_score(self) -> float:
        return self.score()

    def score(self) -> float:
        """Compute the CVSS v3.1 base score."""
        scope_changed = self.scope == "C"
        impact_sub = 1 - (1 - _CIA[self.c]) * (1 - _CIA[self.i]) * (1 - _CIA[self.a])
        if scope_changed:
            impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
        else:
            impact = 6.42 * impact_sub

        if impact <= 0:
            return 0.0

        privileges = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        exploitability = (
            8.22
            * _AV[self.av]
            * _AC[self.ac]
            * privileges[self.pr]
            * _UI[self.ui]
        )
        # The specification multiplies the sum by 1.08 when the scope changes.
        if scope_changed:
            return _round_up(min(1.08 * (impact + exploitability), 10.0))
        return _round_up(min(impact + exploitability, 10.0))


def _round_up(value: float) -> float:
    """The CVSS 3.1 "Roundup" function: round to one decimal, upwards."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def parse_vector(vector: str) -> CvssVector | None:
    """Parse a CVSS v3.x vector string into a :class:`CvssVector`."""
    if not vector:
        return None
    metrics: dict[str, str] = {}
    for match in _VECTOR_RE.finditer(vector):
        key, _, value = match.group(1).partition(":")
        metrics[key] = value
    if "AV" not in metrics:
        return None
    return CvssVector(
        av=metrics.get("AV", "N"),
        ac=metrics.get("AC", "L"),
        pr=metrics.get("PR", "N"),
        ui=metrics.get("UI", "N"),
        scope=metrics.get("S", "U"),
        c=metrics.get("C", "N"),
        i=metrics.get("I", "N"),
        a=metrics.get("A", "N"),
    )


def score_of(vector: str) -> float | None:
    """Base score for a CVSS v3.x vector string, or ``None`` if unparseable."""
    parsed = parse_vector(vector)
    return parsed.score() if parsed else None


def severity_of(vector: str) -> str | None:
    """Map a CVSS v3.x vector onto a severity band name."""
    score = score_of(vector)
    if score is None:
        return None
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"

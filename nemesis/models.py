"""Core data models shared across every layer of the scanner.

These types are the contract between modules, the verifier and the reporters.
They are deliberately plain dataclasses so a finding can be serialised to JSON
or SARIF without ceremony, and so third-party plugin authors never need to
import framework internals.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> str:
    """ISO-8601 UTC timestamp, second precision, always suffixed with Z."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Severity(int, Enum):
    """Severity of a finding. Ordered so ``max()`` picks the worst."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "cyan",
            Severity.LOW: "blue",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "dark_orange",
            Severity.CRITICAL: "bold red",
        }[self]

    def to_cvss_base(self) -> float:
        """Rough CVSS v3.1 base-score band for a finding of this severity.

        Used only when a module does not supply a precise vector; a real
        vector always wins because it is derived from the actual impact.
        """
        return {
            Severity.INFO: 0.0,
            Severity.LOW: 3.1,
            Severity.MEDIUM: 6.5,
            Severity.HIGH: 8.1,
            Severity.CRITICAL: 9.8,
        }[self]


class Confidence(str, Enum):
    """How sure we are that a finding is real.

    This is the single most important field in the report. A scanner that
    cannot express doubt is a scanner that produces noise. nemesis computes
    confidence from differential analysis, never from a module's optimism.
    """

    CONFIRMED = "confirmed"   # proof reproduced independently of the payload
    HIGH = "high"             # strong differential signal, very low FP risk
    MEDIUM = "medium"         # plausible signal, needs a human glance
    LOW = "low"               # heuristic only
    INFO = "info"             # observation, not a defect

    @property
    def rank(self) -> int:
        return {
            Confidence.CONFIRMED: 5,
            Confidence.HIGH: 4,
            Confidence.MEDIUM: 3,
            Confidence.LOW: 2,
            Confidence.INFO: 1,
        }[self]

    @property
    def color(self) -> str:
        return {
            Confidence.CONFIRMED: "bold green",
            Confidence.HIGH: "green",
            Confidence.MEDIUM: "yellow",
            Confidence.LOW: "yellow",
            Confidence.INFO: "dim",
        }[self]


class Capability(str, Enum):
    """What a module needs in order to run.

    The engine uses this to decide which modules are applicable to a target
    and to honour operator restrictions.
    """

    PASSIVE = "passive"     # only reads what the crawler already fetched
    HTTP = "http"           # sends crafted HTTP requests to the target
    HOST = "host"           # touches the host/network (TLS, DNS, ports)
    CODE = "code"           # reads local source code
    DEPS = "deps"           # reads local dependency manifests
    DESTRUCTIVE = "destructive"  # may change state; requires explicit opt-in


class Category(str, Enum):
    """High-level taxonomy, used for grouping and reporting."""

    DISCLOSURE = "disclosure"
    INJECTION = "injection"
    AUTH = "auth"
    CRYPTO = "crypto"
    CONFIG = "config"
    TRAVERSAL = "traversal"
    SSRF = "ssrf"
    XSS = "xss"
    SUPPLY_CHAIN = "supply-chain"
    TRANSPORT = "transport"
    DOS = "dos"
    BUG = "bug"
    INFO = "info"


@dataclass
class Evidence:
    """Everything needed to independently reproduce a finding.

    ``request`` and ``response`` are redacted before they get here, so it is
    safe to include in a report that will be shared.
    """

    request: str = ""
    response: str = ""
    matched: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """A single security defect or bug discovered by a module."""

    title: str
    severity: Severity
    confidence: Confidence
    description: str
    target: str
    module: str
    category: Category = Category.INFO
    remediation: str = ""
    cwe: str | None = None
    owasp: str | None = None
    cvss: str | None = None
    cvss_score: float | None = None
    evidence: Evidence = field(default_factory=Evidence)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    fingerprint: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(default_factory=utcnow)
    file: str | None = None
    line: int | None = None

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()
        # A module may supply a real vector and score; otherwise the score
        # falls back to the band for this severity. Leaving it None meant
        # every report carried `cvss_score: null` while the fallback sat
        # unused one class up.
        if self.cvss_score is None and not self.cvss:
            self.cvss_score = self.severity.to_cvss_base()

    def compute_fingerprint(self) -> str:
        """Stable identity for a finding, used to deduplicate across modules."""
        raw = "|".join(
            [
                self.module,
                self.title,
                self.target,
                self.file or "",
                str(self.line or ""),
            ]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.name
        data["confidence"] = self.confidence.value
        data["category"] = self.category.value
        data["evidence"] = self.evidence.to_dict()
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


@dataclass
class Endpoint:
    """A discovered HTTP endpoint, with everything known about it."""

    url: str
    method: str = "GET"
    status: int | None = None
    title: str = ""
    content_type: str = ""
    length: int = 0
    depth: int = 0
    params: dict[str, str] = field(default_factory=dict)
    forms: list[dict[str, Any]] = field(default_factory=list)
    source: str = "crawl"
    tags: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method} {self.url}"


@dataclass
class Form:
    """An HTML form discovered by the crawler."""

    action: str
    method: str
    fields: dict[str, str] = field(default_factory=dict)
    raw_fields: list[str] = field(default_factory=list)
    has_file_upload: bool = False
    source_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Technology:
    """A fingerprinted technology with optional version."""

    name: str
    version: str | None = None
    category: str = "unknown"
    confidence: Confidence = Confidence.MEDIUM
    source: str = ""

    def __str__(self) -> str:
        return f"{self.name} {self.version}".strip()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Target:
    """The thing being scanned."""

    base_url: str
    host: str = ""
    scheme: str = "https"
    port: int | None = None
    name: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.base_url


@dataclass
class ScanResult:
    """Everything a completed scan produced."""

    target: Target
    findings: list[Finding] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    # -- severity helpers -------------------------------------------------
    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    def confirmed(self) -> list[Finding]:
        """Findings whose confidence is CONFIRMED.

        HIGH is a different label and is deliberately excluded: a header
        is observed with high confidence, but nothing was proven by an
        experiment. Collapsing the two made every passive finding look
        like it had been verified.
        """
        return [f for f in self.findings if f.confidence is Confidence.CONFIRMED]

    def high_confidence(self) -> list[Finding]:
        """Findings observed with high confidence but not proven."""
        return [f for f in self.findings if f.confidence is Confidence.HIGH]

    def risk_score(self) -> float:
        """A 0-100 aggregate risk score weighted by severity and confidence.

        Confirmed criticals dominate; speculative low-severity noise barely
        moves the number. This keeps the headline honest.
        """
        weights = {
            Severity.CRITICAL: 40.0,
            Severity.HIGH: 20.0,
            Severity.MEDIUM: 8.0,
            Severity.LOW: 3.0,
            Severity.INFO: 0.0,
        }
        confidence_factors = {
            Confidence.CONFIRMED: 1.0,
            Confidence.HIGH: 0.9,
            Confidence.MEDIUM: 0.6,
            Confidence.LOW: 0.3,
            Confidence.INFO: 0.1,
        }
        raw = sum(
            weights[f.severity] * confidence_factors[f.confidence] for f in self.findings
        )
        # Saturating curve: 1 critical confirmed ~= 60, a pile of mediums ~= 45.
        return round(min(100.0, 100.0 * (1 - pow(2.718281828, -raw / 55.0))), 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": asdict(self.target),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": self.duration_seconds,
            "stats": self.stats,
            "counts": self.counts(),
            "risk_score": self.risk_score(),
            "technologies": [t.to_dict() for t in self.technologies],
            "endpoints": [asdict(e) for e in self.endpoints],
            "forms": [f.to_dict() for f in self.forms],
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }

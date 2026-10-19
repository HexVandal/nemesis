"""Differential analysis and confidence scoring.

The core idea: a candidate finding is only real if the response *differs
because of our payload* in a way we can explain. We send a benign baseline
request, send the same request with a payload, and compare:

* HTTP status
* body length
* response time
* error signatures present in the probe but absent in the baseline
* **where and how the payload was reflected**

That last one matters most. A payload reflected HTML-escaped in a page is a
non-finding; the same payload reflected verbatim inside a ``<script>`` block
is a confirmed XSS. Most scanners cannot tell the difference, which is why
their reports are full of junk.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from enum import Enum

from ..http.client import Response
from ..models import Confidence

#: Time delta (seconds) above which a blind injection is considered real.
BLIND_TIME_THRESHOLD = 2.0

#: Body length change (absolute and relative) that suggests a behavioural
#: change even when no error signature is present.
LENGTH_DELTA_THRESHOLD = 20
LENGTH_RATIO_THRESHOLD = 0.15

#: Shortest payload that can be meaningfully searched for in a response body.
MIN_REFLECTION_LENGTH = 3
#: Shortest payload that can be meaningfully searched for in a header value.
MIN_HEADER_REFLECTION_LENGTH = 8


class ReflectionContext(str, Enum):
    """Where in the response a payload was reflected."""

    HTML_TEXT = "html_text"
    HTML_ATTRIBUTE = "html_attribute"
    SCRIPT = "script"
    STYLE = "style"
    URL = "url"
    HEADER = "header"
    COOKIE = "cookie"
    JSON_STRING = "json_string"
    XML = "xml"
    UNKNOWN = "unknown"

    @property
    def is_executable(self) -> bool:
        """Does reflection in this context lead to code execution?"""
        return self in (ReflectionContext.SCRIPT, ReflectionContext.HTML_ATTRIBUTE)


@dataclass
class Reflection:
    """One occurrence of the payload inside a response."""

    context: ReflectionContext
    verbatim: bool
    index: int
    snippet: str = ""
    #: True when the payload contains characters that let it escape the
    #: context it was reflected into.
    can_break_out: bool = False

    @property
    def is_dangerous(self) -> bool:
        """Verbatim reflection that can escape its context is a real XSS.

        Reflecting ``<script>alert(1)</script>`` verbatim into HTML text is
        just as exploitable as reflecting it into an attribute, so the
        verdict depends on the *payload* as well as the context.
        """
        return self.verbatim and (self.context.is_executable or self.can_break_out)


@dataclass
class Delta:
    """The difference between a baseline response and a probed response."""

    baseline: Response
    probe: Response
    status_delta: int = 0
    length_delta: int = 0
    length_ratio: float = 1.0
    time_delta: float = 0.0
    reflections: list[Reflection] = field(default_factory=list)
    new_signatures: list[tuple[str, str]] = field(default_factory=list)
    baseline_signatures: list[tuple[str, str]] = field(default_factory=list)

    @property
    def is_noop(self) -> bool:
        """Nothing changed - the payload had no effect at all."""
        return (
            self.status_delta == 0
            and abs(self.length_delta) < LENGTH_DELTA_THRESHOLD
            and self.time_delta < 1.0
            and not self.new_signatures
            and not self.reflections
        )

    @property
    def has_behaviour_change(self) -> bool:
        return (
            self.status_delta != 0
            or abs(self.length_delta) >= LENGTH_DELTA_THRESHOLD
            or abs(self.length_ratio - 1.0) >= LENGTH_RATIO_THRESHOLD
            or self.time_delta >= BLIND_TIME_THRESHOLD
            or bool(self.new_signatures)
        )

    @property
    def dangerous_reflections(self) -> list[Reflection]:
        return [r for r in self.reflections if r.is_dangerous]

    def describe(self, payload: str = "") -> str:
        """Render the experiment as a readable proof.

        This is the text that goes into a finding's evidence, and it is
        the part a reader actually trusts: it shows the baseline, the
        probe, and exactly what changed between them.
        """
        lines = [
            f"Baseline: {self.baseline.summary()}",
        ]
        if payload:
            lines.append(f"Payload : {payload}")
        lines.append(f"Probe   : {self.probe.summary()}")
        lines.append(
            f"Delta   : status {self.status_delta:+d}, "
            f"length {self.length_delta:+d} bytes "
            f"({self.length_ratio:.2f}x), time {self.time_delta:+.2f}s"
        )
        if self.new_signatures:
            for name, snippet in self.new_signatures[:3]:
                lines.append(f"New     : {name} - {snippet[:160]}")
        for reflection in self.dangerous_reflections[:3]:
            lines.append(
                f"Reflect : {reflection.context.value} "
                f"({'verbatim' if reflection.verbatim else 'escaped'})"
                f"{', can break out' if reflection.can_break_out else ''}"
            )
        return "\n".join(lines)


def _context_at(text: str, index: int) -> ReflectionContext:
    """Classify where in the document *index* sits."""
    before = text[:index]

    # Inside a script block?
    last_open = before.rfind("<script")
    last_close = before.rfind("</script")
    if last_open > last_close and last_open != -1:
        return ReflectionContext.SCRIPT

    last_open = before.rfind("<style")
    last_close = before.rfind("</style")
    if last_open > last_close and last_open != -1:
        return ReflectionContext.STYLE

    # Inside an HTML tag (attribute context)?
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt and last_lt != -1:
        return ReflectionContext.HTML_ATTRIBUTE

    # JSON string?
    if re.search(r'["\']\s*:\s*["\'][^"\']*$', before):
        return ReflectionContext.JSON_STRING

    if before.rstrip().endswith(("<", "<?")) or "<?xml" in before[-200:].lower():
        return ReflectionContext.XML

    return ReflectionContext.HTML_TEXT


def _can_escape(payload: str, context: ReflectionContext) -> bool:
    """Can *payload* break out of *context* and inject markup or script?

    This is what separates a real XSS from a harmless reflection. A payload
    containing ``<`` dropped into HTML text is exploitable; the same
    payload HTML-encoded is not.
    """
    if context in (ReflectionContext.HEADER, ReflectionContext.COOKIE, ReflectionContext.URL):
        return False
    if context == ReflectionContext.HTML_TEXT:
        return "<" in payload or ">" in payload
    if context == ReflectionContext.HTML_ATTRIBUTE:
        return any(char in payload for char in ('"', "'", ">", "<"))
    if context == ReflectionContext.SCRIPT:
        lowered = payload.lower()
        return (
            "</script" in lowered
            or any(char in payload for char in ('"', "'", ";", "\n"))
        )
    if context == ReflectionContext.JSON_STRING:
        return any(char in payload for char in ('"', "\\", "\n"))
    if context == ReflectionContext.XML:
        return "<" in payload or "&" in payload
    return False


def analyze_reflections(
    body: str, payload: str, headers: dict[str, str] | None = None
) -> list[Reflection]:
    """Find every place the payload came back, and how it was encoded."""
    if not body or not payload:
        return []

    reflections: list[Reflection] = []
    needle = payload.strip()
    if len(needle) < 2:
        needle = payload

    # A one or two character payload will match by coincidence almost
    # everywhere (the "x" in "text/html", for example), so short payloads
    # are not treated as reflections at all.
    if len(needle) < MIN_REFLECTION_LENGTH:
        return reflections

    # Verbatim reflection: the payload survived encoding untouched.
    start = 0
    while True:
        index = body.find(needle, start)
        if index == -1:
            break
        context = _context_at(body, index)
        if context == ReflectionContext.UNKNOWN:
            context = ReflectionContext.HTML_TEXT
        reflections.append(
            Reflection(
                context=context,
                verbatim=True,
                index=index,
                snippet=body[max(0, index - 80) : index + len(needle) + 80],
                can_break_out=_can_escape(needle, context),
            )
        )
        start = index + max(1, len(needle))

    # Encoded reflection: the payload arrived HTML-escaped. Encoding is a
    # defence, so this is recorded but never treated as dangerous.
    if not reflections:
        escaped = html.escape(needle, quote=True)
        if escaped != needle:
            index = body.find(escaped)
            if index != -1:
                reflections.append(
                    Reflection(
                        context=_context_at(body, index),
                        verbatim=False,
                        index=index,
                        snippet=body[max(0, index - 80) : index + len(escaped) + 80],
                        can_break_out=False,
                    )
                )

    # Header and cookie reflection. Header values are short and structured,
    # so a short payload matches them by accident; require more substance.
    if len(needle) < MIN_HEADER_REFLECTION_LENGTH:
        return reflections

    for name, value in (headers or {}).items():
        if needle and needle in value:
            reflections.append(
                Reflection(
                    context=ReflectionContext.HEADER,
                    verbatim=True,
                    index=0,
                    snippet=f"{name}: {value[:200]}",
                    can_break_out=False,
                )
            )
        if name.lower() == "set-cookie" and needle and needle in value:
            reflections.append(
                Reflection(
                    context=ReflectionContext.COOKIE,
                    verbatim=True,
                    index=0,
                    snippet=value[:200],
                    can_break_out=False,
                )
            )

    return reflections


def compare(
    baseline: Response,
    probe: Response,
    payload: str = "",
    signatures: list[tuple[str, str]] | None = None,
) -> Delta:
    """Build a :class:`Delta` between two responses."""
    from ..knowledge.signatures import match_signatures

    signatures = signatures or []
    # Signatures are matched against error pages as well as successful ones:
    # a backend that returns 500 with a SQL error message is precisely the
    # case we need to detect, so the response status must not gate this.
    baseline_sigs = match_signatures(baseline.text, signatures) if baseline.text else []
    probe_sigs = match_signatures(probe.text, signatures) if probe.text else []
    baseline_labels = {label for label, _ in baseline_sigs}
    new_sigs = [(label, text) for label, text in probe_sigs if label not in baseline_labels]

    length_ratio = probe.length / max(1, baseline.length)

    return Delta(
        baseline=baseline,
        probe=probe,
        status_delta=probe.status - baseline.status,
        length_delta=probe.length - baseline.length,
        length_ratio=length_ratio,
        time_delta=probe.elapsed - baseline.elapsed,
        reflections=analyze_reflections(probe.text, payload, probe.headers),
        new_signatures=new_sigs,
        baseline_signatures=baseline_sigs,
    )


# ---------------------------------------------------------------------------
# Confidence scorers. Each returns a Confidence plus a human explanation.
# ---------------------------------------------------------------------------


def score_error_based(delta: Delta) -> tuple[Confidence, str]:
    """Confidence for a finding proved by a new backend error signature."""
    if delta.new_signatures:
        label, matched = delta.new_signatures[0]
        return (
            Confidence.CONFIRMED,
            f"backend {label} error signature appeared only in the injected request: "
            f"{matched[:120]!r}",
        )
    if delta.status_delta != 0:
        return (
            Confidence.MEDIUM,
            f"HTTP status changed from {delta.baseline.status} to {delta.probe.status} "
            f"with the injected payload",
        )
    if abs(delta.length_delta) >= LENGTH_DELTA_THRESHOLD:
        return (
            Confidence.MEDIUM,
            f"response length changed by {delta.length_delta} bytes "
            f"({delta.length_ratio:.2f}x) with the injected payload",
        )
    return (Confidence.LOW, "no observable difference between baseline and injected request")


def score_blind_time(delta: Delta, threshold: float = BLIND_TIME_THRESHOLD) -> tuple[Confidence, str]:
    """Confidence for a time-based (blind) injection."""
    if delta.time_delta >= threshold:
        return (
            Confidence.CONFIRMED,
            f"request took {delta.time_delta:.2f}s longer with the payload "
            f"(threshold {threshold:.1f}s)",
        )
    return (Confidence.LOW, f"time delta only {delta.time_delta:.2f}s")


def score_reflection(delta: Delta) -> tuple[Confidence, str]:
    """Confidence for a reflected injection (XSS)."""
    dangerous = delta.dangerous_reflections
    if dangerous:
        reflection = dangerous[0]
        return (
            Confidence.CONFIRMED,
            f"payload was reflected verbatim in an executable {reflection.context.value} "
            f"context - output encoding is missing",
        )
    if delta.reflections:
        reflection = delta.reflections[0]
        return (
            Confidence.LOW,
            f"payload was reflected but {reflection.context.value} and "
            f"{'encoded' if not reflection.verbatim else 'non-executable'}",
        )
    return (Confidence.LOW, "payload was not reflected in the response")


def score_disclosure(delta: Delta, marker: str) -> tuple[Confidence, str]:
    """Confidence for file/content disclosure."""
    if marker and marker.lower() in delta.probe.text.lower():
        return (
            Confidence.CONFIRMED,
            "requested file content is present in the response body",
        )
    if delta.new_signatures:
        label, matched = delta.new_signatures[0]
        return (Confidence.CONFIRMED, f"new {label} signature in response: {matched[:120]!r}")
    return (Confidence.LOW, "no disclosure signature found in the response")


def score_behaviour(delta: Delta) -> tuple[Confidence, str]:
    """Confidence for a generic behavioural change (open redirect, IDOR, ...)."""
    if delta.status_delta != 0:
        return (
            Confidence.HIGH,
            f"HTTP status changed {delta.baseline.status} -> {delta.probe.status}",
        )
    if delta.reflections:
        return (Confidence.MEDIUM, "payload reflected in the response")
    if abs(delta.length_delta) >= LENGTH_DELTA_THRESHOLD:
        return (
            Confidence.MEDIUM,
            f"response length changed by {delta.length_delta} bytes",
        )
    return (Confidence.LOW, "no observable behavioural difference")


def overall(deltas: list[Delta], scorer=score_error_based) -> Confidence:
    """Aggregate several deltas into one confidence using the best scorer."""
    best = Confidence.INFO
    for delta in deltas:
        confidence, _ = scorer(delta)
        if confidence.rank > best.rank:
            best = confidence
    return best

"""Tests for the differential verification engine.

These are the tests that matter most: the verification layer is what keeps
the scanner's output trustworthy.
"""

from __future__ import annotations

import pytest

from nemesis.http.client import Response
from nemesis.verify.verifier import (
    ReflectionContext,
    analyze_reflections,
    compare,
    score_behaviour,
    score_blind_time,
    score_disclosure,
    score_error_based,
    score_reflection,
)


def make_response(text: str, status: int = 200, elapsed: float = 0.1) -> Response:
    return Response(
        url="http://target/",
        status=status,
        headers={"content-type": "text/html"},
        text=text,
        content=text.encode(),
        elapsed=elapsed,
    )


class TestReflectionContext:
    def test_html_text(self):
        body = "<html><body><p>hello PAYLOAD here</p></body></html>"
        reflections = analyze_reflections(body, "PAYLOAD")
        assert len(reflections) == 1
        assert reflections[0].context == ReflectionContext.HTML_TEXT
        assert reflections[0].verbatim

    def test_html_attribute(self):
        body = '<div class="PAYLOAD">x</div>'
        reflections = analyze_reflections(body, "PAYLOAD")
        assert reflections[0].context == ReflectionContext.HTML_ATTRIBUTE

    def test_script_block(self):
        body = "<html><script>var x = 'PAYLOAD';</script></html>"
        reflections = analyze_reflections(body, "PAYLOAD")
        assert reflections[0].context == ReflectionContext.SCRIPT

    def test_encoded_reflection_is_not_verbatim(self):
        body = "<html><p>&lt;script&gt;alert(1)&lt;/script&gt;</p></html>"
        reflections = analyze_reflections(body, "<script>alert(1)</script>")
        assert reflections
        assert not reflections[0].verbatim
        assert not reflections[0].is_dangerous

    def test_verbatim_script_in_html_text_is_dangerous(self):
        """A <script> tag dropped into HTML text is exploitable."""
        body = "<html><body><p><script>alert(1)</script></p></body></html>"
        reflections = analyze_reflections(body, "<script>alert(1)</script>")
        assert reflections[0].verbatim
        assert reflections[0].can_break_out
        assert reflections[0].is_dangerous

    def test_escaped_payload_in_html_text_is_not_dangerous(self):
        body = "<html><body><p>&lt;script&gt;alert(1)&lt;/script&gt;</p></body></html>"
        reflections = analyze_reflections(body, "<script>alert(1)</script>")
        assert not reflections[0].is_dangerous

    def test_plain_reflection_is_not_dangerous(self):
        body = "<html><body><p>username is nemesisuser</p></body></html>"
        reflections = analyze_reflections(body, "nemesisuser")
        assert reflections[0].verbatim
        assert not reflections[0].is_dangerous

    def test_header_reflection(self):
        body = "ok"
        marker = "https://evil.example/nemesis-canary"
        headers = {"location": marker}
        reflections = analyze_reflections(body, marker, headers)
        assert any(r.context == ReflectionContext.HEADER for r in reflections)

    def test_short_payload_is_not_treated_as_a_reflection(self):
        """A one-character payload matches by coincidence everywhere."""
        reflections = analyze_reflections("<html>text/html</html>", "x")
        assert reflections == []


class TestCompare:
    def test_noop_delta(self):
        base = make_response("<html>same</html>")
        probe = make_response("<html>same</html>")
        delta = compare(base, probe, payload="x")
        assert delta.is_noop
        assert not delta.has_behaviour_change

    def test_status_delta(self):
        base = make_response("ok", status=200)
        probe = make_response("error", status=500)
        delta = compare(base, probe, payload="x")
        assert delta.status_delta == 300
        assert delta.has_behaviour_change

    def test_new_signature_detected(self):
        base = make_response("<html>fine</html>")
        probe = make_response("<html>You have an error in your SQL syntax</html>")
        signatures = [(r"you have an error in your sql syntax", "MySQL")]
        delta = compare(base, probe, payload="x", signatures=signatures)
        assert delta.new_signatures
        assert delta.new_signatures[0][0] == "MySQL"

    def test_signature_in_both_is_not_new(self):
        text = "<html>You have an error in your SQL syntax</html>"
        signatures = [(r"you have an error in your sql syntax", "MySQL")]
        delta = compare(make_response(text), make_response(text), payload="x", signatures=signatures)
        assert not delta.new_signatures

    def test_length_ratio(self):
        delta = compare(make_response("a" * 100), make_response("a" * 200), payload="x")
        assert delta.length_ratio == pytest.approx(2.0)


class TestScorers:
    def test_error_based_confirmed(self):
        base = make_response("ok")
        probe = make_response("You have an error in your SQL syntax")
        delta = compare(base, probe, payload="x",
                        signatures=[(r"you have an error in your sql syntax", "MySQL")])
        confidence, reason = score_error_based(delta)
        assert confidence.value == "confirmed"
        assert "MySQL" in reason

    def test_error_based_low_when_identical(self):
        delta = compare(make_response("ok"), make_response("ok"), payload="x")
        confidence, _ = score_error_based(delta)
        assert confidence.value == "low"

    def test_blind_time_threshold(self):
        base = make_response("ok", elapsed=0.1)
        probe = make_response("ok", elapsed=5.0)
        delta = compare(base, probe, payload="x")
        confidence, reason = score_blind_time(delta)
        assert confidence.value == "confirmed"
        assert "longer" in reason

    def test_blind_time_below_threshold(self):
        base = make_response("ok", elapsed=0.1)
        probe = make_response("ok", elapsed=0.5)
        delta = compare(base, probe, payload="x")
        confidence, _ = score_blind_time(delta)
        assert confidence.value == "low"

    def test_reflection_confirmed(self):
        body = "<html><body><script>alert(1)</script></body></html>"
        delta = compare(make_response("x"), make_response(body), payload="<script>alert(1)</script>")
        confidence, reason = score_reflection(delta)
        assert confidence.value == "confirmed"
        assert "verbatim" in reason

    def test_reflection_encoded_is_low(self):
        body = "<html><body>&lt;script&gt;alert(1)&lt;/script&gt;</body></html>"
        delta = compare(make_response("x"), make_response(body), payload="<script>alert(1)</script>")
        confidence, _ = score_reflection(delta)
        assert confidence.value == "low"

    def test_disclosure_confirmed(self):
        body = "root:x:0:0:root:/root:/bin/bash"
        delta = compare(make_response("x"), make_response(body), payload="x")
        confidence, reason = score_disclosure(delta, "root:x:0:0")
        assert confidence.value == "confirmed"
        assert "file content" in reason

    def test_behaviour_change(self):
        delta = compare(make_response("a", status=200), make_response("b", status=302), payload="x")
        confidence, _ = score_behaviour(delta)
        assert confidence.value == "high"

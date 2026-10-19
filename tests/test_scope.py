"""Tests for the scope engine."""

from __future__ import annotations

from nemesis.scope import Scope, parse_rule


class TestScopeRules:
    def test_host_rule(self):
        scope = Scope(rules=["example.com"])
        assert scope.allows("https://example.com/page")
        assert scope.allows("http://example.com")
        assert not scope.allows("https://evil.com/page")
        assert not scope.allows("https://sub.example.com/page")

    def test_wildcard_subdomain(self):
        scope = Scope(rules=["*.example.com"])
        assert scope.allows("https://api.example.com/v1")
        assert scope.allows("https://example.com")
        assert not scope.allows("https://example.org")

    def test_port_specific(self):
        scope = Scope(rules=["example.com:8443"])
        assert scope.allows("https://example.com:8443/x")
        assert not scope.allows("https://example.com/x")
        assert not scope.allows("https://example.com:443/x")

    def test_path_prefix(self):
        scope = Scope(rules=["https://example.com/api/*"])
        assert scope.allows("https://example.com/api/users")
        assert not scope.allows("https://example.com/admin")
        assert not scope.allows("http://example.com/api/users")

    def test_exclusion_beats_inclusion(self):
        scope = Scope(rules=["example.com"], exclusions=["example.com/admin"])
        assert scope.allows("https://example.com/ok")
        assert not scope.allows("https://example.com/admin")

    def test_default_deny(self):
        scope = Scope(rules=[])
        assert not scope.allows("https://example.com/")

    def test_path_only_rule(self):
        scope = Scope(rules=["/api"], default_host="example.com")
        assert scope.allows("https://example.com/api/users")
        assert not scope.allows("https://example.com/other")

    def test_malformed_url_is_denied(self):
        scope = Scope(rules=["example.com"])
        assert not scope.allows("not a url at all")

    def test_parse_rule_normalises_trailing_slash(self):
        rule = parse_rule("https://example.com/api/")
        assert rule.path == "/api"

    def test_expand_seed_adds_bare_domain(self):
        scope = Scope(rules=["*.example.com"])
        seeds = scope.expand_seed("https://api.example.com/app")
        assert "https://api.example.com/app" in seeds
        assert "https://example.com/" in seeds

    def test_describe(self):
        scope = Scope(rules=["example.com"], exclusions=["example.com/x"])
        assert "example.com" in scope.describe()

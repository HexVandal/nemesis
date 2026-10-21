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


class TestPathBoundaries:
    """A path rule must stop at a segment boundary.

    A plain string prefix lets /admin grant /administrator and
    /admin-secret, which are different resources. This was a real defect
    found in audit: the boundary is the whole point of a scope rule.
    """

    def test_exact_path_is_allowed(self):
        scope = Scope(rules=["example.com/admin"])
        assert scope.allows("https://example.com/admin")
        assert scope.allows("https://example.com/admin/")

    def test_descendants_are_allowed(self):
        scope = Scope(rules=["example.com/admin"])
        assert scope.allows("https://example.com/admin/users")
        assert scope.allows("https://example.com/admin/users/1/edit")

    def test_sibling_prefix_is_denied(self):
        scope = Scope(rules=["example.com/admin"])
        assert not scope.allows("https://example.com/administrator")
        assert not scope.allows("https://example.com/admin-secret")
        assert not scope.allows("https://example.com/administrator/login")

    def test_dot_segments_are_resolved_before_matching(self):
        scope = Scope(rules=["example.com/admin"])
        # Resolves to /secret, so it is outside the rule.
        assert not scope.allows("https://example.com/admin/../secret")
        # Resolves to /admin/users, so it is inside.
        assert scope.allows("https://example.com/admin/./users")

    def test_duplicate_slashes_do_not_confuse_boundary(self):
        scope = Scope(rules=["example.com/admin"])
        assert scope.allows("https://example.com//admin//users")

    def test_explicit_glob_keeps_prefix_behaviour(self):
        scope = Scope(rules=["example.com/admin/*"])
        assert scope.allows("https://example.com/admin/users")
        assert not scope.allows("https://example.com/administrator")

    def test_path_rule_denies_unrelated_path(self):
        scope = Scope(rules=["example.com/admin"])
        assert not scope.allows("https://example.com/other")
        assert not scope.allows("https://example.com/")

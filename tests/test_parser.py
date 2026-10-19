"""Tests for HTML parsing and the parameter helper."""

from __future__ import annotations

from nemesis.crawler.parser import parse_html
from nemesis.modules.http_helper import HttpModule, build_form_body, replace_param


class TestParser:
    def test_extracts_links(self):
        html = '<a href="/a">A</a><a href="https://other.com/b">B</a><a href="javascript:void(0)">C</a>'
        page = parse_html("http://target/", html)
        assert "http://target/a" in page.links
        assert "https://other.com/b" in page.links
        assert not any("javascript" in link for link in page.links)

    def test_extracts_forms(self):
        html = """
        <form action="/login" method="POST">
          <input type="text" name="user">
          <input type="password" name="pass">
          <input type="hidden" name="csrf" value="tok">
          <input type="file" name="upload">
        </form>
        """
        page = parse_html("http://target/page", html)
        assert len(page.forms) == 1
        form = page.forms[0]
        assert form["action"] == "http://target/login"
        assert form["method"] == "POST"
        assert form["has_file_upload"] is True
        assert form["fields"]["csrf"] == "tok"
        assert "user" in form["raw_fields"]

    def test_extracts_title_and_metas(self):
        html = '<html><head><title>My Page</title><meta name="generator" content="WordPress 6.4"></head></html>'
        page = parse_html("http://target/", html)
        assert page.title == "My Page"
        assert "WordPress" in page.metas["generator"]

    def test_detects_technology(self):
        page = parse_html("http://target/", '<html><script src="/wp-content/x.js"></script></html>')
        assert "WordPress" in page.tech_hints

    def test_extracts_query_params(self):
        page = parse_html("http://target/search?q=test&page=2", "<html></html>")
        assert "q" in page.param_names
        assert "page" in page.param_names

    def test_finds_endpoints_in_inline_js(self):
        html = '<script>fetch("/api/v1/users"); var u = "https://api.example.com/v2/thing";</script>'
        page = parse_html("http://target/", html)
        assert any("/api/v1/users" in e for e in page.endpoints)

    def test_empty_html_is_safe(self):
        page = parse_html("http://target/", "")
        assert page.links == []
        assert page.forms == []


class TestReplaceParam:
    def test_replaces_existing_param(self):
        url = replace_param("http://t/x?q=old&p=1", "q", "new")
        assert "q=new" in url
        assert "p=1" in url

    def test_adds_missing_param(self):
        url = replace_param("http://t/x", "q", "new")
        assert "q=new" in url

    def test_encodes_special_characters(self):
        url = replace_param("http://t/x?q=old", "q", "a b&c=d")
        assert " " not in url
        assert "%20" in url or "+" in url


class TestBenignEquivalent:
    def test_same_length(self):
        for payload in ["'", "<script>alert(1)</script>", "1' OR '1'='1", "abc", "12345"]:
            benign = HttpModule.benign_equivalent(payload)
            assert len(benign) == len(payload), payload

    def test_digits_stay_numeric(self):
        assert HttpModule.benign_equivalent("12345").isdigit()

    def test_quotes_are_neutralised(self):
        benign = HttpModule.benign_equivalent("''")
        assert "'" not in benign

    def test_angle_brackets_are_neutralised(self):
        benign = HttpModule.benign_equivalent("<b>")
        assert "<" not in benign and ">" not in benign


class TestBuildFormBody:
    def test_overrides_one_field(self):
        body = build_form_body({"user": "bob", "pass": ""}, ("pass", "x"))
        assert body["user"] == "bob"
        assert body["pass"] == "x"

    def test_empty_values_get_filled(self):
        body = build_form_body({"q": ""})
        assert body["q"]

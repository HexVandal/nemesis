"""HTML analysis: the crawler turns raw responses into structured attack surface.

Everything here is pure parsing - no network access - so it is cheap to run
over every crawled page and easy to unit test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urljoin, urlparse

from bs4 import BeautifulSoup

#: Matches API-ish URLs inside JavaScript sources.
_JS_URL_PATTERNS = [
    re.compile(r"""["'`](https?://[^\s"'`]{4,200})["'`]"""),
    re.compile(r"""["'](/(?:api|v\d|rest|graphql|gql|internal|admin)[^\s"'`]{0,160})["'`]"""),
    re.compile(r"""\b(?:fetch|axios\.(?:get|post|put|patch|delete)|url)\s*[:(]\s*["'`]([^"'`]{2,200})["'`]"""),
]

#: Query-parameter names that commonly carry interesting values.
INTERESTING_PARAMS = {
    "id", "uid", "user", "userid", "user_id", "account", "acct", "profile",
    "order", "sort", "filter", "q", "query", "search", "keyword", "page",
    "file", "path", "dir", "name", "url", "redirect", "next", "return",
    "callback", "jsonp", "view", "template", "include", "load", "download",
    "img", "image", "dest", "destination", "target", "out", "continue",
    "email", "host", "domain", "port", "proxy", "lang", "locale", "ref",
    "token", "key", "api_key", "apikey", "auth", "code", "state", "session",
}

#: File extensions worth trying for path traversal and exposure checks.
INTERESTING_FILES = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/hostname",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "/windows/win.ini",
    "C:\\windows\\win.ini",
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "/proc/self/environ",
    "file:///etc/passwd",
    "/.env",
    "/.git/HEAD",
    "/config.php",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/.DS_Store",
    "/web.config",
    "/backup.zip",
    "/dump.sql",
]

#: Common sensitive paths worth probing for exposure.
EXPOSED_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/index",
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.svn/entries", "/.hg/requires",
    "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip", "/src.zip",
    "/db.sql", "/dump.sql", "/database.sql",
    "/config.php.bak", "/config.php~", "/config.php.old", "/config.php.save",
    "/wp-config.php.bak", "/wp-config.php.old", "/.wp-config.php.swp",
    "/web.config", "/application.properties", "/application.yml",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/configprops",
    "/.DS_Store", "/composer.json", "/composer.lock",
    "/.gitignore", "/Dockerfile", "/docker-compose.yml",
    "/metrics", "/debug/vars", "/debug/pprof/",
    "/elmah.axd", "/trace.axd",
    "/swagger-ui.html", "/swagger.json", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/_debug",
]


@dataclass
class ParsedPage:
    """Structured view of one HTML document."""

    url: str
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    stylesheets: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    metas: dict[str, str] = field(default_factory=dict)
    endpoints: list[str] = field(default_factory=list)
    param_names: set[str] = field(default_factory=set)
    tech_hints: list[str] = field(default_factory=list)
    inline_js: list[str] = field(default_factory=list)
    has_json: bool = False
    word_count: int = 0

    def all_params(self) -> list[str]:
        return sorted(self.param_names)


def _clean_url(base: str, href: str) -> str | None:
    if not href:
        return None
    href = href.strip()
    if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#", "about:")):
        return None
    try:
        absolute = urljoin(base, href)
    except ValueError:
        return None
    parsed = urlparse(absolute)
    if parsed.scheme not in ("http", "https"):
        return None
    return absolute


def parse_html(url: str, html: str, content_type: str = "") -> ParsedPage:
    """Extract links, forms, parameters and technology hints from *html*."""
    page = ParsedPage(url=url)
    if not html:
        return page

    page.has_json = "json" in content_type
    soup = BeautifulSoup(html, "lxml" if _has_lxml() else "html.parser")

    if soup.title and soup.title.string:
        page.title = soup.title.string.strip()[:300]
    page.word_count = len(soup.get_text(" ", strip=True).split())

    for meta in soup.find_all("meta"):
        name = (meta.get("name") or meta.get("property") or "").lower()
        content = meta.get("content")
        if name and content:
            page.metas[name] = content[:500]
            if name == "generator":
                page.tech_hints.append(content.split()[0])

    for tag in soup.find_all("a", href=True):
        target = _clean_url(url, tag["href"])
        if target:
            page.links.append(target)

    for tag in soup.find_all(["link", "img", "source", "iframe", "embed"]):
        attr = tag.get("href") or tag.get("src")
        target = _clean_url(url, attr) if attr else None
        if target:
            if tag.name == "link":
                page.stylesheets.append(target)
            page.links.append(target)

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            target = _clean_url(url, src)
            if target:
                page.scripts.append(target)
                page.links.append(target)
        elif tag.string:
            page.inline_js.append(tag.string[:20000])

    for comment in soup.find_all(string=lambda t: isinstance(t, str) and t.strip().startswith("<!--")):
        text = str(comment).strip()
        if 4 < len(text) < 2000:
            page.comments.append(text)

    for form in soup.find_all("form"):
        action = form.get("action") or ""
        action_url = _clean_url(url, action) or url
        method = (form.get("method") or "GET").upper()
        fields: dict[str, str] = {}
        raw_fields: list[str] = []
        has_file = False
        for field_tag in form.find_all(["input", "textarea", "select"]):
            name = field_tag.get("name")
            if not name:
                continue
            raw_fields.append(name)
            if (field_tag.get("type") or "").lower() == "file":
                has_file = True
                fields[name] = "file"
            elif field_tag.get("type") == "hidden":
                fields[name] = field_tag.get("value") or ""
            else:
                fields[name] = ""
        page.forms.append(
            {
                "action": action_url,
                "method": method,
                "fields": fields,
                "raw_fields": raw_fields,
                "has_file_upload": has_file,
                "source_url": url,
            }
        )
        page.param_names.update(raw_fields)

    # Query parameters present on this page.
    parsed = urlparse(url)
    page.param_names.update(key for key, _ in parse_qsl(parsed.query))

    # Endpoints referenced from inline JavaScript.
    for script in page.inline_js:
        for pattern in _JS_URL_PATTERNS:
            for match in pattern.finditer(script):
                candidate = match.group(1)
                target = _clean_url(url, candidate)
                if target and target not in page.endpoints:
                    page.endpoints.append(target)

    page.tech_hints.extend(_guess_tech(soup, html))
    return page


def _has_lxml() -> bool:
    try:
        import lxml  # noqa: F401

        return True
    except ImportError:
        return False


_TECH_SIGNATURES: list[tuple[str, str]] = [
    (r"wp-content|wp-includes|wordpress", "WordPress"),
    (r"drupal-settings|drupal\.js|/sites/default/files", "Drupal"),
    (r"joomla|com_content", "Joomla"),
    (r"__NEXT_DATA__|_next/static", "Next.js"),
    (r"__NUXT__|_nuxt/", "Nuxt"),
    (r"data-reactroot|data-reactid|react-dom", "React"),
    (r"data-v-[0-9a-f]{8}|__VUE__|vue-runtime", "Vue"),
    (r"ng-version|angular\.min\.js", "Angular"),
    (r"svelte-[0-9a-z]{6}", "Svelte"),
    (r"laravel_session|XSRF-TOKEN", "Laravel"),
    (r"csrfmiddlewaretoken|csrftoken", "Django"),
    (r"__cf_bm|cloudflare", "Cloudflare"),
    (r"csrf-param", "Ruby on Rails"),
    (r"ASP.NET_SessionId|__VIEWSTATE|aspnetForm", "ASP.NET"),
    (r"springframework|spring-security", "Spring"),
    (r"Express|session=.*connect\.sid", "Express"),
    (r"phpmyadmin|phpMyAdmin", "phpMyAdmin"),
    (r"grafana|Grafana", "Grafana"),
    (r"kibana", "Kibana"),
    (r"jira|JIRA", "Jira"),
    (r"strapi", "Strapi"),
    (r"ghost", "Ghost"),
    (r"bootstrap", "Bootstrap"),
    (r"jquery[.\-/]?3", "jQuery"),
    (r"tailwindcss", "Tailwind CSS"),
    (r"socket\.io", "Socket.IO"),
    (r"graphql", "GraphQL"),
]


def _guess_tech(soup: BeautifulSoup, html: str) -> list[str]:
    found: list[str] = []
    haystack = html[:200000]
    for pattern, name in _TECH_SIGNATURES:
        if re.search(pattern, haystack, re.IGNORECASE):
            found.append(name)
    for script in soup.find_all("script", src=True):
        src = script["src"]
        for pattern, name in _TECH_SIGNATURES:
            if re.search(pattern, src, re.IGNORECASE) and name not in found:
                found.append(name)
    return found

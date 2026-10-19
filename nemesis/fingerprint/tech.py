"""Technology fingerprinting.

Knowing what runs behind the target decides which exploits are even worth
trying: a Node app and a Django app fail in completely different ways, and
an IIS box invites different paths than a Spring Boot service.
"""

from __future__ import annotations

import re

from ..http.client import Response
from ..models import Confidence, Technology

#: Header name -> (technology, regex to extract version)
_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", "Web server", r"([\w.\-/]+)"),
    ("x-powered-by", "Runtime", r"([\w.\-]+)"),
    ("x-aspnet-version", "ASP.NET", r"([\d.]+)"),
    ("x-aspnetmvc-version", "ASP.NET MVC", r"([\d.]+)"),
    ("x-drupal-cache", "Drupal", None),
    ("x-generator", "Generator", r"(.+)"),
    ("x-runtime", "Runtime", r"(.+)"),
    ("x-version", "Platform", r"(.+)"),
    ("x-backend-server", "Backend", r"(.+)"),
    ("x-shopify-stage", "Shopify", None),
    ("x-magento-tags", "Magento", None),
    ("x-varnish", "Varnish", None),
    ("via", "Proxy", r"(.+)"),
    ("cf-ray", "Cloudflare", None),
    ("cf-cache-status", "Cloudflare", None),
    ("akamai-grn", "Akamai", None),
    ("x-amz-cf-id", "AWS CloudFront", None),
    ("x-goog-generation", "Google Cloud", None),
    ("x-github-request-id", "GitHub", None),
    ("x-served-by", "CDN", r"(.+)"),
    ("x-sucuri-id", "Sucuri", None),
    ("x-iinfo", "IIS", None),
    ("x-aspnetmvc-version", "ASP.NET", r"([\d.]+)"),
]

#: Body/cookie patterns -> technology.
_BODY_SIGNATURES: list[tuple[str, str, str | None]] = [
    (r"wp-content|wp-includes", "WordPress", None),
    (r'"generator"\s*:\s*"WordPress', "WordPress", None),
    (r"drupal-settings-json", "Drupal", None),
    (r"__NEXT_DATA__", "Next.js", None),
    (r"__NUXT__", "Nuxt", None),
    (r"data-reactroot|react-dom", "React", None),
    (r"data-v-[0-9a-f]{8}|vue", "Vue", None),
    (r"ng-version=", "Angular", None),
    (r"svelte-[0-9a-z]{6}", "Svelte", None),
    (r"csrfmiddlewaretoken|__admin_media_prefix__", "Django", None),
    (r"_rails_session|X-CSRF-Token", "Ruby on Rails", None),
    (r"laravel_session|XSRF-TOKEN", "Laravel", None),
    (r"ASP.NET_SessionId|__VIEWSTATE", "ASP.NET", None),
    (r"springframework|Whitelabel Error Page", "Spring", None),
    (r"passport|payloads\.gzip", "Ruby on Rails", None),
    (r"wp-json|wp-emoji", "WordPress", None),
    (r"Shopify|cdn\.shopify", "Shopify", None),
    (r"Magento|magento", "Magento", None),
    (r"TYPO3|typo3conf", "TYPO3", None),
    (r"Solr|org\.apache\.solr", "Apache Solr", None),
    (r"grafana_session|grafanaBootData", "Grafana", None),
    (r"strapi|Strapi", "Strapi", None),
    (r"ghost/api", "Ghost", None),
    (r"Discourse|discourse", "Discourse", None),
    (r"phpMyAdmin", "phpMyAdmin", None),
    (r"tomcat|Apache-Coyote|jsessionid", "Apache Tomcat", None),
    (r"JBoss|jboss", "JBoss", None),
    (r"WebLogic|weblogic", "WebLogic", None),
    (r"WebSphere|websphere", "WebSphere", None),
    (r"werkzeug|__debug__", "Werkzeug", None),
    (r"rails-ujs|data-remote", "Ruby on Rails", None),
    (r"bootstrap[-\.min]?\.css|bootstrap", "Bootstrap", None),
    (r"socket\.io", "Socket.IO", None),
    (r"graphql|/graphql", "GraphQL", None),
    (r"apollo|apollo-client", "Apollo", None),
    (r"trpc|@trpc", "tRPC", None),
    (r"supabase|supabase\.co", "Supabase", None),
    (r"firebaseio|firebase", "Firebase", None),
]

#: Cookie names that identify a platform.
_COOKIE_SIGNATURES: list[tuple[str, str]] = [
    ("PHPSESSID", "PHP"),
    ("JSESSIONID", "Java Servlet"),
    ("ASP.NET_SessionId", "ASP.NET"),
    ("_session_id", "Ruby on Rails"),
    ("laravel_session", "Laravel"),
    ("csrftoken", "Django"),
    ("connect.sid", "Express"),
    ("ci_session", "CodeIgniter"),
    ("_cf_bm", "Cloudflare"),
    ("XSRF-TOKEN", "Laravel"),
    ("wp-settings", "WordPress"),
    ("django_language", "Django"),
    ("remember_token", "Ruby on Rails"),
]

#: Products with a known-CVE surface where version detection is valuable.
_VERSIONED_PRODUCTS = {
    "WordPress", "Drupal", "Joomla", "Magento", "TYPO3", "Apache Tomcat",
    "OpenSSL", "nginx", "Apache", "Microsoft IIS", "PHP", "Strapi", "Ghost",
}


def _extract_version(text: str) -> str | None:
    match = re.search(r"(\d+\.\d+(?:\.\d+)?(?:[-.\w]*)?)", text)
    return match.group(1) if match else None


def fingerprint(response: Response, body: str = "") -> list[Technology]:
    """Identify technologies from a response's headers, cookies and body."""
    found: dict[str, Technology] = {}

    def add(name: str, version: str | None, category: str, confidence: Confidence, source: str) -> None:
        existing = found.get(name)
        if existing is None:
            found[name] = Technology(
                name=name, version=version, category=category,
                confidence=confidence, source=source,
            )
        elif version and not existing.version:
            existing.version = version
        elif version and existing.version and version != existing.version:
            # Two different versions seen - keep the more specific one.
            existing.version = max(existing.version, version, key=len)

    for header, category, version_pattern in _HEADER_SIGNATURES:
        value = response.header(header)
        if not value:
            continue
        version = None
        if version_pattern:
            match = re.search(version_pattern, value, re.IGNORECASE)
            version = match.group(1).strip() if match else None
        add(category if category != "Web server" else value.split("/")[0].split(" ")[0],
            version, category, Confidence.HIGH, f"header:{header}")

    raw_cookies = response.header("set-cookie")
    for cookie_name, tech in _COOKIE_SIGNATURES:
        if cookie_name.lower() in raw_cookies.lower():
            add(tech, None, "Platform", Confidence.MEDIUM, "cookie")

    haystack = (body or response.text)[:300000]
    for pattern, name, _ in _BODY_SIGNATURES:
        if re.search(pattern, haystack, re.IGNORECASE):
            add(name, None, "Framework", Confidence.MEDIUM, "body")

    # Generator meta often carries an exact version.
    generator = re.search(
        r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)",
        haystack, re.IGNORECASE,
    )
    if generator:
        raw = generator.group(1).strip()
        name = raw.split()[0].split("/")[0]
        add(name, _extract_version(raw), "CMS/Platform", Confidence.HIGH, "meta:generator")

    # A server banner frequently carries a version; split it out.
    server = response.header("server")
    if server:
        name = server.split("/")[0].split(" ")[0]
        version = _extract_version(server)
        add(name, version, "Web server", Confidence.HIGH, "header:server")

    return list(found.values())

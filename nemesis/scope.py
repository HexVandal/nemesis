"""Scope enforcement.

A scanner that walks outside the boundaries it was given is both dangerous
and useless. Every outbound request in nemesis passes through :class:`Scope`,
and the default posture is *deny*: a URL is only fetched when an inclusion
rule matches it and no exclusion rule does.

Supported rule syntax::

    example.com                 host, any scheme/port/path
    *.example.com               host and all subdomains
    example.com:8443            host and port
    https://example.com/api/*   scheme + host + path prefix
    /admin                      path prefix on the current target host
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


@dataclass(frozen=True)
class ScopeRule:
    """One parsed inclusion or exclusion rule."""

    raw: str
    scheme: str | None
    host: str | None
    port: int | None
    path: str | None
    is_path_only: bool

    def matches(self, scheme: str, host: str, port: int, path: str) -> bool:
        # A rule that names a scheme only covers that scheme. A rule that
        # does not covers HTTP and HTTPS only - the scanner speaks nothing
        # else, and allowing, say, ftp:// through would be a hole in the
        # boundary rather than a feature.
        if self.scheme:
            if self.scheme != scheme:
                return False
        elif scheme not in ("http", "https"):
            return False
        if self.port is not None and self.port != port:
            return False
        if self.host is not None and not self._host_matches(host):
            return False
        if self.path is not None:
            # A path rule grants its own path and everything beneath it,
            # and the comparison has to land on a segment boundary.
            #
            # A plain string prefix is wrong: a rule for /admin would then
            # also grant /administrator and /admin-secret, which are
            # different resources. An explicit glob tail (/admin/*) is the
            # opt-in for raw prefix behaviour.
            if self.path.endswith("*"):
                prefix = self.path[:-1]
                if not path.startswith(prefix):
                    return False
            elif path != self.path and not path.startswith(self.path + "/"):
                return False
        return True

    def _host_matches(self, host: str) -> bool:
        if self.host.startswith("*."):
            suffix = self.host[1:]  # ".example.com"
            return host.endswith(suffix) or host == self.host[2:]
        if self.host.startswith("*"):
            return fnmatch.fnmatch(host, self.host)
        return host == self.host


def _normalise_path(path: str) -> str:
    """Resolve dot segments so scope is checked on the resolved path.

    ``/admin/../secret`` is presented by a client that wants the admin
    rule to match, and resolved by the server to ``/secret``. Both the
    scanner and the server must be looking at the same string.
    """
    if not path:
        return "/"
    # Collapse duplicate slashes first, then walk the segments.
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    resolved = "/" + "/".join(segments)
    if path.endswith("/") and resolved != "/":
        resolved += "/"
    return resolved


def _default_ports(scheme: str) -> int:
    return {"http": 80, "https": 443}.get(scheme, 0)


def parse_rule(rule: str, default_host: str | None = None) -> ScopeRule:
    """Parse a user-supplied rule string into a :class:`ScopeRule`."""
    raw = rule.strip()
    if not raw:
        raise ValueError("empty scope rule")

    # Path-only rule: "/admin" or "/api/*"
    if raw.startswith("/"):
        return ScopeRule(
            raw=raw,
            scheme=None,
            host=default_host,
            port=None,
            path=raw,
            is_path_only=True,
        )

    candidate = raw
    if "://" not in candidate:
        candidate = f"//{candidate}"

    parsed = urlparse(candidate)
    scheme = parsed.scheme or None
    host = parsed.hostname
    port = parsed.port
    path = parsed.path or None

    # Normalise the path: "/" and "" mean "any path"; a trailing slash on a
    # non-glob rule is just noise.
    if not path or path == "/":
        path = None
    elif path.endswith("/") and not path.endswith("/*"):
        path = path.rstrip("/")

    if host is None and default_host:
        host = default_host

    return ScopeRule(
        raw=raw,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        is_path_only=False,
    )


class Scope:
    """Decides which URLs the scanner is allowed to touch.

    Parameters
    ----------
    rules:
        Inclusion rules. At least one is required; without one nothing is
        in scope and the scanner will refuse to run.
    exclusions:
        Exclusion rules, evaluated first and always winning.
    default_host:
        Host assumed for path-only rules such as ``/admin``.
    """

    def __init__(
        self,
        rules: list[str] | None = None,
        exclusions: list[str] | None = None,
        default_host: str | None = None,
    ) -> None:
        self.rules = [parse_rule(r, default_host) for r in (rules or [])]
        self.exclusions = [parse_rule(r, default_host) for r in (exclusions or [])]
        self.default_host = default_host
        self._wildcard_host = None
        for rule in self.rules:
            if rule.host and rule.host.startswith("*."):
                self._wildcard_host = rule.host[2:]
                break

    def __bool__(self) -> bool:
        return bool(self.rules)

    def allows(self, url: str) -> bool:
        """Return ``True`` when *url* is inside the scan boundary."""
        try:
            parsed = urlparse(url)
        except ValueError:
            return False

        scheme = (parsed.scheme or "https").lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port or _default_ports(scheme)

        # Resolve "." and ".." before matching. A path such as
        # /admin/../secret has the shape of the admin tree but resolves
        # to /secret, and the server will do the same resolution. The
        # check has to run on the path the server will actually see.
        path = _normalise_path(parsed.path or "/")

        if not host:
            return False

        # Any exclusion match wins.
        for rule in self.exclusions:
            if rule.matches(scheme, host, port, path):
                return False

        if not self.rules:
            return False

        for rule in self.rules:
            if rule.matches(scheme, host, port, path):
                return True
        return False

    def expand_seed(self, base_url: str) -> list[str]:
        """Return candidate root URLs to start crawling from.

        A wildcard host rule such as ``*.example.com`` also seeds the bare
        domain, because most sites put their main entry point there. A
        rule for a specific host seeds that host's root as well, so a
        scan of ``https://api.example.com/v1/users`` still visits
        ``https://api.example.com/``.
        """
        seeds = [base_url]
        parsed = urlparse(base_url)

        bare_host = self._wildcard_host
        if bare_host is None:
            for rule in self.rules:
                if rule.host and not rule.host.startswith("*"):
                    bare_host = rule.host
                    break

        if bare_host:
            bare = urlunparse((parsed.scheme, bare_host, "/", "", "", ""))
            if bare not in seeds:
                seeds.append(bare)
        return seeds

    def describe(self) -> str:
        inc = ", ".join(r.raw for r in self.rules) or "(none)"
        exc = ", ".join(r.raw for r in self.exclusions) or "(none)"
        return f"include=[{inc}] exclude=[{exc}]"

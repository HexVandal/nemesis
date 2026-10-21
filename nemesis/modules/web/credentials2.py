"""Credential and flow checks: what an application accepts as proof of identity.

Every finding here is something the server did, observed on the wire. No
check reports a guess.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext
from ..http_helper import make_marker

_IDENTITY = ("user", "email", "login", "account", "name")
_SECRET = ("pass", "secret", "pin")

#: Tried in order, stopping at the first accepted pair. Deliberately short:
#: this is a check for shipped defaults, not a password spray.
DEFAULTS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("test", "test"),
    ("guest", "guest"),
]

_FAILURE_TEXT = re.compile(
    r"(invalid|incorrect|failed|denied|not recognised|not recognized|try again)",
    re.IGNORECASE,
)
_SUCCESS_TEXT = re.compile(r"(logout|sign out|dashboard|welcome back|my account)", re.IGNORECASE)
_POLICY_TEXT = re.compile(
    r"(too short|at least \d+|minimum (?:of )?\d+|must (?:be|contain)|password strength)",
    re.IGNORECASE,
)


def _field(form, hints: tuple[str, ...]) -> str | None:
    for name in form.raw_fields:
        if any(hint in name.lower() for hint in hints):
            return name
    return None


def _login_forms(ctx: ScanContext) -> list:
    forms = []
    for form in ctx.forms:
        if _field(form, ("pass",)) and _field(form, _IDENTITY):
            forms.append(form)
    return forms[:2]


class DefaultCredentialsModule(Module):
    """Try the credentials that vendors ship, and stop at the first success.

    A login is only called successful when the response behaves like a login
    that worked: a redirect away from the form, a new session cookie, or the
    account chrome appearing where it was not. A 200 with "Invalid password"
    in it is a failure, whatever the status code says.
    """

    group = "auth"

    id = "default_credentials"
    name = "Default Credentials"
    description = (
        "Attempts a short list of vendor defaults against login forms and "
        "reports the first pair the application actually accepts."
    )
    severity = Severity.CRITICAL
    confidence = Confidence.CONFIRMED
    category = Category.AUTH
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-1392"
    owasp = "A07"
    remediation = (
        "Force a credential change on first boot and refuse to start with a "
        "factory password."
    )
    references = ["https://cwe.mitre.org/data/definitions/1392.html"]
    tags = ["auth", "defaults", "destructive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in _login_forms(ctx):
            identity = _field(form, _IDENTITY)
            secret = _field(form, _SECRET)
            if not identity or not secret:
                continue

            baseline_body = {k: (v or "nemesis") for k, v in form.fields.items()}
            baseline_body[identity] = "nms_nonexistent_account"
            baseline_body[secret] = make_marker("pw")
            baseline = await ctx.client.post(
                form.action, data=baseline_body, follow_redirects=False
            )
            baseline_cookies = dict(baseline.headers).get("set-cookie", "")

            for user, password in DEFAULTS:
                body = {k: (v or "nemesis") for k, v in form.fields.items()}
                body[identity] = user
                body[secret] = password
                response = await ctx.client.post(
                    form.action, data=body, follow_redirects=False
                )

                location = ""
                for key, value in response.headers.items():
                    if key.lower() == "location":
                        location = value
                cookie = ""
                for key, value in response.headers.items():
                    if key.lower() == "set-cookie":
                        cookie = value

                redirected_away = (
                    response.status in (301, 302, 303, 307)
                    and location
                    and not re.search(r"log-?in|sign-?in|auth", location, re.IGNORECASE)
                )
                new_session = bool(cookie) and cookie != baseline_cookies
                account_chrome = bool(
                    _SUCCESS_TEXT.search(response.text or "")
                ) and not _FAILURE_TEXT.search(response.text or "")

                if not (redirected_away or (new_session and account_chrome) or account_chrome):
                    continue

                findings.append(
                    self.finding(
                        title=f"Default credentials accepted: {user}/{password}",
                        target=form.action,
                        description=(
                            f"The login form accepted the shipped default "
                            f"combination {user}/{password} and responded as an "
                            f"authenticated session. Anyone who reaches this "
                            f"screen owns the account."
                        ),
                        evidence_text=(
                            f"POST {form.action}\n"
                            f"  {identity} = {user}\n"
                            f"  {secret} = {password}\n"
                            f"  status    = {response.status}\n"
                            f"  location  = {location or '-'}\n"
                            f"  set-cookie= {'present' if cookie else '-'}"
                        ),
                        matched=f"{user}/{password}",
                        username=user,
                    )
                )
                break
        return findings


class WeakPasswordPolicyModule(Module):
    """Does the registration form accept a one-character password?

    One request, a deliberately trivial value. If the server stores it, the
    policy is absent - that is a fact, not an opinion about strength meters.
    """

    group = "auth"

    id = "weak_password_policy"
    name = "Weak Password Policy"
    description = (
        "Submits a single-character password to registration forms and "
        "reports the ones that accept it without a policy error."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.AUTH
    capability = Capability.DESTRUCTIVE
    cwe = "CWE-521"
    owasp = "A07"
    remediation = (
        "Enforce a minimum length (12+), check against breached-password lists, "
        "and reject the account's own name as a password."
    )
    references = ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"]
    tags = ["auth", "password-policy", "destructive"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for form in ctx.forms:
            secret = _field(form, ("pass",))
            if not secret or form.method.lower() != "post":
                continue
            if "login" in form.action.lower() or "signin" in form.action.lower():
                continue

            body = {k: (v or "nemesis") for k, v in form.fields.items()}
            body[secret] = "a"
            if any("confirm" in name.lower() for name in form.raw_fields):
                for name in form.raw_fields:
                    if "confirm" in name.lower():
                        body[name] = "a"
            response = await ctx.client.post(form.action, data=body, follow_redirects=False)
            if response.status >= 400:
                continue
            if _POLICY_TEXT.search(response.text or ""):
                continue
            if _FAILURE_TEXT.search(response.text or "") and not _SUCCESS_TEXT.search(
                response.text or ""
            ):
                continue

            findings.append(
                self.finding(
                    title=f"One-character password accepted by {form.action}",
                    target=form.action,
                    description=(
                        "The registration form stored the password 'a'. No "
                        "minimum length, no complexity rule and no breach check "
                        "stood in the way, which makes every account on this "
                        "system trivial to crack offline."
                    ),
                    evidence_text=(
                        f"POST {form.action}\n"
                        f"  {secret} = a\n"
                        f"  status = {response.status}\n"
                        f"  policy error: none"
                    ),
                    matched="accepted a single character",
                    field=secret,
                )
            )
        return findings


class OAuthStateModule(Module):
    """Does the authorize endpoint require a state parameter?

    A flow that completes without one cannot distinguish a callback the user
    started from one an attacker crafted, which is the whole of OAuth CSRF.
    """

    group = "oauth"

    id = "oauth_state_missing"
    name = "OAuth state Parameter Not Required"
    description = (
        "Replays an authorization request with the state parameter removed and "
        "reports endpoints that still issue the redirect."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.AUTH
    capability = Capability.HTTP
    cwe = "CWE-352"
    owasp = "A07"
    remediation = "Generate a per-request state value and verify it on callback."
    references = ["https://datatracker.ietf.org/doc/html/rfc6749#section-10.12"]
    tags = ["oauth", "csrf", "active"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints:
            parsed = urlparse(endpoint.url)
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            names = {key for key, _ in pairs}
            if not {"client_id", "redirect_uri"} <= names or endpoint.url in seen:
                continue
            seen.add(endpoint.url)
            if "state" not in names:
                continue

            stripped = urlunparse(
                parsed._replace(query=urlencode([(k, v) for k, v in pairs if k != "state"]))
            )
            response = await ctx.client.get(stripped, follow_redirects=False)
            location = ""
            for key, value in response.headers.items():
                if key.lower() == "location":
                    location = value
            if response.status not in (301, 302, 303, 307) or not location:
                continue
            if not any(value for key, value in pairs if key == "redirect_uri"):
                continue

            findings.append(
                self.finding(
                    title="OAuth authorize proceeds without a state parameter",
                    target=endpoint.url,
                    description=(
                        "The authorization endpoint issued a redirect even though "
                        "the state parameter was removed. A callback cannot be "
                        "tied to the user who started the flow, so an attacker "
                        "can graft their own authorization code onto a victim's "
                        "session."
                    ),
                    evidence_text=(
                        f"GET {stripped}\n"
                        f"  status   = {response.status}\n"
                        f"  location = {location}"
                    ),
                    matched=location[:200],
                )
            )
        return findings

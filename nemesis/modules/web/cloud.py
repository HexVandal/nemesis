"""Cloud attack surface.

A cloud deployment has an attack surface that a traditional scanner does
not know about, and it is the surface that matters most:

- **The instance metadata service.** On AWS, `169.254.169.254` returns
  the IAM credentials of the role the instance is running as - temporary
  credentials that are usually more privileged than anything the
  application itself uses. On GCP and Azure the equivalents are
  different, and the risk is the same. An SSRF in the application is
  therefore a cloud-credential compromise, and that is the difference
  between a medium and a critical finding.
- **IMDSv1.** AWS IMDSv1 is a single unauthenticated GET. IMDSv2
  requires a session token obtained with a `PUT`, and the hop limit
  matters: a hop limit of 1 stops a container from reaching the
  metadata service through a proxy.
- **Public storage.** A bucket that allows anonymous `GetObject` leaks
  whatever was written to it, and a lot gets written to buckets.
- **Signed URL abuse.** A pre-signed URL that is valid for years, or one
  that does not bind the HTTP method, is a permanent public link.
- **Storage event notifications.** They leak object names, and object
  names leak structure.

This module checks the metadata service directly, looks for cloud storage
endpoints, and tests the storage rules it can reach.
"""

from __future__ import annotations

import re

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule

#: Cloud metadata endpoints and what they mean.
METADATA_ENDPOINTS = (
    ("http://169.254.169.254/latest/meta-data/", "AWS instance metadata"),
    ("http://169.254.169.254/latest/api/token", "AWS IMDSv2 token endpoint"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata service"),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure instance metadata"),
    ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
)

#: The paths that carry credentials rather than configuration.
CREDENTIAL_PATHS = (
    "/latest/meta-data/iam/security-credentials/",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/metadata/identity/oauth2/token",
)

#: Cloud storage hostnames.
STORAGE_HOSTS = (
    "s3.amazonaws.com",
    "s3.",
    "storage.googleapis.com",
    "blob.core.windows.net",
    "r2.cloudflarestorage.com",
)

#: A pre-signed URL. The signature is the interesting part.
SIGNED_URL = re.compile(
    r"https?://[^\s\"'<>]+"
    r"(?:[?&](?:X-Amz-Signature|Signature|X-Goog-Signature|sig|token)=[^\s\"'<>]+)"
)

#: A long-lived signed URL.
LONG_LIVED_SIGNATURE = re.compile(
    r"(?:X-Amz-Expires|Expires)=(\d{5,})|se=(\d{9,})"
)

#: The maximum a pre-signed URL should live, in seconds (7 days).
MAX_SIGNED_URL_LIFETIME = 7 * 24 * 3600


class CloudAttackSurfaceModule(HttpModule):
    """Probes the cloud attack surface around a target."""

    group = "ssrf"
    id = "cloud_attack_surface"
    name = "Cloud Attack Surface"
    description = (
        "Checks the cloud metadata service, looks for exposed cloud "
        "storage and pre-signed URLs, and reports how much of the cloud "
        "an SSRF would reach."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.SSRF
    capability = Capability.HTTP
    cwe = "CWE-918"
    owasp = "A10"
    tags = ["cloud", "aws", "gcp", "azure", "metadata", "imds", "s3", "storage"]
    remediation = (
        "Require IMDSv2 with a hop limit of 1, and block the metadata "
        "address at the egress proxy and in the subnet route table so an "
        "SSRF cannot reach it. Give the instance role only the "
        "permissions the workload needs, and scope pre-signed URLs to a "
        "short lifetime and a single HTTP method."
    )
    references = [
        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/08-Testing_Cloud_Services",
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    ]

    max_payloads = 1

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        # 1. The metadata service, reached directly.
        metadata = await self._probe_metadata(ctx)
        findings.extend(metadata)

        # 2. Cloud storage and signed URLs in the crawled responses.
        findings.extend(self._scan_responses(ctx))

        # 3. Does the application itself fetch cloud URLs?
        findings.extend(self._scan_endpoints(ctx))

        return findings

    # -- metadata --------------------------------------------------------
    async def _probe_metadata(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for url, label in METADATA_ENDPOINTS:
            response = await self._safe_get(ctx, url)
            if response is None:
                continue
            if response.status in (200, 401, 403) and not response.error:
                # A 401 from IMDSv2 is a *good* answer: the service exists
                # and requires a token. A 200 is the bad one.
                if response.status == 200:
                    findings.append(
                        self.finding(
                            title=f"{label} is reachable and returned data",
                            target=url,
                            description=(
                                f"The {label} answered a plain unauthenticated "
                                f"GET with {response.status}. On AWS, the "
                                f"IMDSv1 metadata path returns the IAM "
                                f"credentials of the role the instance runs "
                                f"as, and those are usually more privileged "
                                f"than anything the application uses. An SSRF "
                                f"in the application is then a full cloud "
                                f"compromise, not a data leak."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            evidence_text=(
                                f"URL    : {url}\n"
                                f"Status : {response.status}\n"
                                f"Body   : {response.text[:600]}"
                            ),
                            matched=url,
                        )
                    )
                else:
                    findings.append(
                        self.finding(
                            title=f"{label} is reachable (authentication required)",
                            target=url,
                            description=(
                                f"The {label} responded with {response.status} "
                                f"rather than being unreachable. The service "
                                f"is exposed to this host. If the "
                                f"application has an SSRF, an attacker who "
                                f"can reach this host can reach it too, and "
                                f"whether they can use what they get depends "
                                f"on the token policy."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            evidence_text=(
                                f"URL    : {url}\n"
                                f"Status : {response.status}"
                            ),
                            matched=url,
                        )
                    )
        return findings

    # -- responses -------------------------------------------------------
    def _scan_responses(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for response in ctx.responses:
            for match in SIGNED_URL.finditer(response.text):
                url = match.group(0)
                lifetime = self._signed_url_lifetime(url)
                if lifetime is not None and lifetime > MAX_SIGNED_URL_LIFETIME:
                    findings.append(
                        self.finding(
                            title="Pre-signed cloud URL with a long lifetime",
                            target=response.url,
                            description=(
                                f"A pre-signed URL is visible in the response "
                                f"from {response.url}, and it is valid for "
                                f"about {lifetime // 86400} days. A pre-signed "
                                f"URL is a bearer token: anyone who has it "
                                f"has the access, and it cannot be revoked "
                                f"individually. A week is a reasonable ceiling "
                                f"for a download link."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            evidence_text=(
                                f"URL      : {response.url}\n"
                                f"Signed   : {url[:200]}\n"
                                f"Lifetime : ~{lifetime // 86400} days"
                            ),
                            matched=url[:200],
                        )
                    )
                    break
        return findings

    def _scan_endpoints(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for endpoint in ctx.endpoints:
            lowered = endpoint.url.lower()
            for host_marker in STORAGE_HOSTS:
                if host_marker not in lowered:
                    continue
                if lowered in seen:
                    break
                seen.add(lowered)
                bucket = self._bucket_name(lowered)
                findings.append(
                    self.finding(
                        title="Application references a cloud storage endpoint",
                        target=endpoint.url,
                        description=(
                            f"{endpoint.url} points at cloud storage"
                            + (f" (bucket '{bucket}')" if bucket else "")
                            + ". Storage endpoints are where bulk data lives, "
                            "and they are worth checking independently: the "
                            "object may be readable even when the URL is "
                            "not."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        evidence_text=f"URL: {endpoint.url}",
                        matched=bucket or host_marker,
                    )
                )
                break
        return findings

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _bucket_name(url: str) -> str:
        match = re.search(r"://([^./]+)\.s3[.-]", url)
        if match:
            return match.group(1)
        match = re.search(r"://storage\.googleapis\.com/([^/?#]+)", url)
        if match:
            return match.group(1)
        return ""

    @staticmethod
    def _signed_url_lifetime(url: str) -> int | None:
        for pattern in (r"[?&]X-Amz-Expires=(\d+)", r"[?&]Expires=(\d+)", r"[?&]se=(\d+)"):
            match = re.search(pattern, url)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    continue
        return None

    async def _safe_get(self, ctx: ScanContext, url: str):
        """GET a URL that is usually outside the scan scope.

        The metadata service is a link-local address that is almost never
        in scope, and reaching it is the entire point of the check. The
        request is made directly, with a short timeout, and the response
        is only used to decide whether to report.
        """
        if ctx.client is None:
            return None
        try:
            return await ctx.client.get(
                url, follow_redirects=False, timeout=3.0
            )
        except Exception:
            return None

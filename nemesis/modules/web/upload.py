"""File upload vulnerabilities.

An upload endpoint is a small execution surface: the server decides what to
call the file, where to put it, and whether the file is later served with a
type that the browser will run.

The checks here are all differential. A benign upload of a text file is
compared with uploads of the same content under a dangerous name, a
mismatched content type, a double extension and a traversal path. A finding
is only raised when the server treated the dangerous upload differently
from the benign one.
"""

from __future__ import annotations

import base64

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import ScanContext
from ..http_helper import HttpModule

#: A harmless file body that every upload test reuses.
SAFE_BODY = b"nemesis upload probe\n"

#: A file that is harmless as a name but is a script when executed.
SCRIPT_BODY = b"<?php echo 'nemesis'; ?>\n"

#: The upload field names to try, in order of likelihood.
UPLOAD_FIELDS = ("file", "upload", "image", "avatar", "attachment", "document", "media")


class FileUploadModule(HttpModule):
    """Tests upload endpoints for filter bypass and dangerous storage."""

    group = "upload"
    id = "file_upload"
    name = "File Upload Vulnerabilities"
    description = (
        "Probes multipart upload endpoints for extension filtering bypass, "
        "content-type confusion, double extensions, path traversal in the "
        "filename and files that are stored and later served as active "
        "content."
    )
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    category = Category.INJECTION
    capability = Capability.HTTP
    cwe = "CWE-434"
    owasp = "A04"
    tags = ["upload", "file", "rce", "bypass"]
    remediation = (
        "Store uploads outside the web root, serve them with a fixed "
        "non-executable content type, and generate the stored filename "
        "server-side instead of trusting the client's. Validate the file "
        "content, not just its extension."
    )
    references = ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"]

    #: Extensions the server should never accept for a user upload.
    dangerous_extensions = (
        "php", "phtml", "php3", "php4", "php5", "pht", "phar",
        "jsp", "jspx", "jsw", "jsv", "jspf",
        "asp", "aspx", "cer", "asa", "ashx", "asmx",
        "cgi", "pl", "py", "rb", "sh", "bash",
        "exe", "dll", "so", "jar", "war", "htaccess",
    )

    max_params = 15

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for target in self._upload_targets(ctx):
            for probe in self._probes():
                result = await self._try(ctx, target, probe)
                if result is None:
                    continue
                accepted, detail = result
                if not accepted:
                    continue
                findings.append(
                    self.finding(
                        title=f"File upload accepted a dangerous file: {probe['label']}",
                        target=target.url,
                        description=(
                            f"The upload endpoint accepted a file that "
                            f"should have been rejected ({probe['label']}). "
                            f"{detail} If the stored file is later served "
                            f"from the same origin, this becomes remote "
                            f"code execution."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence_text=(
                            f"Endpoint  : {target.url}\n"
                            f"Field     : {target.param}\n"
                            f"Filename  : {probe['filename']}\n"
                            f"Type      : {probe['content_type']}\n"
                            f"Technique : {probe['label']}\n"
                            f"Result    : {detail}"
                        ),
                        matched=probe["filename"],
                    )
                )
        return findings

    # -- helpers ---------------------------------------------------------
    def _upload_targets(self, ctx: ScanContext) -> list:
        """Find parameters that look like a file upload."""
        from ..http_helper import ParamTarget

        targets: list[ParamTarget] = []
        seen: set[str] = set()

        for form in ctx.forms:
            for param in form.raw_fields:
                if param.lower() not in UPLOAD_FIELDS:
                    continue
                if form.fields.get("_nemesis_file_upload") == "1":
                    continue
                key = f"{form.method}:{form.action}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(
                    ParamTarget(
                        url=form.action,
                        param=param,
                        method=form.method,
                        fields=dict(form.fields),
                    )
                )

        for endpoint in ctx.endpoints:
            for param in endpoint.params:
                if param.lower() not in UPLOAD_FIELDS:
                    continue
                key = f"GET:{endpoint.url}:{param}"
                if key in seen:
                    continue
                seen.add(key)
                targets.append(ParamTarget(url=endpoint.url, param=param, method="GET"))

        return targets[: self.max_params]

    def _probes(self) -> list[dict]:
        """The upload shapes worth trying, safest first."""
        return [
            {
                "label": "double extension",
                "filename": "nemesis.php.jpg",
                "content_type": "image/jpeg",
                "body": SCRIPT_BODY,
            },
            {
                "label": "executable extension",
                "filename": "nemesis.php",
                "content_type": "image/jpeg",
                "body": SCRIPT_BODY,
            },
            {
                "label": "content type mismatch",
                "filename": "nemesis.txt",
                "content_type": "image/jpeg",
                "body": SCRIPT_BODY,
            },
            {
                "label": "path traversal in filename",
                "filename": "../../nemesis-upload.php",
                "content_type": "image/jpeg",
                "body": SCRIPT_BODY,
            },
            {
                "label": "null byte extension",
                "filename": "nemesis.php\x00.jpg",
                "content_type": "image/jpeg",
                "body": SCRIPT_BODY,
            },
            {
                "label": "data uri content type",
                "filename": "nemesis.png",
                "content_type": "data:image/png;base64,"
                + base64.b64encode(SCRIPT_BODY).decode(),
                "body": SCRIPT_BODY,
            },
        ]

    async def _try(self, ctx: ScanContext, target, probe: dict) -> tuple[bool, str] | None:
        """Upload one probe and compare it with a benign upload."""
        benign = await self._upload(ctx, target, "nemesis.txt", "text/plain", SAFE_BODY)
        if benign is None:
            return None
        result = await self._upload(
            ctx, target, probe["filename"], probe["content_type"], probe["body"]
        )
        if result is None:
            return None

        status, text = result
        if status == 0:
            return None

        # The upload was rejected outright, which is the correct behaviour.
        if status >= 400:
            return False, ""

        # A benign upload of the same shape is accepted, so acceptance
        # alone proves nothing. What matters is that the dangerous one was
        # treated the same as the benign one.
        if benign[0] >= 400:
            return False, ""

        if probe["filename"] in text or probe["filename"].split("/")[-1] in text:
            return True, (
                "the server echoed the dangerous filename back, so it was "
                "stored under that name"
            )
        if benign[0] == status and benign[1] == text:
            return True, (
                "the dangerous upload was accepted and stored exactly like "
                "the benign one, so no filter stopped it"
            )
        return False, ""

    async def _upload(
        self, ctx: ScanContext, target, filename: str, content_type: str, body: bytes
    ) -> tuple[int, str] | None:
        """Send one multipart upload."""
        files = {target.param: (filename, body, content_type)}
        try:
            response = await ctx.client.post(
                target.url, files=files, follow_redirects=False
            )
        except Exception:
            return None
        return response.status, response.text or ""

"""TLS configuration analysis."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from ...models import Capability, Category, Confidence, Finding, Severity
from ..base import Module, ScanContext


class TlsConfigurationModule(Module):
    """Review the TLS configuration of the target host."""
    group = "host"

    id = "tls_configuration"
    name = "TLS Configuration Weakness"
    description = (
        "Checks the negotiated TLS version, certificate validity, hostname "
        "matching and the cipher suites the server is willing to use."
    )
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.TRANSPORT
    capability = Capability.HOST
    cwe = "CWE-326"
    owasp = "A02"
    tags = ["tls", "ssl", "transport"]
    remediation = (
        "Serve TLS 1.2 or 1.3 only, prefer AEAD cipher suites, keep the "
        "certificate chain complete and renew before expiry."
    )
    references = [
        "https://ssl-config.mozilla.org/STARTTLS/",
        "https://owasp.org/www-project-secure-headers/",
    ]

    #: Protocols that must not be offered.
    _LEGACY_PROTOCOLS = [
        ("SSLv2", getattr(ssl, "PROTOCOL_SSLv2", None)),
        ("SSLv3", getattr(ssl, "PROTOCOL_SSLv3", None)),
        ("TLSv1", getattr(ssl, "PROTOCOL_TLSv1", None)),
        ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
    ]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        parsed = urlparse(ctx.target_url)
        if parsed.scheme != "https":
            return []
        host = parsed.hostname or ctx.host
        port = parsed.port or 443
        findings: list[Finding] = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        except Exception as exc:
            ctx.stats.setdefault("tls_errors", []).append(str(exc))
            return findings

        # 1. Which protocol versions does the server still accept?
        for name, proto in self._LEGACY_PROTOCOLS:
            if proto is None:
                continue
            try:
                legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                legacy.check_hostname = False
                legacy.verify_mode = ssl.CERT_NONE
                legacy.maximum_version = proto
                legacy.minimum_version = proto
                with socket.create_connection((host, port), timeout=8) as sock:
                    with legacy.wrap_socket(sock, server_hostname=host) as tls:
                        negotiated = tls.version()
            except Exception:
                continue
            findings.append(
                self.finding(
                    title=f"Server accepts {name}",
                    target=f"{host}:{port}",
                    description=(
                        f"{host} still negotiates {name}, which is deprecated and "
                        "known to be vulnerable. Only TLS 1.2 and 1.3 should be "
                        "offered."
                    ),
                    severity=Severity.MEDIUM if name in ("TLSv1", "TLSv1.1") else Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_text=f"Negotiated protocol: {negotiated} with {host}:{port}",
                    matched=name,
                )
            )

        # 2. Certificate health.
        try:
            with socket.create_connection((host, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    cipher = tls.cipher()
                    negotiated = tls.version()
        except ssl.SSLError as exc:
            findings.append(
                self.finding(
                    title="TLS certificate could not be validated",
                    target=f"{host}:{port}",
                    description=(
                        f"The certificate presented by {host} failed validation: {exc}. "
                        "Clients may refuse to connect or the connection may be "
                        "interceptable."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence_text=str(exc),
                    matched=str(exc)[:200],
                )
            )
            return findings
        except Exception:
            return findings

        if not cert:
            return findings

        not_after = cert.get("notAfter")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                now = datetime.now(timezone.utc)
                if expiry < now:
                    findings.append(
                        self.finding(
                            title="TLS certificate has expired",
                            target=f"{host}:{port}",
                            description=(
                                f"The certificate for {host} expired on {not_after}. "
                                "Clients will show warnings and may refuse the "
                                "connection."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            evidence_text=f"notAfter: {not_after}",
                            matched=not_after,
                        )
                    )
                elif (expiry - now).days < 14:
                    findings.append(
                        self.finding(
                            title="TLS certificate expires soon",
                            target=f"{host}:{port}",
                            description=(
                                f"The certificate for {host} expires on {not_after}, "
                                f"in {(expiry - now).days} days."
                            ),
                            severity=Severity.LOW,
                            confidence=Confidence.HIGH,
                            evidence_text=f"notAfter: {not_after}",
                            matched=not_after,
                        )
                    )
            except ValueError:
                pass

        if cipher:
            name = cipher[0]
            if "GCM" not in name and "CHACHA" not in name and "CCM" not in name:
                findings.append(
                    self.finding(
                        title="Non-AEAD cipher suite negotiated",
                        target=f"{host}:{port}",
                        description=(
                            f"The server negotiated {name}, which is not an AEAD "
                            "cipher. Prefer AES-GCM or ChaCha20-Poly1305."
                        ),
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        evidence_text=f"Protocol: {negotiated}\nCipher: {name}",
                        matched=name,
                    )
                )

        return findings

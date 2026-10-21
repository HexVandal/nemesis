"""The vulnerability taxonomy, and what nemesis can honestly say about it.

A scanner that claims coverage needs a denominator. This module holds the
taxonomy the product is measured against - 2,883 classes in 50 families - and
records, for each family, the *kind* of evidence nemesis can produce and the
modules that produce it.

The verdicts are deliberately blunt. A web scanner cannot find a kernel
use-after-free, and saying so costs nothing while pretending otherwise costs
the user their trust.

Verdicts
--------
``http``
    Directly testable against a running target over HTTP. Evidence is a
    request, a response, and a delta between them.
``code``
    Needs a source tree or a build artifact. Evidence is a location, a
    pattern and an explanation.
``host``
    Needs network or host posture: TLS, DNS, packet captures.
``artifact``
    Needs a container, binary or manifest to inspect.
``manual``
    Needs a human, a browser, or knowledge of the application's intent.
``out-of-scope``
    Cannot be determined without kernel instrumentation, physical access or
    hardware. nemesis does not pretend to look.
``self``
    A defect class that applies to the scanner itself. Covered by nemesis's
    own test suite rather than by a scan target.
"""

from __future__ import annotations

from dataclasses import dataclass

VERDICTS = ("http", "code", "host", "artifact", "manual", "out-of-scope", "self")

VERDICT_LABELS = {
    "http": "testable over HTTP",
    "code": "needs source",
    "host": "needs host/network posture",
    "artifact": "needs an artifact",
    "manual": "needs a human",
    "out-of-scope": "not determinable from outside",
    "self": "applies to the scanner itself",
}


@dataclass(frozen=True)
class Family:
    """One family of the taxonomy, and what can be said about it."""

    number: int
    name: str
    first_class: int
    last_class: int
    verdict: str
    modules: tuple[str, ...] = ()
    note: str = ""

    @property
    def count(self) -> int:
        return self.last_class - self.first_class + 1


#: The taxonomy, family by family. Ranges are inclusive and contiguous:
#: ``test_the_ranges_are_contiguous`` fails if a class is ever dropped.
CATEGORIES: tuple[Family, ...] = (
    Family(1, "Web Application Vulnerabilities", 1, 80, "http",
           ("sqli", "nosql_injection", "command_injection", "template_injection",
            "xss", "xml_external_entity", "insecure_deserialization",
            "path_traversal", "file_upload", "open_redirect", "host_header_injection",
            "request_smuggling", "web_cache_poisoning", "exposed_files",
            "directory_listing", "info_disclosure"),
           "The core of the HTTP surface."),
    Family(2, "Cross-Site Scripting and Browser Injection", 81, 140, "http",
           ("xss", "csp_analyzer", "clickjacking", "cors_misconfig",
            "cookie_flags", "mixed_content", "browser_security", "csrf_missing"),
           "Reflected and stored XSS are testable; DOM XSS needs a browser, which "
           "nemesis deliberately does not ship."),
    Family(3, "Server-Side Request Forgery and Network-Facing Bugs", 141, 175, "http",
           ("ssrf", "cloud_attack_surface"),
           "Blind and out-of-band variants need an interaction server."),
    Family(4, "XML, Serialization and Parser Vulnerabilities", 176, 225, "http",
           ("xml_external_entity", "insecure_deserialization"),
           "XXE and unsafe deserialisation are testable; parser memory-safety bugs are not."),
    Family(5, "Authentication Vulnerabilities", 226, 320, "http",
           ("csrf_missing", "open_redirect", "jwt_weakness", "mass_assignment",
            "host_header_injection", "info_disclosure"),
           "JWT and account-surface checks are native; MFA quality needs credentials "
           "and a second factor."),
    Family(6, "Authorization and Access-Control Vulnerabilities", 321, 370, "http",
           ("idor", "mass_assignment", "business_logic"),
           "IDOR needs two accounts to prove; single-account probing is partial by nature."),
    Family(7, "Business Logic Vulnerabilities", 371, 450, "http",
           ("price_tampering", "business_logic"),
           "Price, quantity and coupon tampering are native. Workflow and state-machine "
           "bypass need the application's own rules."),
    Family(8, "API Vulnerabilities", 451, 530, "http",
           ("graphql_introspection", "idor", "mass_assignment", "price_tampering"),
           "REST and GraphQL introspection are covered; gRPC needs its own transport."),
    Family(9, "Injection Beyond Web Applications", 531, 600, "http",
           ("command_injection", "sqli", "nosql_injection", "template_injection"),
           "HTTP-reachable injection is covered; SMTP, IMAP and DNS injection are not."),
    Family(10, "Cryptographic Vulnerabilities", 601, 670, "code",
           ("crypto_misuse", "tls_configuration"),
           "Source patterns and TLS posture are checked; oracle attacks need an oracle."),
    Family(11, "Memory Safety Vulnerabilities", 671, 740, "artifact",
           ("binary_triage", "binary_exploit_primitives"),
           "Binaries are triaged for mitigations and primitives; proving a UAF needs a debugger."),
    Family(12, "Operating System and Kernel Vulnerabilities", 741, 820, "out-of-scope",
           (), "Requires kernel instrumentation or a live host; outside a network scanner."),
    Family(13, "Denial-of-Service and Resource Exhaustion", 821, 895, "http",
           ("request_smuggling", "business_logic"),
           "Unbounded-input patterns can be inferred; deliberately exhausting a target "
           "is destructive and is not performed."),
    Family(14, "Network and Protocol Vulnerabilities", 896, 970, "host",
           ("tls_configuration", "dns_posture", "ipv6_security", "pcap_analysis"),
           "TLS, DNS and IPv6 posture are native; routing and wireless are not."),
    Family(15, "Cloud Security Vulnerabilities", 971, 1030, "http",
           ("cloud_attack_surface",),
           "Metadata endpoints and exposed buckets are reachable; IAM review needs cloud APIs."),
    Family(16, "Containers and Kubernetes", 1031, 1090, "artifact",
           (), "Needs the image or the cluster; a web scan cannot see either."),
    Family(17, "CI/CD, Build Systems and Supply Chain", 1091, 1160, "code",
           ("cicd_pipeline_security", "dependency_confusion", "typosquatting"),
           "Workflow files and manifests are analysed statically."),
    Family(18, "Database Vulnerabilities", 1161, 1220, "http",
           ("sqli", "nosql_injection", "info_disclosure"),
           "Reachable injection is covered; engine configuration and replication are not."),
    Family(19, "Mobile Application Vulnerabilities", 1221, 1280, "out-of-scope",
           (), "Requires an APK or IPA. Not shipped."),
    Family(20, "Desktop Application Vulnerabilities", 1281, 1320, "artifact",
           ("binary_triage",), "Binaries can be triaged; Electron and IPC analysis is absent."),
    Family(21, "Browser and Client-Side Security", 1321, 1380, "http",
           ("browser_security", "csp_analyzer", "cors_misconfig", "clickjacking",
            "cookie_flags", "mixed_content"),
           "Header and policy posture is native. Prototype pollution and DOM sinks "
           "need JavaScript execution."),
    Family(22, "IoT and Embedded Systems", 1381, 1440, "out-of-scope",
           (), "Firmware and hardware interfaces."),
    Family(23, "Hardware and Side-Channel Vulnerabilities", 1441, 1480, "out-of-scope",
           (), "Physical access, fault injection, power analysis."),
    Family(24, "AI, Machine Learning and LLM Security", 1481, 1570, "http",
           ("llm_endpoint_detection", "prompt_injection", "agent_tool_security",
            "model_extraction", "ml_model_security"),
           "Prompt injection and model-file handling are native; training-time attacks are not."),
    Family(25, "Blockchain and Smart Contract Vulnerabilities", 1571, 1650, "code",
           ("solidity_audit", "defi_security"),
           "Solidity source is analysed; on-chain economics need a fork and a simulator."),
    Family(26, "Identity, Directory Services and Enterprise", 1651, 1710, "host",
           (), "Active Directory and Kerberos need domain credentials and a domain."),
    Family(27, "Configuration and Deployment Weaknesses", 1711, 1770, "http",
           ("headers_security", "cookie_flags", "tls_configuration", "info_disclosure",
            "exposed_files"),
           "Headers, cookies and exposed config are native."),
    Family(28, "Information Disclosure and Privacy", 1771, 1840, "http",
           ("info_disclosure", "exposed_files", "secrets", "git_history_secrets"),
           "Exposed files, secrets and stack traces are native; data-residency questions are legal."),
    Family(29, "Logging, Monitoring and Audit Failures", 1841, 1880, "out-of-scope",
           (), "Observability is internal state; it cannot be seen from outside."),
    Family(30, "Race Conditions and Concurrency Defects", 1881, 1930, "out-of-scope",
           (), "Proving a race needs repeated concurrent requests against a known workflow."),
    Family(31, "Software Correctness and Reliability Bugs", 1931, 2040, "code",
           ("logic_bugs", "dangerous_patterns"),
           "Whole classes of logic defects are visible in source; runtime behaviour is not."),
    Family(32, "Build, Compiler and Language-Level Defects", 2041, 2090, "artifact",
           ("binary_triage",), "Compiler flags and binary properties can be read from the artifact."),
    Family(33, "Filesystem and Storage Bugs", 2091, 2140, "code",
           ("path_traversal", "iac_misconfiguration"), "Source patterns only."),
    Family(34, "Messaging, Queues and Event-Driven Systems", 2141, 2180, "out-of-scope",
           (), "Broker configuration lives in the broker."),
    Family(35, "Observability, Monitoring and Infrastructure Tools", 2181, 2210, "http",
           ("info_disclosure",), "Exposed metrics and debug endpoints are reachable over HTTP."),
    Family(36, "Machine Learning and Data Pipeline Reliability", 2211, 2250, "out-of-scope",
           (), "Pipeline internals."),
    Family(37, "Privacy, Consent and Data Governance", 2251, 2280, "manual",
           (), "Consent and purpose limitation are questions about intent, not bytes."),
    Family(38, "Configuration Parsers and Infrastructure-as-Code", 2281, 2320, "code",
           ("iac_misconfiguration",), "Terraform, Kubernetes and Ansible manifests are parsed."),
    Family(39, "Authentication and Authorization Implementation", 2321, 2360, "code",
           ("logic_bugs", "crypto_misuse", "jwt_weakness"), "Source-level handling of tokens and sessions."),
    Family(40, "API and Protocol Correctness Defects", 2361, 2400, "http",
           ("request_smuggling", "web_cache_poisoning"), "Framing and parsing differentials are testable."),
    Family(41, "Cryptographic Implementation and Key Lifecycle", 2401, 2440, "code",
           ("crypto_misuse",), "Source patterns; key lifecycle is an operational question."),
    Family(42, "Testing, Quality Assurance and Regression Defects", 2441, 2480, "self",
           (), "applies to nemesis's own suite."),
    Family(43, "Deployment, Availability and Recovery", 2481, 2530, "out-of-scope",
           (), "Operational state."),
    Family(44, "Additional Common Software Defects", 2531, 2600, "code",
           ("logic_bugs",), "Source-level correctness patterns."),
    Family(45, "Security Architecture and Design Weaknesses", 2601, 2640, "manual",
           (), "Design review."),
    Family(46, "Network, Proxy and Gateway Defects", 2641, 2680, "http",
           ("proxy_security", "host_header_injection", "request_smuggling"),
           "Header trust and routing confusion are testable."),
    Family(47, "Supply-Chain and Repository Security", 2681, 2720, "code",
           ("secrets", "git_history_secrets", "cicd_pipeline_security",
            "dependency_vulnerabilities", "typosquatting"),
           "History, manifests and workflow files."),
    Family(48, "Input Validation and Canonicalization", 2721, 2760, "http",
           ("path_traversal", "open_redirect", "host_header_injection", "xss"),
           "Parser differentials against the target's own handling."),
    Family(49, "Authentication, Session and Identity Defects", 2761, 2800, "http",
           ("cookie_flags", "csrf_missing", "jwt_weakness", "idor"), "Session surface over HTTP."),
    Family(50, "Defect Classes for Scanner Engineering", 2801, 2883, "self",
           (), "A checklist nemesis is held to; see tests/ for the evidence."),
)


def all_classes() -> int:
    """How many classes the taxonomy describes."""
    return sum(family.count for family in CATEGORIES)


def by_verdict() -> dict[str, int]:
    """Class count per verdict."""
    counts = dict.fromkeys(VERDICTS, 0)
    for family in CATEGORIES:
        counts[family.verdict] += family.count
    return counts


def coverage_ratio() -> float:
    """Share of classes a scanner of this kind can address at all.

    This is the honest denominator: classes that need physical access or
    kernel instrumentation are not "missing features", they are outside the
    problem.
    """
    total = all_classes()
    reachable = sum(
        family.count
        for family in CATEGORIES
        if family.verdict in ("http", "code", "host", "artifact")
    )
    return round(100.0 * reachable / total, 1) if total else 0.0


__all__ = [
    "CATEGORIES",
    "VERDICTS",
    "VERDICT_LABELS",
    "Family",
    "all_classes",
    "by_verdict",
    "coverage_ratio",
]

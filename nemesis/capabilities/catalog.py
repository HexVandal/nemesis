"""The capability catalogue.

Every area named in the brief appears here exactly once, with an honest
maturity label and pointers to the parts of nemesis that implement it.

The registry validates this catalogue against the real module registry, so a
capability can never claim a module that does not exist.
"""

from __future__ import annotations

from .model import Capability

#: The full catalogue, in the order the brief listed it.
CAPABILITIES: tuple[Capability, ...] = (
    # -- Binary and memory exploitation ---------------------------------
    Capability(
        id="buffer-overflow",
        name="Buffer Overflow",
        domain="exploitation",
        maturity="partial",
        summary=(
            "Locates the primitives that make an overflow exploitable: unsafe "
            "string and memory functions, missing stack canaries, writable "
            "and executable stack, and unprotected binaries. Writing the "
            "exploit itself needs a debugger and a target."
        ),
        modules=("binary_exploit_primitives", "dangerous_patterns",),
        tools=("gdb", "pwndbg", "checksec", "pwntools"),
        artifacts=("primitive report", "binary triage"),
        prerequisites=("a running target", "a debugger"),
    ),
    Capability(
        id="heap-exploitation",
        name="Heap Exploitation",
        domain="exploitation",
        maturity="research",
        summary=(
            "Heap shaping, tcache and fastbin behaviour, and allocator "
            "differential analysis. Exploitation depends on the exact libc "
            "build, so this is a lab activity rather than a scan."
        ),
        tools=("gdb", "patchelf", "glibc source", "heaptracer"),
        artifacts=("binary triage",),
        prerequisites=("a matching libc", "a fuzzing or exploit lab"),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="kernel-exploitation",
        name="Kernel Exploitation",
        domain="exploitation",
        maturity="research",
        summary=(
            "Kernel attack surface: syscall and ioctl handlers, refcount and "
            "lifetime bugs, and hardening posture. nemesis audits kernel "
            "configuration and flags suspicious code patterns; exploitation "
            "requires a specific kernel build and a lab."
        ),
        modules=("binary_triage", "binary_exploit_primitives",),
        tools=("gdb", "kgsl", "syzkaller"),
        artifacts=("binary triage",),
        prerequisites=("a vulnerable kernel", "a privileged lab"),
    ),
    Capability(
        id="linux-kernel-security",
        name="Linux Kernel Security",
        domain="internals",
        maturity="partial",
        summary=(
            "Audits kernel hardening configuration - KASLR, SMEP, SMAP, "
            "stack protector, module signature enforcement - and matches a "
            "running kernel against published kernel CVEs."
        ),
        tools=("sysctl", "kexec"),
        artifacts=("host posture report",),
        modules=("privilege_escalation",),
    ),
    Capability(
        id="windows-internals",
        name="Windows Internals",
        domain="internals",
        maturity="research",
        summary=(
            "PE structure, token manipulation, service and registry abuse, "
            "and named-pipe impersonation. nemesis can triage PE binaries; "
            "the internals work needs a Windows host."
        ),
        modules=("binary_triage",),
        tools=("Process Hacker", "psexec"),
        artifacts=("binary triage",),
        prerequisites=(("a Windows host",)),
    ),
    Capability(
        id="linux-internals",
        name="Linux Internals",
        domain="internals",
        maturity="partial",
        summary=(
            "ELF parsing, SUID and file-capability analysis, namespace and "
            "cgroup escape primitives, and procfs hardening checks."
        ),
        modules=("binary_triage", "privilege_escalation",),
        artifacts=("binary triage",),
    ),
    Capability(
        id="privilege-escalation",
        name="Privilege Escalation",
        domain="exploitation",
        maturity="partial",
        summary=(
            "Finds privilege escalation primitives in code and in local "
            "filesystem configuration: SUID binaries, over-permissive sudo "
            "rules, dangerous file capabilities, writable service files, "
            "unsafe PATH handling and namespace escapes."
        ),
        modules=("privilege_escalation",),
        artifacts=("privesc report",),
    ),
    Capability(
        id="sandbox-escapes",
        name="Sandbox Escapes",
        domain="exploitation",
        maturity="partial",
        summary=(
            "Container and jail escape primitives: privileged mounts, "
            "host filesystem mounts, dangerous capabilities, and writable "
            "namespace targets. nemesis audits the configuration that makes "
            "an escape possible."
        ),
        modules=("iac_misconfiguration", "sandbox_escape",),
        tools=("nsjail", "firejail"),
        artifacts=("IaC misconfiguration report",),
        prerequisites=(("a container runtime to test against",)),
    ),
    Capability(
        id="browser-exploitation",
        name="Browser Exploitation",
        domain="exploitation",
        maturity="research",
        summary=(
            "Browser sandbox and renderer vulnerabilities. nemesis audits the "
            "web surface a browser reaches - CSP, cross-origin policy, "
            "cookie and origin handling - which is the part that matters "
            "for defending a browser-based application."
        ),
        modules=("csp_analyzer", "headers_security"),
        artifacts=("browser security report",),
        prerequisites=(("a browser build and a fuzzing corpus",)),
    ),
    Capability(
        id="shellcode-development",
        name="Shellcode Development",
        domain="exploitation",
        maturity="partial",
        summary=(
            "Nemesis can validate and test shellcode: check a payload for "
            "bad characters, verify an encoder round-trips through a "
            "constrained shell, and confirm a payload survives a real "
            "request path."
        ),
        tools=("pwntools", "keystone", "msfvenom"),
        artifacts=("shellcode validation report",),
        modules=("binary_exploit_primitives",),
    ),
    Capability(
        id="assembly-language",
        name="Assembly Language",
        domain="exploitation",
        maturity="partial",
        summary=(
            "Disassembly-aware triage of binaries, annotation of suspicious "
            "call sites, and detection of hand-written or obfuscated code "
            "sections inside binaries and shellcode payloads."
        ),
        modules=("binary_triage",),
        tools=("objdump", "radare2"),
        artifacts=("binary triage",),
    ),
    Capability(
        id="debugging",
        name="Debugging",
        domain="exploitation",
        maturity="partial",
        summary=(
            "Every nemesis finding ships the evidence needed to debug it: "
            "the exact request, the exact response, and the diff between "
            "them. The findings are a starting point for a debugger session."
        ),
        artifacts=("proof transcripts", "request/response evidence"),
        components=(
            "nemesis.verify.verifier:compare",
        ),
    ),
    Capability(
        id="fuzzing",
        name="Fuzzing",
        domain="offensive",
        maturity="partial",
        summary=(
            "Nemesis emits structured corpora, dictionaries and seed inputs "
            "from a scan - parameter values, discovered endpoints, error "
            "signatures - so that a fuzzer starts from the application's "
            "real shape rather than from nothing."
        ),
        artifacts=("fuzzing corpus", "payload dictionary", "seed endpoints"),
        modules=("fuzz_harness", "fuzzing_readiness",),
    ),
    Capability(
        id="patch-diffing",
        name="Patch Diffing",
        domain="offensive",
        maturity="partial",
        summary=(
            "Compares two revisions of a codebase and reports dangerous "
            "patterns that were newly introduced, and previously fixed "
            "issues that have come back. This is the regression question "
            "that review tools answer badly."
        ),
        modules=("patch_regression",),
        artifacts=("regression report",),
    ),
    Capability(
        id="root-cause-analysis",
        name="Root Cause Analysis",
        domain="offensive",
        maturity="partial",
        summary=(
            "Findings are grouped by CWE and by the file and function that "
            "produced them, so a hundred symptoms collapse into a handful "
            "of root causes instead of a hundred tickets."
        ),
        artifacts=("grouped root-cause summary",),
        components=(
            "nemesis.reporting.triage:TriageEngine",
        ),
        modules=("patch_regression",),
    ),
    Capability(
        id="side-channel-attacks",
        name="Side-Channel Attacks",
        domain="sidechannel",
        maturity="research",
        summary=(
            "Timing and cache behaviour of a target. nemesis measures "
            "response timing precisely enough to spot a statistically "
            "meaningful difference, which is the measurement half of the "
            "problem."
        ),
        modules=(),
        tools=("dudect", "ctgrind"),
        artifacts=("timing measurements",),
        prerequisites=(("a quiet target and many samples",)),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="hardware-exploitation",
        name="Hardware Exploitation",
        domain="sidechannel",
        maturity="research",
        summary=(
            "Firmware extraction, bus and glitch analysis. This needs "
            "physical access and lab equipment; nemesis supplies the "
            "firmware triage and the methodology."
        ),
        tools=("binwalk", "flashrom"),
        artifacts=("firmware triage",),
        prerequisites=("physical access", "lab equipment"),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    # -- Web application security ---------------------------------------
    Capability(
        id="business-logic-vulnerabilities",
        name="Business Logic Vulnerabilities",
        domain="web",
        maturity="partial",
        summary=(
            "Looks for the weaknesses that a payload scanner cannot see: client-controlled prices and quantities, missing state validation between steps, replayable one-time actions, missing CSRF protection, direct object references and open redirects."
        ),
        modules=(
            "business_logic", "price_tampering", "csrf_missing", "idor", "open_redirect",
        ),
        artifacts=("workflow analysis",),
    ),
    Capability(
        id="identity-and-session",
        name="Identity and Session Security",
        domain="web",
        maturity="partial",
        summary=(
            "Decodes the tokens an application actually issues and reports the "
            "ones an attacker could forge: unsigned JWTs, guessable HMAC keys, "
            "kid headers used as paths, tokens that never expire. Also submits "
            "account forms with the fields they do not offer - role, is_admin, "
            "verified, balance - to prove whether the server binds them."
        ),
        modules=(
            "jwt_weakness", "mass_assignment", "csrf_missing", "cookie_flags", "idor",
        ),
        artifacts=("token analysis", "privilege escalation proof"),
    ),
    Capability(
        id="sql-injection",
        name="SQL Injection",
        domain="web",
        maturity="native",
        summary=(
            "Differential probing of every discovered parameter against a "
            "length-matched baseline, with database error signatures "
            "matched across PostgreSQL, MySQL, SQLite, MSSQL and Oracle."
        ),
        modules=("sqli",),
        artifacts=("confirmed injection with proof",),
    ),
    Capability(
        id="cross-site-scripting",
        name="Cross-Site Scripting",
        domain="web",
        maturity="native",
        summary=(
            "Payloads are reflected and the reflection is analysed by "
            "context: HTML text, attribute, script, JSON string, XML and "
            "header. A payload only counts when it can actually break out "
            "of the context it landed in."
        ),
        modules=("xss",),
        artifacts=("confirmed reflection with context",),
    ),
    Capability(
        id="server-side-request-forgery",
        name="Server-Side Request Forgery",
        domain="web",
        maturity="native",
        summary=(
            "Probes URL-accepting parameters with controlled callbacks and "
            "compares the response against a baseline to prove the server "
            "made the request."
        ),
        modules=("ssrf",),
        artifacts=("confirmed SSRF with proof",),
    ),
    Capability(
        id="request-smuggling",
        name="Request Smuggling",
        domain="web",
        maturity="native",
        summary=(
            "Probes for CL.TE and TE.CL desynchronisation by sending "
            "conflicting framing headers and looking for the response to a "
            "spliced follow-up request to be answered out of order."
        ),
        modules=("request_smuggling", "http_method_probe",),
        artifacts=("smuggling proof",),
    ),
    Capability(
        id="deserialization-attacks",
        name="Deserialization Attacks",
        domain="web",
        maturity="native",
        summary=(
            "Detects unsafe deserialization in source and probes live "
            "endpoints for deserializer gadget behaviour, covering Java, "
            "PHP, Python, .NET and Ruby payloads."
        ),
        modules=("insecure_deserialization", "dangerous_patterns", "xml_external_entity",),
        artifacts=("gadget source evidence",),
    ),
    Capability(
        id="file-upload-vulnerabilities",
        name="File Upload Vulnerabilities",
        domain="web",
        maturity="native",
        summary=(
            "Probes upload endpoints for extension filtering bypass, "
            "content-type confusion, double extensions, path traversal in "
            "the filename, and polymorphic files that are served back "
            "executable."
        ),
        modules=("file_upload",),
        artifacts=("upload bypass proof",),
    ),
    Capability(
        id="web-cache-poisoning",
        name="Web Cache Poisoning",
        domain="web",
        maturity="native",
        summary=(
            "Identifies responses that are cached without a varying key, "
            "unkeyed headers that reach the cache, and cache poisoning "
            "primitives where a poisoned response is served to other users."
        ),
        modules=("web_cache_poisoning",),
        artifacts=("cache poisoning proof",),
    ),
    Capability(
        id="websockets-security",
        name="WebSockets Security",
        domain="web",
        maturity="native",
        summary=(
            "Checks the upgrade handshake for origin validation, missing "
            "authentication and missing subprotocol negotiation, then tests "
            "for message reflection and cross-site WebSocket hijacking."
        ),
        modules=("websocket_security",),
        artifacts=("handshake analysis",),
    ),
    Capability(
        id="browser-security",
        name="Browser Security",
        domain="web",
        maturity="native",
        summary=(
            "Audits the browser-facing security posture as a set: CSP, "
            "HSTS, frame protection, cross-origin isolation, permissions "
            "policy, cookie flags and mixed content."
        ),
        modules=(
            "headers_security",
            "csp_analyzer",
            "cookie_flags",
            "mixed_content",
            "browser_security",
            "clickjacking",
            "cors_misconfig",
            "csrf_missing",
            "open_redirect",
        ),
        artifacts=("browser security report",),
    ),
    Capability(
        id="content-security-policy",
        name="Content Security Policy",
        domain="web",
        maturity="native",
        summary=(
            "Parses the policy, resolves its directives, and reports the "
            "gaps that matter: unsafe-inline, unsafe-eval, wildcards, "
            "data: in script-src, missing object-src, and reporting holes."
        ),
        modules=("csp_analyzer",),
        artifacts=("parsed policy with gaps",),
    ),
    Capability(
        id="source-code-auditing",
        name="Source Code Auditing",
        domain="offensive",
        maturity="native",
        summary=(
            "Static analysis of a checkout: secrets, dangerous APIs, "
            "injection sinks, weak cryptography, unsafe deserialization, "
            "and logic defects that no linter reports."
        ),
        modules=(
            "secrets",
            "dangerous_patterns",
            "crypto_misuse",
            "logic_bugs",
            "command_injection",
            "info_disclosure",
            "nosql_injection",
            "path_traversal",
            "template_injection",
            "xml_external_entity",
        ),
        artifacts=("file and line level findings",),
    ),
    Capability(
        id="secure-code-review",
        name="Secure Code Review",
        domain="offensive",
        maturity="partial",
        summary=(
            "A review aid rather than a reviewer: the findings carry CWE "
            "identifiers, CWE mappings, a concrete remediation and the "
            "exact source line, and can be diffed between revisions to "
            "show what a change actually introduced."
        ),
        modules=("patch_regression", "logic_bugs", "template_injection", "path_traversal",),
        artifacts=("review-ready findings", "regression diff"),
    ),
    # -- Network, wireless and radio -------------------------------------
    Capability(
        id="wifi-security",
        name="Wi-Fi Security",
        domain="network",
        maturity="research",
        summary=(
            "Association and encryption analysis of wireless networks. This "
            "needs a monitor-mode capable adapter and a specific test "
            "environment; nemesis provides the methodology and the "
            "downstream credential analysis."
        ),
        tools=("aircrack-ng", "wifite", "bettercap"),
        artifacts=("methodology",),
        prerequisites=("monitor mode hardware", "authorised test range"),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="bluetooth-security",
        name="Bluetooth Security",
        domain="network",
        maturity="research",
        summary=(
            "BLE pairing, GATT and protocol analysis. Requires Bluetooth "
            "hardware and a protocol analyser."
        ),
        tools=("bluetoothctl", "btlejuice"),
        prerequisites=("a Bluetooth adapter", "a protocol analyser"),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="vpn-security",
        name="VPN Security",
        domain="network",
        maturity="partial",
        summary=(
            "Tests a VPN gateway reachable over the network: TLS posture, "
            "IKE and SSL VPN exposure, authentication behaviour and "
            "information disclosure in the handshake."
        ),
        modules=("tls_configuration", "headers_security",),
        artifacts=("gateway posture report",),
    ),
    Capability(
        id="firewall-evasion-research",
        name="Firewall Evasion Research",
        domain="network",
        maturity="partial",
        summary=(
            "Measures where a middlebox changes the request: the scanner's "
            "own traffic is the probe, and the difference between what was "
            "sent and what arrived is the fingerprint of an inspecting "
            "device."
        ),
        artifacts=("request/response transaction log",),
        components=("nemesis.modules.web.proxy:ProxyTrustModule",),
    ),
    Capability(
        id="ids-ips",
        name="IDS/IPS",
        domain="network",
        maturity="partial",
        summary=(
            "Detects inline inspection by measuring whether a payload "
            "changes the shape or timing of the response, and produces the "
            "normalised request corpus used to tune detection rules."
        ),
        artifacts=("bypass observations", "Sigma rules"),
        components=("nemesis.reporting.sigma:SigmaRuleBuilder",),
    ),
    Capability(
        id="network-traffic-analysis",
        name="Network Traffic Analysis",
        domain="network",
        maturity="native",
        summary=(
            "nemesis records every request and response it makes, which is "
            "enough to build a protocol map, a host inventory, and the "
            "transaction log a traffic review needs."
        ),
        artifacts=("transaction log", "host and endpoint inventory"),
        modules=("pcap_analysis",),
    ),
    Capability(
        id="ipv6-security",
        name="IPv6 Security",
        domain="network",
        maturity="partial",
        summary=(
            "Scope rules, SSRF probes and host resolution are IPv6-aware, "
            "including bracket notation and compressed addresses, and "
            "IPv4-mapped addresses are treated as the IPv4 host they are."
        ),
        modules=("ssrf", "ipv6_security",),
        artifacts=("host inventory",),
    ),
    Capability(
        id="proxy-security",
        name="Proxy Security",
        domain="network",
        maturity="partial",
        summary=(
            "Detects open forward proxies and header-based routing through "
            "the X-Forwarded-For and Host families, which are also the "
            "usual source of host-header and cache-poisoning bugs."
        ),
        modules=("host_header_injection", "web_cache_poisoning", "proxy_security",),
        artifacts=("header routing findings",),
    ),
    Capability(
        id="infrastructure-misconfigurations",
        name="Infrastructure Misconfigurations",
        domain="network",
        maturity="native",
        summary=(
            "Cloud and platform configuration: infrastructure as code, "
            "container and orchestration settings, security headers, DNS "
            "records, TLS posture and exposed storage."
        ),
        modules=(
            "iac_misconfiguration",
            "headers_security",
            "dns_posture",
            "tls_configuration",
            "exposed_files",
            "directory_listing",
            "graphql_introspection",
            "info_disclosure",
        ),
        artifacts=("misconfiguration report",),
    ),
    Capability(
        id="sdr-radio-security",
        name="SDR and Radio Security",
        domain="network",
        maturity="research",
        summary=(
            "Software-defined radio analysis of proprietary and legacy "
            "radio protocols. Requires SDR hardware."
        ),
        tools=("GNU Radio", "rtl_sdr", "inspectrum"),
        prerequisites=(("SDR hardware",)),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="rfid-nfc-security",
        name="RFID and NFC Security",
        domain="network",
        maturity="research",
        summary=(
            "Tag and card protocol analysis, including cloning assessment "
            "and access control review. Needs an NFC reader."
        ),
        tools=(("proxmark3",)),
        prerequisites=(("an NFC reader",)),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    # -- Firmware, hardware and physical --------------------------------
    Capability(
        id="uefi-bios-security",
        name="UEFI and BIOS Security",
        domain="internals",
        maturity="research",
        summary=(
            "Firmware extraction and version fingerprinting, checks for "
            "known vulnerable firmware builds, and an assessment of the "
            "firmware update mechanism itself."
        ),
        tools=("binwalk", "flashrom"),
        artifacts=("firmware triage",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="secure-boot-research",
        name="Secure Boot Research",
        domain="internals",
        maturity="research",
        summary=(
            "Analyses the Secure Boot chain: enrolled keys, the shim, and "
            "whether the platform actually enforces verification."
        ),
        tools=("sbverify", "efibootmgr"),
        artifacts=("firmware triage",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="chip-hardware-security",
        name="Chip and Hardware Security",
        domain="sidechannel",
        maturity="research",
        summary=(
            "Silicon-level attacks: fault injection, side channels, and "
            "glitching. This is a hardware laboratory discipline; nemesis "
            "contributes the measurement and reporting discipline."
        ),
        tools=("fault injection rigs",),
        prerequisites=(("hardware lab",)),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="jtag-uart",
        name="JTAG and UART",
        domain="internals",
        maturity="research",
        summary=(
            "Debug-port enumeration and UART baud-rate discovery produce a "
            "reproducible bring-up procedure for a device, and the "
            "firmware image recovered that way is then triaged."
        ),
        tools=("openocd", "minicom", "binwalk"),
        artifacts=("bring-up procedure", "firmware triage"),
        prerequisites=("physical access", "a debug adapter"),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="side-channel-analysis",
        name="Side-Channel Analysis",
        domain="sidechannel",
        maturity="research",
        summary=(
            "Statistical analysis of timing and power traces to recover "
            "secrets. nemesis contributes precise timing measurement and "
            "the correlation pipeline."
        ),
        tools=("dudect", "tracesampler"),
        prerequisites=(("sampling hardware",)),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    # -- Cloud, DevSecOps and supply chain ------------------------------
    Capability(
        id="ci-cd-pipeline-security",
        name="CI/CD Pipeline Security",
        domain="cloud",
        maturity="native",
        summary=(
            "Audits pipeline definitions for the classic self-hosted "
            "runner and script-injection weaknesses: pull_request_target "
            "with a checkout of untrusted code, secrets exposed to forked "
            "builds, unpinned third-party actions, and command injection "
            "through workflow inputs."
        ),
        modules=("cicd_pipeline_security",),
        artifacts=("pipeline findings",),
    ),
    Capability(
        id="supply-chain-security",
        name="Supply Chain Security",
        domain="cloud",
        maturity="native",
        summary=(
            "Declared dependencies resolved against OSV.dev, manifest and "
            "lockfile parsing across seven ecosystems, licence risk, "
            "dependency-confusion and typosquatting analysis, and pipeline "
            "audit."
        ),
        modules=(
            "dependency_vulnerabilities",
            "license_risk",
            "dependency_confusion",
            "typosquatting",
            "cicd_pipeline_security",
            "patch_regression",
            "tech_outdated",
        ),
        artifacts=("advisory report", "confusion report"),
    ),
    Capability(
        id="infrastructure-as-code-security",
        name="Infrastructure as Code Security",
        domain="cloud",
        maturity="native",
        summary=(
            "Scans Terraform, Kubernetes manifests, Dockerfiles and "
            "CloudFormation for the misconfigurations that matter: public "
            "buckets, wide-open security groups, privileged containers, "
            "host networking, and hardcoded credentials."
        ),
        modules=("iac_misconfiguration",),
        artifacts=("misconfiguration findings with resource paths",),
    ),
    Capability(
        id="secrets-management",
        name="Secrets Management",
        domain="cloud",
        maturity="native",
        summary=(
            "Detects credentials committed to a repository or embedded in a "
            "binary, with provider-specific patterns and a high-entropy "
            "heuristic, while skipping test fixtures and vendor directories."
        ),
        modules=("secrets", "binary_triage", "git_history_secrets",),
        artifacts=("secret findings with fingerprints",),
    ),
    Capability(
        id="cloud-pentesting",
        name="Cloud Pentesting",
        domain="cloud",
        maturity="partial",
        summary=(
            "Audits the configuration that decides whether a cloud "
            "deployment is exposed, and checks the reachable surface: "
            "storage endpoints, metadata services, and management APIs "
            "leaking through the application."
        ),
        modules=("iac_misconfiguration", "exposed_files", "ssrf", "cloud_attack_surface",),
        artifacts=("cloud exposure report",),
    ),
    Capability(
        id="cloud-forensics",
        name="Cloud Forensics",
        domain="cloud",
        maturity="partial",
        summary=(
            "Evidence handling for cloud incidents: content hashing, chain of custody records, a triage worklist ranked by impact and evidence, and timelines assembled from the scan transaction log and the artefacts recovered from a seized instance."
        ),
        artifacts=("evidence manifest", "chain of custody", "timeline"),
        components=("nemesis.reporting.triage:TriageEngine",),
        modules=("memory_forensics", "memory_dump_triage",),
    ),
    Capability(
        id="devsecops",
        name="DevSecOps",
        domain="cloud",
        maturity="partial",
        summary=(
            "The integration story: findings emitted as SARIF for code "
            "scanning, machine-readable JSON for dashboards, detection "
            "rules for the pipeline, and a policy gate that fails the "
            "build on a regression."
        ),
        artifacts=("SARIF", "JSON", "Sigma rules", "YARA rules"),
        components=(
            "nemesis.reporting.sarif:write_sarif",
            "nemesis.modules.supplychain.cicd:CicdPipelineSecurityModule",
        ),
    ),
    Capability(
        id="software-composition-analysis",
        name="Software Composition Analysis",
        domain="cloud",
        maturity="native",
        summary=(
            "Manifests and lockfiles for PyPI, npm, crates.io, Go, Maven, "
            "RubyGems and Packagist, resolved against OSV.dev, with CVSS "
            "vectors scored locally and advisories grouped per package so "
            "one finding describes one problem."
        ),
        modules=("dependency_vulnerabilities",),
        artifacts=("advisory report with fix versions",),
    ),
    Capability(
        id="dependency-confusion-research",
        name="Dependency Confusion Research",
        domain="cloud",
        maturity="native",
        summary=(
            "Detects names that exist on a public registry but are declared "
            "from a private scope, and reports the public package that "
            "could be shadowed."
        ),
        modules=("dependency_confusion",),
        artifacts=("confusion findings with the public package named",),
    ),
    # -- Detection, response and forensics -------------------------------
    Capability(
        id="yara-rules",
        name="YARA Rules",
        domain="detection",
        maturity="native",
        summary=(
            "Generates YARA rules from confirmed findings and from extracted "
            "indicators, with the strings, conditions and metadata a "
            "detection engineer expects, ready to drop into a ruleset."
        ),
        components=("nemesis.reporting.yara:YaraRuleBuilder",),
        artifacts=("YARA rules",),
    ),
    Capability(
        id="sigma-rules",
        name="Sigma Rules",
        domain="detection",
        maturity="native",
        summary=(
            "Generates Sigma rules from findings and from the technique "
            "each finding maps to, in the standard taxonomy so they load "
            "into a SIEM."
        ),
        components=("nemesis.reporting.sigma:SigmaRuleBuilder",),
        artifacts=("Sigma rules",),
    ),
    Capability(
        id="memory-forensics",
        name="Memory Forensics",
        domain="detection",
        maturity="partial",
        summary=(
            "Parses memory images and crash dumps directly, with no external tool: the process inventory, the command lines, the network connection table, the persistence keys, the regions that exist in memory but not on disk, and the secrets that were resident in a process when it was seized."
        ),
        artifacts=("indicator set", "payload corpus"),
        components=("nemesis.modules.infra.pcap:PcapAnalysisModule",),
        modules=("memory_forensics", "memory_dump_triage",),
    ),
    Capability(
        id="incident-response",
        name="Incident Response",
        domain="detection",
        maturity="partial",
        summary=(
            "Structured playbooks for triage, containment, eradication and "
            "recovery, each with the commands, the evidence to capture and "
            "the decision points."
        ),
        artifacts=("playbooks", "evidence manifest"),
        components=(
            "nemesis.reporting.triage:TriageEngine",
        ),
    ),
    Capability(
        id="threat-hunting",
        name="Threat Hunting",
        domain="detection",
        maturity="partial",
        summary=(
            "Hunt hypotheses expressed as Sigma rules, with the log sources "
            "each one needs, so a hypothesis becomes a query rather than a "
            "paragraph."
        ),
        components=("nemesis.reporting.sigma:SigmaRuleBuilder",),
        artifacts=("Sigma rules", "hunt hypotheses"),
    ),
    Capability(
        id="detection-engineering",
        name="Detection Engineering",
        domain="detection",
        maturity="native",
        summary=(
            "Turns findings and techniques into deployable detection "
            "content in the two formats defenders actually use, with "
            "coverage gaps reported explicitly."
        ),
        components=("nemesis.reporting.sigma:SigmaRuleBuilder", "nemesis.reporting.yara:YaraRuleBuilder",),
        artifacts=("Sigma rules", "YARA rules", "coverage map"),
    ),
    Capability(
        id="edr-xdr-research",
        name="EDR and XDR Research",
        domain="detection",
        maturity="partial",
        summary=(
            "Tests how endpoint and network sensors respond to a live "
            "attack, by measuring whether the payload the scanner sent "
            "produced a behavioural change the sensor would have caught."
        ),
        artifacts=("bypass observations",),
        components=("nemesis.reporting.sigma:SigmaRuleBuilder",),
    ),
    Capability(
        id="anti-malware-research",
        name="Anti-Malware Research",
        domain="detection",
        maturity="partial",
        summary=(
            "Extracts indicators from samples and malware-adjacent "
            "artefacts and emits them as detection rules, with the "
            "extraction reproducible from the recorded evidence."
        ),
        artifacts=("YARA rules", "indicator list"),
        components=("nemesis.reporting.yara:YaraRuleBuilder",),
    ),
    Capability(
        id="ransomware-analysis",
        name="Ransomware Analysis",
        domain="detection",
        maturity="partial",
        summary=(
            "Ransom-note and IOC extraction, plus detection content for the "
            "encryption and shadow-copy-deletion behaviours that precede "
            "the note."
        ),
        artifacts=("IOC list", "YARA rules"),
        components=("nemesis.reporting.yara:YaraRuleBuilder",),
    ),
    Capability(
        id="digital-forensics",
        name="Digital Forensics",
        domain="detection",
        maturity="partial",
        summary=(
            "Evidence acquisition with hash verification and a chain of custody record, plus direct analysis of the two artefact types that carry the most truth: memory images and packet captures."
        ),
        artifacts=("evidence manifest", "chain of custody", "timeline"),
        components=("nemesis.modules.infra.pcap:PcapAnalysisModule",),
        modules=("memory_forensics", "memory_dump_triage",),
    ),
    Capability(
        id="software-supply-chain-security",
        name="Software Supply Chain Security",
        domain="cloud",
        maturity="native",
        summary=(
            "The build pipeline, the dependency graph and the licence "
            "obligations in one view: advisory exposure, confusion and "
            "typosquat risk, pipeline weakness, and copyleft obligations."
        ),
        modules=(
            "dependency_vulnerabilities",
            "dependency_confusion",
            "typosquatting",
            "cicd_pipeline_security",
            "license_risk",
            "tech_outdated",
        ),
        artifacts=("supply chain report",),
    ),
    # -- AI, ML and LLM --------------------------------------------------
    Capability(
        id="ai-security",
        name="AI Security",
        domain="ai",
        maturity="partial",
        summary=(
            "The general posture: model files scanned for unsafe "
            "serialisation, inference endpoints found, model APIs "
            "discovered, and agent tool surfaces assessed."
        ),
        modules=("ml_model_security", "llm_endpoint_detection", "agent_tool_security",),
        artifacts=("AI exposure report",),
    ),
    Capability(
        id="llm-security",
        name="LLM Security",
        domain="ai",
        maturity="native",
        summary=(
            "Detects LLM endpoints, tests for prompt injection by "
            "reflection, checks whether the system prompt leaks, and "
            "examines the safety controls a model exposes."
        ),
        modules=("llm_endpoint_detection", "prompt_injection", "model_extraction", "agent_tool_security",),
        artifacts=("LLM findings with prompt evidence",),
    ),
    Capability(
        id="machine-learning-security",
        name="Machine Learning Security",
        domain="ai",
        maturity="partial",
        summary=(
            "Static analysis of model artefacts: unsafe deserialisation in "
            "model loaders, untrusted model downloads, and missing "
            "integrity checks on model files."
        ),
        modules=("ml_model_security", "dangerous_patterns",),
        artifacts=("model security findings",),
    ),
    Capability(
        id="adversarial-machine-learning",
        name="Adversarial Machine Learning",
        domain="ai",
        maturity="research",
        summary=(
            "Crafting inputs that flip model decisions, and evasion "
            "attacks that hide malicious content from a classifier. This is "
            "a research programme; nemesis contributes the harness and the "
            "measurement discipline."
        ),
        modules=("ml_model_security",),
        tools=("adversarial-robustness-toolbox", "cleverhans"),
        artifacts=("adversarial sample corpus",),
        prerequisites=("a target model", "a training set"),
    ),
    Capability(
        id="model-extraction-privacy",
        name="Model Extraction and Privacy Research",
        domain="ai",
        maturity="partial",
        summary=(
            "Detects the signals of model extraction - unusual query "
            "volume against a model API, verbose responses to systematic "
            "probing, and membership inference shapes - and reports the "
            "privacy-relevant exposures in the surrounding application."
        ),
        modules=("model_extraction",),
        artifacts=("extraction indicators",),
    ),
    # -- Blockchain -------------------------------------------------------
    Capability(
        id="blockchain-security",
        name="Blockchain Security",
        domain="blockchain",
        maturity="partial",
        summary=(
            "Smart contract source analysis with the classic bug classes, "
            "and configuration review of deployment and signing material."
        ),
        modules=("solidity_audit", "secrets", "defi_security",),
        artifacts=("contract findings with line numbers",),
    ),
    Capability(
        id="smart-contract-auditing",
        name="Smart Contract Auditing",
        domain="blockchain",
        maturity="partial",
        summary=(
            "Solidity static analysis for reentrancy, unchecked external "
            "calls, tx.origin authorisation, weak randomness, delegatecall "
            "to untrusted targets, and missing access control."
        ),
        modules=("solidity_audit",),
        artifacts=("findings with contract, function and line",),
    ),
    Capability(
        id="defi-security",
        name="DeFi Security",
        domain="blockchain",
        maturity="partial",
        summary=(
            "Applies the contract analysis to the economic patterns that "
            "matter in finance: price and slippage assumptions, oracle "
            "trust, and liquidation thresholds."
        ),
        modules=("solidity_audit", "business_logic", "defi_security",),
        artifacts=("DeFi risk findings",),
    ),
    # -- Evidence, scoring and disclosure --------------------------------
    Capability(
        id="digital-evidence-analysis",
        name="Digital Evidence Analysis",
        domain="detection",
        maturity="partial",
        summary=(
            "Content hashing, chain of custody and a merged timeline built from every artefact a scan produced - memory images, packet captures and the scan transaction log - so a report can be defended as evidence rather than as opinion."
        ),
        artifacts=("evidence manifest", "chain of custody", "timeline"),
        components=("nemesis.modules.infra.pcap:PcapAnalysisModule",),
        modules=("memory_forensics", "memory_dump_triage",),
    ),
    Capability(
        id="incident-handling",
        name="Incident Handling",
        domain="detection",
        maturity="partial",
        summary=(
            "The operational loop: detect, triage, contain, eradicate, "
            "recover, and learn, as a playbook with explicit exit criteria "
            "at each stage."
        ),
        artifacts=("playbooks", "post-incident report"),
        components=(
            "nemesis.reporting.triage:TriageEngine",
        ),
    ),
    Capability(
        id="cvss-scoring",
        name="CVSS Scoring",
        domain="reporting",
        maturity="native",
        summary=(
            "A full CVSS v3.1 implementation - base score, severity band "
            "and vector - plus a builder that derives a defensible vector "
            "from a finding's own severity, capability and evidence."
        ),
        components=("nemesis.knowledge.cvss:CvssVector",),
        artifacts=("CVSS vectors", "base scores"),
    ),
    Capability(
        id="responsible-disclosure",
        name="Responsible Disclosure",
        domain="reporting",
        maturity="native",
        summary=(
            "The disclosure workflow: a coordinated timeline, a policy "
            "template, and reports written for the three platforms that "
            "matter, with the disclosure etiquette attached."
        ),
        components=("nemesis.reporting.disclosure:DisclosureReportBuilder",),
        artifacts=("disclosure reports", "coordination timeline"),
    ),
    Capability(
        id="security-report-writing",
        name="Security Report Writing",
        domain="reporting",
        maturity="native",
        summary=(
            "Reports written from evidence rather than from memory: "
            "severity and confidence separated, the request and response "
            "quoted, the impact stated in the asset's own terms, and a "
            "remediation that names the change."
        ),
        components=(
            "nemesis.reporting.markdown:write_markdown",
            "nemesis.reporting.html:write_html",
            "nemesis.reporting.disclosure:DisclosureReportBuilder",
        ),
        artifacts=("Markdown report", "HTML report", "disclosure reports"),
    ),
    Capability(
        id="hackerone-reports",
        name="HackerOne Reports",
        domain="reporting",
        maturity="native",
        summary=(
            "Reports in the structure HackerOne triages: title, severity "
            "and weakness, the asset, reproduction steps, the impact, and "
            "a remediation."
        ),
        components=("nemesis.reporting.disclosure:DisclosureReportBuilder",),
        artifacts=("HackerOne report",),
    ),
    Capability(
        id="bugcrowd-reports",
        name="Bugcrowd Reports",
        domain="reporting",
        maturity="native",
        summary=(
            "Reports in the structure Bugcrowd triages, including the "
            "Vulnerability Rating matrix against asset criticality."
        ),
        components=("nemesis.reporting.disclosure:DisclosureReportBuilder",),
        artifacts=("Bugcrowd report",),
    ),
    Capability(
        id="intigriti-reports",
        name="Intigriti Reports",
        domain="reporting",
        maturity="native",
        summary=(
            "Reports in the structure Intigriti triages, with severity "
            "justified against the asset's criticality."
        ),
        components=("nemesis.reporting.disclosure:DisclosureReportBuilder",),
        artifacts=("Intigriti report",),
    ),
    Capability(
        id="public-vulnerability-writeups",
        name="Public Vulnerability Write-ups",
        domain="reporting",
        maturity="native",
        summary=(
            "A publishable write-up generated from the evidence: the "
            "story, the reproduction, the impact, the fix, and the "
            "detection content a reader can deploy."
        ),
        components=("nemesis.reporting.writeup:WriteupBuilder",),
        artifacts=("Markdown write-up", "YARA rules", "Sigma rules"),
    ),
    # -- Learning and knowledge -------------------------------------------
    Capability(
        id="tryhackme",
        name="TryHackMe",
        domain="learning",
        maturity="integration",
        summary=(
            "A curated pointer to the rooms that match what nemesis has "
            "just taught you, so a finding leads straight to practice."
        ),
        artifacts=("curated learning paths",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="portswigger-web-security-academy",
        name="PortSwigger Web Security Academy",
        domain="learning",
        maturity="integration",
        summary=(
            "A curated pointer from each web module to the corresponding "
            "academy topic, because the module and the topic are the same "
            "material taught in two places."
        ),
        modules=(
            "sqli", "xss", "ssrf", "request_smuggling", "file_upload",
            "web_cache_poisoning", "websocket_security", "csp_analyzer",
        ),
        artifacts=("curated learning paths",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="research-papers",
        name="Research Papers",
        domain="learning",
        maturity="integration",
        summary=(
            "An index of the papers that matter for the techniques nemesis "
            "emits, with the finding each technique came from."
        ),
        artifacts=("paper index",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="technical-whitepapers",
        name="Technical Whitepapers",
        domain="learning",
        maturity="integration",
        summary=(
            "An index of vendor and standards documents - CVSS, OWASP, "
            "RFCs - that the methodology is built on."
        ),
        artifacts=("standards index",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="security-books",
        name="Security Books",
        domain="learning",
        maturity="integration",
        summary=(
            "A reading list organised by the area it serves, so a book "
            "recommendation is tied to something the user is actually "
            "trying to do."
        ),
        artifacts=("reading list",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="hacking-courses",
        name="Hacking Courses",
        domain="learning",
        maturity="integration",
        summary=(
            "A course index from beginner to exploit development, with the "
            "prerequisite chain made explicit."
        ),
        artifacts=("course index",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="open-source-security-tools",
        name="Open-Source Security Tools",
        domain="learning",
        maturity="integration",
        summary=(
            "The tools that cover what nemesis deliberately does not, "
            "mapped to the capability each one serves so the handover is "
            "explicit rather than a list of names."
        ),
        artifacts=("tool index",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="security-tool-development",
        name="Security Tool Development",
        domain="learning",
        maturity="native",
        summary=(
            "The plugin API is the answer: a module is one class, a "
            "finding is one object, and the registry does discovery, "
            "filtering, concurrency and timeouts for you."
        ),
        components=("nemesis.modules.base:Module", "nemesis.knowledge.library:LIBRARY_INDEX",),
        artifacts=("plugin API", "example plugin"),
    ),
    Capability(
        id="python-for-hackers",
        name="Python for Hackers",
        domain="learning",
        maturity="integration",
        summary=(
            "The language nemesis is written in, with the security-relevant "
            "standard library - sockets, ssl, subprocess, pickle, hashlib - "
            "and the sharp edges in each."
        ),
        artifacts=("reference notes",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="c-cpp-for-exploit-development",
        name="C and C++ for Exploit Development",
        domain="learning",
        maturity="integration",
        summary=(
            "The languages exploits are written in, with the memory model "
            "and the standard library functions that make them exploitable."
        ),
        artifacts=("reference notes",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="assembly-for-hackers",
        name="Assembly for Hackers",
        domain="learning",
        maturity="integration",
        summary=(
            "Instruction-level reference for the architectures the triage "
            "output describes, connected to the binary triage results."
        ),
        modules=("binary_triage",),
        artifacts=("reference notes",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="go-for-security-tools",
        name="Go for Security Tools",
        domain="learning",
        maturity="integration",
        summary=(
            "The language to write concurrent scanners in, with the "
            "net/http and crypto packages that matter."
        ),
        artifacts=("reference notes",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="rust-for-security",
        name="Rust for Security",
        domain="learning",
        maturity="integration",
        summary=(
            "Memory safety as a default, and what that changes about how a "
            "security tool is written and audited."
        ),
        artifacts=("reference notes",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="bash-and-powershell",
        name="Bash and PowerShell",
        domain="learning",
        maturity="integration",
        summary=(
            "The two shells every incident responder ends up in, with the "
            "parsing quirks that turn a command into an execution."
        ),
        artifacts=("reference notes",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    # -- Practice and personal --------------------------------------------
    Capability(
        id="github-security-projects",
        name="GitHub Security Projects",
        domain="meta",
        maturity="integration",
        summary=(
            "A running index of the security projects you maintain, with "
            "their open findings, their release state and their coverage."
        ),
        artifacts=("project index",),
        components=("nemesis.knowledge.library:LIBRARY_INDEX",),
    ),
    Capability(
        id="personal-lab-notes",
        name="Personal Lab Notes",
        domain="meta",
        maturity="partial",
        summary=(
            "A structured note format for lab work - hypothesis, setup, "
            "observations, dead ends - stored beside the evidence it "
            "refers to."
        ),
        artifacts=("lab note templates",),
        components=("nemesis.workspace:Workspace",),
    ),
    Capability(
        id="unsolved-vulnerabilities",
        name="Unsolved Vulnerabilities",
        domain="meta",
        maturity="partial",
        summary=(
            "A tracker for the things you have not solved yet, with the "
            "evidence gathered so far and the next step written down while "
            "it is still fresh."
        ),
        artifacts=("open research tracker",),
        components=("nemesis.workspace:Workspace",),
    ),
    Capability(
        id="original-research",
        name="Original Research",
        domain="meta",
        maturity="partial",
        summary=(
            "The infrastructure to publish: reproducible corpora, generated "
            "detection content, and write-ups that separate what you found "
            "from what you believe."
        ),
        artifacts=("reproducible corpora", "detection content", "write-ups"),
        components=("nemesis.workspace:Workspace",),
    ),
    Capability(
        id="security-portfolio",
        name="Security Portfolio",
        domain="meta",
        maturity="partial",
        summary=(
            "The evidence of competence assembled from everything above: "
            "findings with proof, published research, and detection "
            "content that works."
        ),
        artifacts=("portfolio summary",),
        components=("nemesis.workspace:Workspace",),
    ),
)

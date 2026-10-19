# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

**Scan speed**
- The **request-smuggling probe waited out the full client timeout**
  (15 s) for every candidate, because a smuggling probe is deliberately
  malformed and a timeout is the expected outcome rather than an
  error. It now uses a 3 s probe timeout, which cut a 125-second scan
  to 53 seconds and the test suite from 133 seconds to 61.
- The **test fixture app was single-threaded**, so one deliberately
  desynchronised connection blocked every later request. It is now
  threaded, and it no longer prints a broken-pipe traceback when a
  scanner closes a connection it does not need.

**Bugs found by writing the tests for the second wave**
- The **Content-Security-Policy parser never split directives on
  semicolons**, so every policy was parsed as a single directive with
  every other directive's name as a source. `default-src 'none';
  script-src 'self'` parsed as one `default-src` directive. Every CSP
  check that asked "is this directive present" was therefore always
  wrong, in both directions.
- The **pcap parser crashed on every capture file**: it unpacked a
  24-byte format from a 20-byte slice, so the global header could
  never be read.
- The **pcap DNS-exfiltration check applied a bytes pattern to a
  string** and raised on the first DNS query it saw.
- The **pcap Basic-authentication check base64-decoded the value with
  the `Basic ` scheme still attached**, so it reported garbage instead
  of the credential it had actually found.
- The **DeFi module inherited a `_finding` with a different argument
  order** from the Solidity module and raised `TypeError` on its first
  finding, so it had never produced output at all.
- The **fuzz-harness module generated harness source but never wrote
  it**, so the harness only existed inside a report.
- The **git-history secret scan skipped `config.py` and `settings.yml`**,
  because the file filter only recognised a fixed list of extensions.
- The **IPv6 module compared an address payload against a neutralised
  string** rather than against the address it was equivalent to, so the
  comparison was between two rejections and proved nothing.
- The **`side-channel-attacks` capability claimed `sqli` as its
  backing module**, and fifteen modules shipped without any capability
  claiming them.

### Added

**The capability map**
- `nemesis/capabilities/` — a registry of **102 capability areas** (kernel
  exploitation, side-channel analysis, smart contract auditing, incident
  response, security portfolio, and the rest) each carrying an honest
  maturity label: `native`, `partial`, `integration`, `research`, `manual`.
- The registry is **validated against the real module registry**: a
  capability that names a module or a component which does not exist is a
  test failure. All 102 are backed by shipped code or a shipped component
  today (32 native, 40 partial, 14 integration, 16 research), and no
  module may ship without a capability that claims it.
- `nemesis capabilities`, `nemesis capability <id>` — the map, on the CLI.

**New modules — 32 added, 64 total**
- *Request-level*: `request_smuggling` (CL.TE / TE.CL), `file_upload`,
  `web_cache_poisoning`, `websocket_security`, `csp_analyzer` (with a real
  CSP parser), `business_logic` (price / quantity / role / state tampering).
- *Code*: `privilege_escalation`, `iac_misconfiguration` (Terraform,
  Kubernetes, Dockerfile, CloudFormation), `binary_triage` and
  `binary_exploit_primitives` (a real ELF / PE / Mach-O parser),
  `patch_regression` (git-diff based).
- *Supply chain*: `dependency_confusion`, `typosquatting`,
  `cicd_pipeline_security` (`pull_request_target` with untrusted checkout,
  unpinned actions, expression injection into `run:` blocks, privileged
  containers).
- *AI*: `llm_endpoint_detection`, `prompt_injection`, `model_extraction`,
  `agent_tool_security`, `ml_model_security`.
- *Blockchain*: `solidity_audit` (reentrancy, access control, `tx.origin`,
  unchecked return values, unprotected initialisers).

**Second wave — 12 more modules, and the last of the 102 areas**
- *Forensics*: `pcap_analysis` (a dependency-free pcap/pcapng parser:
  cleartext credentials, DNS exfiltration, plaintext protocols, bulk flows)
  and `memory_forensics` + `memory_dump_triage` (process inventory, command
  lines, the connection table, persistence keys, injected regions and
  resident secrets, read from both narrow and UTF-16LE strings).
- *Code*: `git_history_secrets` (credentials that survive in the history
  after being removed from `HEAD`), `sandbox_escape` (container escape
  configuration), `fuzz_harness` (libFuzzer harness generation, written
  to disk) and `fuzzing_readiness`.
- *Web*: `proxy_security` (trusted-proxy lists, host poisoning, hop-by-hop
  headers), `ipv6_security` (IPv4-mapped, long-form and zone-id
  confusion) and `browser_security` (CSP depth, HSTS, `__Host-` cookie
  prefixes, cross-origin isolation).
- *Cloud and blockchain*: `cloud_attack_surface` (IMDS, storage hosts,
  pre-signed URL lifetime) and `defi_security` (unchecked transfers,
  slippage, oracle staleness, AMM pricing, token callbacks, missing
  events).

**The knowledge layer**
- `nemesis/knowledge/library.py` — 136 curated resources (papers, books,
  courses, labs, standards, tools) mapped to the capability areas they
  serve, with the reason each one is worth your time.
- `nemesis/workspace.py` — a research workspace on disk: lab notes,
  unsolved vulnerabilities, original research and a portfolio, each with a
  structure that makes it useful six months later.
- `nemesis knowledge`, `nemesis lab` — the two, on the CLI.

**The action layer**
- `nemesis triage` — ranks findings on three independent axes (impact,
  evidence quality, effort) and collapses duplicates into root causes, so
  the output is a worklist rather than a severity list.
- `nemesis yara` / `nemesis sigma` — generate detection rules from what was
  actually observed, and refuse to emit rules that would be too noisy to
  maintain. The skipped rules are listed with the reason.
- `nemesis report` — HackerOne, Bugcrowd and Intigriti disclosure reports
  in each programme's own shape.
- `nemesis writeup` — a public write-up draft that states the limits of the
  review rather than claiming completeness.
- `nemesis cvss` — CVSS v3.1 scoring with each metric explained.

**Fixes**
- `Finding.file` and `Finding.line` were never populated: the keyword
  arguments leaked into `Evidence.extra` instead, so code findings
  fingerprinted without their location. Both are now set on the finding.
- `binary_triage` crashed on **every** binary: the packer-signature loop
  compared a `str` key against `bytes`.
- Extensionless executables were never triaged; binaries are now found by
  magic bytes as well as by name.
- The Solidity reentrancy check counted local variable declarations as
  state writes, which hid every reentrancy.
- The Sigma rule id used Python's randomised `hash()`, so the same finding
  produced a different id on every run.
- `prompt_injection` fired on any application that reflected text. It now
  requires positive evidence that a model is present.
- The write-up's severity counter raised `KeyError` on any finding set.

## [0.1.0] - 2026-10-18

The first release. A scanner that treats every active check as a
differential experiment and reports the proof alongside the finding.

### Added

**Core engine**
- Default-deny scope engine with wildcard hosts, path prefixes, port
  matching, and exclusions that always win over inclusions.
- Single egress point: one HTTP client owning redirects, per-host token
  bucket rate limiting, global concurrency, timeouts and secret redaction.
  Manual redirect handling re-checks scope at every hop.
- BFS crawler with `robots.txt` support, depth and page caps, form and
  endpoint extraction, and JavaScript link discovery.
- Technology fingerprinting across headers, meta tags, cookies and body
  signatures.
- Differential verification engine: status, length, timing, signature
  emergence, and reflection-context analysis.
- Severity and confidence as two independent axes, with confidence derived
  from evidence rather than from a module's optimism.
- Dedupe and ranking stage, plus a bounded risk score.

**Modules — 32 built in**
- *Web*: SQL injection, NoSQL injection, OS command injection, template
  injection, reflected XSS, XXE, insecure deserialization, path traversal,
  directory listing, exposed files, SSRF, open redirect, IDOR, missing CSRF,
  host header injection, GraphQL introspection, information disclosure,
  stack traces, HTTP method probing, outdated technology, security
  headers, cookie flags, CORS, clickjacking, mixed content.
- *Code*: secret detection (AWS, GCP, GitHub, GitLab, Slack, Stripe,
  SendGrid, Twilio, private keys, JWTs, database URLs, generic high-entropy
  strings), dangerous patterns, crypto misuse, and logic bugs such as
  mutable default arguments, swallowed exceptions and float money.
- *Dependencies*: manifest and lockfile parsing for PyPI, npm, crates.io,
  Go, Maven, RubyGems and Packagist, resolved against OSV.dev with local
  CVSS v3.1 scoring; advisories grouped per package; licence risk analysis.
- *Host*: TLS protocol and cipher posture, certificate expiry, SPF, DMARC,
  CAA and dangling CNAME checks.
- *Plugins*: built-in discovery, `nemesis_plugins` entry points and a
  `plugins/` directory, with include/exclude/tag filtering.

**Interfaces**
- `nemesis scan` with profiles (`quick`, `web`, `code`, `recon`, `full`,
  `passive`), auth modes (bearer, basic, header, cookie), scope and
  exclusion rules, module filters, severity floors and rate control.
- Reports in `console`, `json`, `markdown`, `html` and SARIF 2.1.0.
- `nemesis modules`, `nemesis profiles` and `nemesis explain`.
- Console output includes a proof-of-exploitability transcript for every
  confirmed finding.

**Engineering**
- CVSS v3.1 base score calculator.
- 97 tests including an end-to-end integration suite against a
  deliberately vulnerable fixture application.
- CI across Python 3.10 to 3.13, with lint, test and build gates.

[Unreleased]: https://github.com/nemesis-sec/nemesis/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nemesis-sec/nemesis/releases/tag/v0.1.0

# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`price_tampering` — a module for carts, payment gateways and product
  pages.** It does not report a parameter because the response changed; it
  reports when the server's own total moves to a number the attacker chose.
  Three surfaces are covered: a price in the query string, hidden price and
  quantity inputs in a POST form, and a JSON-only gateway that rejects form
  encoding. Findings quote baseline total, tampered total and the encoding
  used, and the fixed-price control in the test fixture proves the module
  stays silent when the server is authoritative.
- **65 modules** (was 64).

### Security

- **Path-scoped rules matched by string prefix**, so a rule for
  `/admin` also granted `/administrator` and `/admin-secret`. The
  comparison now lands on a segment boundary; an explicit glob tail
  (`/admin/*`) remains the way to opt into prefix behaviour. Found in
  an external technical audit.
- **Dot segments were not resolved before the scope check**, so
  `/admin/../secret` had the shape of the admin tree while resolving
  to `/secret`. Paths are now normalised to what the server will
  actually see, which is the path the check has to run on.

### Fixed

**Defects found by executing the scanner against a live target**

- **Every POST body was silently discarded.** `_raw_request` used
  `kwargs.pop("data")` to capture the body for the audit log, which removed
  it from the request that was actually sent. Form probes, XXE payloads and
  smuggling payloads all left the client as an empty body while the
  transaction log recorded the payload as if it had been delivered. Nine
  modules were affected. Bodies are now captured without being removed, and
  a regression test asserts that the server receives them.
- **The HTML report executed whatever it scanned.** The report template used
  `jinja2.Template`, whose default is `autoescape=False`, so a target that
  reflected `<script>` into a page could get it into `report.html` and run it
  in the analyst's browser. The environment now escapes by default.

**Defects found by fuzzing the parsers**

- **A 4-byte packet capture crashed the PCAP parser.** A file containing only
  the magic number has no global header, and `struct.unpack` raised. Files
  shorter than 24 bytes are now treated as truncated rather than fatal.
- **A malformed `pyproject.toml` crashed dependency parsing.**
  `dependencies = 5` raised `TypeError`, and a list of integers raised
  `AttributeError`. Parsed manifests are untrusted input and are now
  type-checked before use.
- **A malformed `package.json` crashed dependency parsing.** A string where
  an object was expected raised `AttributeError` on `.items()`.

**Hardening**

- **TLS verification was disabled for every request.** `verify=False` was
  hardcoded. The default is now to validate the certificate, with
  `--insecure` available for targets that genuinely have broken certificates.
- **The transaction log grew without bound.** Every response body was kept in
  a list nothing ever read. It is now a bounded deque.
- **`assert` guarded a runtime precondition**, and would vanish under
  `python -O`; it is now an explicit exception.
- **Request markers were generated with `random`**; they now use `secrets`.
- **`tech_outdated` declared `group = "supply-chain"`** while
  `cicd_pipeline_security` declared `"supplychain"`, so filtering by group
  silently missed one of them.

**Release-readiness audit**
- **The CI test job could never have passed.** The workflow ran
  `pytest --timeout=300`, but `pytest-timeout` was not a dependency, so
  every run died with `unrecognized arguments: --timeout=300` before a
  single test ran. Added to the `dev` extra.
- **Nine capability entries stored a string where a tuple belonged**, so
  `prerequisites` and `tools` iterated character by character — a
  `tools` value of `"a Windows host"` was displayed as
  `a; ; W; i; n; d; o; w; s; ; h; o; s; t`. Fixed: `windows-internals`,
  `sandbox-escapes`, `browser-exploitation`, `side-channel-attacks`,
  `sdr-radio-security`, `rfid-nfc-security`, `chip-hardware-security`,
  `side-channel-analysis`.
- **The `render` extra advertised a playwright renderer that does not
  exist.** Removed rather than left as a promise.
- **`package-data` pointed at two directories that do not exist.** Now
  ships `py.typed`, so downstream type checkers see the inline types.
- **The research library had 27 capability areas with no resource**, so
  `nemesis knowledge --area fuzzing` printed an empty table — which reads
  as "there is nothing worth reading about this" rather than "the index
  is incomplete". SQL injection, XSS, SSRF, request smuggling and
  deserialisation were all among them. Added 59 resources; the library is
  now **186 entries across 104 areas**, and a test asserts that no
  capability area can be added without one.
- **45 of the library's URLs were dead** (404, or pointing at hosts that
  no longer resolve). Every URL was re-checked and the broken ones
  replaced with verified equivalents. Duplicate entries and duplicate
  URLs were merged.

### Added

- `assets/` — banner, logo and architecture diagram, as SVG with rendered
  PNGs, so the README renders identically on GitHub and in a terminal.
- `GITHUB_SETUP.md` — first-push instructions, including the placeholder
  repository name that has to be replaced.
- Two tests that make the knowledge layer's completeness a build failure
  rather than a documentation bug.
- Repository URLs are now consistent across the README, package metadata,
  issue tracker, disclosure policy and the default User-Agent, which the
  audit found pointing at two different non-existent organisations.
- The comparison table no longer calls a Python package "one binary", and
  the offline row names the OSV lookup as the one network dependency.


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

### Changed

- **CVSS scores are filled in.** `Severity.to_cvss_base()` has existed since
  the first commit and was never called, so `cvss_score` was `null` in every
  JSON, SARIF and HTML report. Findings without a vector now carry the band
  for their severity; a real vector still wins. SARIF rules expose the value
  as `security-severity`, which is what GitHub ranks alerts by.
- **The HTTP client retries idempotent requests.** `rate.max_retries` and
  `rate.backoff` were declared and read by nothing. GET, HEAD and OPTIONS now
  retry transport errors and 429/502/503/504, honouring `Retry-After`.
  POST, PUT, PATCH and DELETE never retry: repeating a cart request is how a
  race-condition probe becomes two carts.

### Fixed

- **A business parameter that moves without the page moving is now caught.**
  `1` to `-1` changes one byte, so the length gate discarded it. If the
  injected value appears in the new body and not the old one, it is reported.
- `pcap.py` carried an `if True:` scaffold with a misindented block under it.

### Removed

- Sixteen functions nothing called: `all_params`, `request_with_cookies`,
  five `CspPolicy.allows_*` helpers, `Library.by_area`, `ScanContext.has_tech`
  / `tech_version` / `interesting_params`, `limited_gather`, `_is_confusable`,
  `price._fetch_original`, `print_finding`, `severity_badge`.
- The `save_evidence` and `no_banner` config switches, which nothing read.
- The `cryptography` and `validators` dependencies, which nothing imported.
- `assets/` and `examples/`. Nothing referenced them after the README was
  removed, and the demo could not run from an installed wheel because it
  imported `tests.fixtures`.
- The bundled plugin example is now `_example_plugin.py`. It used to load
  into every scan as an undocumented 141st module that no capability listed.

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

[Unreleased]: https://github.com/HexVandal/nemesis/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/HexVandal/nemesis/releases/tag/v0.1.0

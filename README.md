<p align="center">
  <img src="assets/banner-umbrella.jpg" alt="nemesis — differential offensive security" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-8B0000?style=for-the-badge&logo=python&logoColor=white&labelColor=000000" alt="Python">
  <img src="https://img.shields.io/badge/Windows-8B0000?style=for-the-badge&logo=windows&logoColor=white&labelColor=000000" alt="Windows">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/modules-140-8B0000?style=for-the-badge&labelColor=000000" alt="140 modules">
  <img src="https://img.shields.io/badge/capability%20areas-113-8B0000?style=for-the-badge&labelColor=000000" alt="113 capability areas">
  <img src="https://img.shields.io/badge/tests-478%20passing-8B0000?style=for-the-badge&labelColor=000000" alt="478 tests">
  <img src="https://img.shields.io/badge/scope-default--deny-8B0000?style=for-the-badge&labelColor=000000" alt="default-deny scope">
  <img src="https://img.shields.io/badge/license-Apache--2.0-8B0000?style=for-the-badge&labelColor=000000" alt="Apache-2.0">
</p>

<p align="center"><i>“Our business is life itself.”</i></p>

---

## ⚡ The problem with scanners

Almost every scanner answers a question nobody asked: **“did a pattern match?”** 🔍

You get a list of template hits, a severity colour, and no way to tell the one real SQL
injection from the two hundred false positives. Then you spend the afternoon triaging —
which was the work the tool was supposed to do. 😮‍💨

**nemesis answers a different question: _did the server’s behaviour change when I
attacked it?_**

Every active check is a **differential experiment** ⚗️. It sends a benign request, sends a
payload request to the *same* endpoint, and compares the two — status, body length,
timing, headers, and where the payload came back. A finding is only as strong as the
evidence that something changed.

---

## 🧪 A finding is an experiment you can re-run

```
  🔴 CRITICAL  SQL injection in parameter 'q'
  target       http://127.0.0.1:8899/search
╭──────────────────────────────────────────────────────────────────────────╮
│ Baseline: 200 GET /search?q=x            (48B, 0.00s)                    │
│ Probe   : 500 GET /search?q=%27         (233B, 0.00s)                    │
│ Delta   : status +300, length +185 bytes (4.85x), time +0.00s            │
╰──────────────────────────────────────────────────────────────────────────╯
```

You do not have to trust the scanner. **You can read the experiment.** 📖

---

## 🚀 Install

```bash
git clone https://github.com/HexVandal/nemesis.git
cd nemesis
python -m venv .venv
.\.venv\Scripts\activate        # Windows
# source .venv/bin/activate      # Linux / macOS
pip install -e .
```

🐍 Python 3.10 or newer. 🪟 Windows is a first-class target, not an afterthought.

## ▶️ Run

```bash
nemesis scan https://example.com --profile quick
nemesis scan https://example.com --format html --output reports/
nemesis scan https://example.com -i injection -i auth --allow-destructive
nemesis scan --code-path ./src --profile code
```

---

## 🧭 Profiles

| profile | what it is for | destructive |
|---|---|---|
| 🏃 `quick` | the high-signal checks, minutes not hours | no |
| 👁️ `passive` | read-only: headers, TLS, DNS, what the crawl saw | no |
| 🌐 `web` | the full web attack surface | some |
| 🧬 `code` | a local source tree: SAST, secrets, IaC, binaries | n/a |
| 🛰️ `recon` | DNS, TLS, host posture | no |
| 🤖 `ai` | LLM endpoints, prompt injection, agent tooling | some |
| ⛓️ `blockchain` | Solidity and DeFi surface | no |
| 🧪 `forensics` | memory images, PCAP, artefacts | n/a |
| 🏁 `full` | everything, including destructive checks | **yes** |

---

## 🛠️ The command line

| command | what it does |
|---|---|
| `nemesis scan` | scan a target and write a report |
| `nemesis modules` | list every module with its needs and severity |
| `nemesis capabilities` | the capability map, including what is **not** covered |
| `nemesis capability <id>` | one capability in detail |
| `nemesis coverage` | the 2,883-class taxonomy and what is honestly reachable |
| `nemesis profiles` | the nine scan profiles |
| `nemesis explain <severity>` | how a severity is decided |
| `nemesis cvss <vector>` | calculate and explain a CVSS v3.1 base score |
| `nemesis report <json>` | turn a scan into a bug-bounty disclosure draft |
| `nemesis writeup <json>` | turn a scan into a public write-up |
| `nemesis triage <json>` | rank findings into a worklist |
| `nemesis yara <json>` | detection rules from what was found |
| `nemesis sigma <json>` | SIEM rules from what was found |
| `nemesis knowledge` | the research library: papers, labs, courses, books |
| `nemesis lab` | the research workspace: notes, projects, portfolio |

📄 Five report formats: `console`, `json`, `markdown`, `html`, `sarif`.

---

## 📦 The complete catalogue — every module, what it needs and how bad it is
**140 modules** across **25 groups**. `needs` is what the module requires to run at all: 👁️ passive reads only what the crawl already fetched, 🌐 http sends requests, 🖧 host talks to the host, 🧬 code reads a local tree, 📦 deps reads manifests, 💥 destructive changes state on the target and needs `--allow-destructive`.
| severity | modules |
|---|---:|
| 🔴 Critical | 13 |
| 🟠 High | 40 |
| 🟡 Medium | 56 |
| 🔵 Low | 28 |
| ⚪ Info | 3 |

---
### 💉 Injection — 18 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `client_side_validation_bypass` | Submits non-numeric text into fields that name themselves numeric and reports the servers that store it. | 💥 destructive | 🔵 Low |
| `command_injection` | Sends shell metacharacters and looks for command output or a delayed response that the baseline does not produce. | 🌐 http | 🔴 Critical |
| `crlf_injection` | Sends CR and LF sequences inside parameters and checks whether the server emits the header that was smuggled in after them. | 🌐 http | 🟠 High |
| `expression_language_injection` | Sends SpEL, OGNL, MVEL and JSP-EL arithmetic and reports the pages where the expression was evaluated. | 🌐 http | 🟠 High |
| `http_parameter_pollution` | Sends a parameter twice with different values and reports endpoints whose answer depends on which copy wins. | 🌐 http | 🔵 Low |
| `insecure_deserialization` | Probes endpoints that accept structured objects for gadget-chain markers left by Java, Python, PHP or .NET deserialisers. | 🌐 http | 🔴 Critical |
| `ldap_injection` | Sends LDAP filter metacharacters and reports the parameters that produce a directory-server error the baseline did not. | 🌐 http | 🟠 High |
| `nosql_injection` | Tests MongoDB-style operators such as `$ne` and `$gt` that can bypass authentication or widen query results. | 🌐 http | 🟠 High |
| `null_byte_handling` | Compares a rejected value against the same value followed by a NUL and reports the pairs where only the second is accepted. | 🌐 http | 🟡 Medium |
| `redos_probe` | Times a pathological input against a benign one and reports large slowdowns on parameters that clearly reach a matcher. | 🌐 http | 🟡 Medium |
| `sqli` | Probes parameters with SQL metacharacters and error-based, boolean and time-based payloads, then verifies the response actually changed. | 🌐 http | 🔴 Critical |
| `ssi_injection` | Submits an SSI directive and reports the pages where the server executed it and printed its own environment back. | 🌐 http | 🟠 High |
| `stored_xss` | Submits a unique marker into ordinary text fields, then re-reads the page and its neighbours looking for the marker served back as markup. | 💥 destructive | 🟠 High |
| `template_injection` | Probes for template expression evaluation across common engines (Jinja2, Twig, Freemarker, Velocity, ERB, EL). | 🌐 http | 🔴 Critical |
| `unicode_normalization` | Sends a value and its full-width equivalent and reports endpoints that treat them as the same string. | 🌐 http | ⚪ Info |
| `xml_external_entity` | Sends XML containing an external entity reference to endpoints that accept XML and reports when a local file is disclosed. | 🌐 http | 🔴 Critical |
| `xpath_injection` | Sends XPath metacharacters and reports the parameters that produce an XPath parser error the baseline did not. | 🌐 http | 🟠 High |
| `xss` | Injects script-bearing payloads and analyses where they land. Only reports when the payload is reflected verbatim in an executable context, so HTML-encoded reflections are not flagged. | 🌐 http | 🟠 High |

### 🔐 Auth — 15 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `account_enumeration` | Submits two logins that cannot succeed - one for a common account name, one random - and reports forms that answer them differently. | 🌐 http | 🟡 Medium |
| `csrf_missing` | Identifies state-changing forms that carry no anti-CSRF token, and checks whether the server enforces an Origin or Referer check. | 👁️ passive | 🟡 Medium |
| `csrf_token_reuse` | Submits a form twice with an identical token and reports the actions that accept both. | 💥 destructive | 🟡 Medium |
| `default_credentials` | Attempts a short list of vendor defaults against login forms and reports the first pair the application actually accepts. | 💥 destructive | 🔴 Critical |
| `function_level_authz` | Requests administrative paths anonymously and reports the ones that answer 200. | 🌐 http | 🟠 High |
| `host_header_injection` | Sends a foreign Host header and checks whether it is reflected into the response, a Location header or an absolute link. | 🌐 http | 🟡 Medium |
| `idor` | Substitutes object identifiers with values belonging to other records and reports when the server returns a different, unauthorised object. | 🌐 http | 🟠 High |
| `jwt_audience_missing` | Decodes issued tokens and reports the ones that name no audience. | 👁️ passive | 🟡 Medium |
| `jwt_lifetime_excessive` | Reports tokens valid for more than 30 days, or with no expiry at all. | 👁️ passive | 🟡 Medium |
| `jwt_weakness` | Decodes every JWT the application issues and checks the things an attacker checks: is it signed at all, is the key a dictionary word, can 'kid' be steered, does it ever expire. | 👁️ passive | 🟠 High |
| `mass_assignment` | Submits registration and profile forms with an extra privileged field - role, is_admin, verified, balance - and reports it when the server stores the value and hands it back. | 💥 destructive | 🟠 High |
| `open_redirect` | Supplies external URLs into redirect-like parameters and checks whether the server will actually redirect off-site. | 🌐 http | 🟡 Medium |
| `rate_limiting` | Submits a short series of failed logins for accounts that cannot exist and reports the form that never slows down, locks out or issues a challenge. | 🌐 http | 🟡 Medium |
| `reset_token_entropy` | Measures reset tokens observed in crawled URLs for length and alphabet. | 👁️ passive | 🟡 Medium |
| `weak_password_policy` | Submits a single-character password to registration forms and reports the ones that accept it without a policy error. | 💥 destructive | 🟡 Medium |

### 🧬 Code — 13 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `binary_exploit_primitives` | Reports whether a binary's mitigations are on - stack canary, NX, PIE, RELRO - and whether it imports the unbounded string functions that memory corruption bugs use. | 🧬 code | 🟡 Medium |
| `binary_triage` | Parses ELF, PE and Mach-O binaries: architecture, hardening posture, imported dangerous functions, packer detection and credentials embedded in the binary. | 🧬 code | 🔵 Low |
| `crypto_misuse` | Detects ECB mode, static IVs, hardcoded keys, weak hash functions for passwords and low-iteration key derivation. | 🧬 code | 🟡 Medium |
| `dangerous_patterns` | Greps for constructs that are dangerous in context: shell execution, dynamic evaluation, unsafe deserialisation, disabled TLS verification and concatenated SQL. | 🧬 code | 🟠 High |
| `fuzz_harness` | Finds the buffer-parsing functions in a C or C++ source tree and generates a libFuzzer and an AFL++ harness for each, wired to the project's own build system, with a seed dictionary and the crash assertions that turn a crash into a report. | 🧬 code | ⚪ Info |
| `fuzzing_readiness` | Reports whether a project can be fuzzed at all: is there a harness, is there a corpus, is there a dictionary, and is the build wired to a fuzzing sanitizer. | 🧬 code | 🔵 Low |
| `git_history_secrets` | Walks a git repository's history and finds credentials that were committed and then removed - they are still in every clone and every CI cache, and removing them from HEAD does not remove them. | 🧬 code | 🔴 Critical |
| `iac_misconfiguration` | Scans Terraform, Kubernetes, Dockerfiles and CloudFormation for public storage, wide-open network rules, privileged containers, wildcard identity policies and embedded credentials. | 🧬 code | 🟠 High |
| `logic_bugs` | Detects defect patterns that are bugs rather than vulnerabilities: mutable default arguments, swallowed exceptions, missing `is None` comparisons, float currency and unsafe interpolation. | 🧬 code | 🔵 Low |
| `patch_regression` | Compares the working tree against the previous revision and reports dangerous patterns that were newly introduced, and previously fixed problems that have come back. | 🧬 code | 🟠 High |
| `privilege_escalation` | Finds the building blocks of a local privilege escalation: SUID and file capabilities, writable files that privileged processes read, PATH manipulation, and dangerous calls in the source. | 🧬 code | 🟡 Medium |
| `sandbox_escape` | Audits container and pod configuration for the settings that remove the isolation boundary: privileged containers, host namespace sharing, the Docker socket mounted inside, dangerous capabilities, and a writable root filesystem. | 🧬 code | 🔴 Critical |
| `secrets` | Finds API keys, tokens, private keys and passwords committed to source control using provider-specific patterns plus an entropy heuristic. | 🧬 code | 🔴 Critical |

### 🗂️ Exposure — 12 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `actuator_endpoints` | Checks for exposed Spring Boot actuator endpoints. | 🌐 http | 🟡 Medium |
| `api_schema_exposure` | Probes the conventional locations of OpenAPI and Swagger documents and reports the ones served to an unauthenticated client. | 🌐 http | 🔵 Low |
| `backup_file_sweep` | Appends editor and backup suffixes to discovered paths and reports the ones served. | 🌐 http | 🟠 High |
| `ci_metadata` | Checks for pipeline definitions served from the web root. | 🌐 http | 🟡 Medium |
| `csv_formula_injection` | Submits a formula into a form field, then reads the CSV export back and reports the cell that survived unescaped. | 💥 destructive | 🟡 Medium |
| `debug_console` | Checks for H2 console, phpinfo, werkzeug debugger and server-status pages. | 🌐 http | 🔴 Critical |
| `directory_listing_deep` | Reports discovered directories that render an index instead of a page. | 🌐 http | 🟡 Medium |
| `env_file_exposure` | Checks for .env files and confirms the response looks like a key-value environment. | 🌐 http | 🔴 Critical |
| `exposed_files` | Probes for version control directories, environment files, database dumps, backup archives and other artefacts that should never be served. | 🌐 http | 🟠 High |
| `graphql_introspection` | Queries the GraphQL introspection endpoint to see whether the full schema is exposed to unauthenticated clients. | 🌐 http | 🔵 Low |
| `robots_disclosure` | Reads robots.txt, requests the disallowed paths that look sensitive, and reports the ones the server actually serves. | 🌐 http | 🔵 Low |
| `vcs_metadata` | Checks for .git, .svn, .hg and .bzr directories in the web root. | 🌐 http | 🟠 High |

### 🛡️ Headers — 12 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `browser_security` | Checks that the browser security headers actually protect: a CSP that permits unsafe-inline is not a CSP, a __Host- cookie without Secure is silently rejected by the browser, and a cross-origin isolation header that is not accompanied by its partners does not enable isolation. | 👁️ passive | 🟡 Medium |
| `cache_control_misconfig` | Reports responses that set a session cookie or show account chrome without a no-store directive. | 👁️ passive | 🔵 Low |
| `clickjacking` | Pages without X-Frame-Options or a CSP frame-ancestors directive can be embedded by an attacker to trick a user into clicking. | 👁️ passive | 🟡 Medium |
| `cookie_flags` | Cookies issued without Secure, HttpOnly or SameSite can be stolen over plaintext, read by injected scripts, or replayed cross-site. | 👁️ passive | 🟡 Medium |
| `cors_misconfig` | Detects Access-Control-Allow-Origin wildcards and origins reflected from the request, especially combined with credentialed requests. | 👁️ passive | 🟡 Medium |
| `csp_analyzer` | Parses the Content-Security-Policy, resolves its directives, and reports the gaps that matter: unsafe-inline, unsafe-eval, wildcards, data: in script-src, and missing frame-ancestors and object-src. | 👁️ passive | 🟡 Medium |
| `csp_report_only` | Reports pages that send a CSP in report-only mode with no enforcing policy. | 👁️ passive | 🟡 Medium |
| `headers_security` | Detects missing response headers that browsers and proxies rely on for defence in depth, such as HSTS, CSP and X-Content-Type-Options. | 👁️ passive | 🟡 Medium |
| `ipv6_security` | Tests whether the application's address handling survives the forms of IPv6 that look like something else: IPv4-mapped addresses, zone identifiers, unbracketed literals and long-form abbreviations. | 🌐 http | 🟡 Medium |
| `mixed_content` | HTTPS pages that load sub-resources over plain HTTP can be downgraded or tampered with. | 👁️ passive | 🟡 Medium |
| `permissions_policy_gaps` | Reports pages with no Permissions-Policy, or one that grants sensitive features to all. | 👁️ passive | 🔵 Low |
| `proxy_security` | Checks whether the application takes the client address, the original host and the scheme from proxy headers without a trusted-proxy list - which means anyone can forge them. | 🌐 http | 🟡 Medium |

### 🤖 Ai — 9 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `agent_tool_security` | Finds tool and function-calling surfaces on an AI agent, and reports the ones that a caller can reach without authentication - a tool is a capability, and an exposed capability is an exposed action. | 🌐 http | 🟠 High |
| `ai_endpoint_auth` | Sends a minimal completion request with no credentials and reports one that answers. | 🌐 http | 🟠 High |
| `ai_endpoint_rate_limit` | Sends a short burst to model endpoints and reports the ones that never push back. | 🌐 http | 🔵 Low |
| `indirect_prompt_injection` | Plants a canary instruction in a stored field and checks whether the model repeats it later, when the field is read back into a prompt. | 💥 destructive | 🟠 High |
| `llm_endpoint_detection` | Finds model API endpoints, identifies the provider, and reports the ones that answered without authentication - an unauthenticated model endpoint is an expensive, abusable and often prompt-injectable resource. | 🌐 http | 🟡 Medium |
| `ml_model_security` | Finds model artefacts in unsafe serialisation formats, loading code that executes code while deserialising, datasets that contain personal data, and model cards or configs that leak credentials, internal endpoints or training data. | 🧬 code | 🟠 High |
| `model_extraction` | Reports model endpoints that return unusually complete outputs to systematic probing, endpoints that leak training-style information, and privacy-relevant exposures in the surrounding application. | 👁️ passive | 🟡 Medium |
| `prompt_injection` | Sends instruction-shaped input to every discovered parameter and checks whether it is reflected back into the model's context, which is the point at which a user's text becomes the model's instructions. | 🌐 http | 🟠 High |
| `system_prompt_extraction` | Sends an extraction prompt and reports replies that read like the model's own instructions. | 🌐 http | 🟡 Medium |

### 🔌 Api — 7 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `accept_header_bypass` | Asks JSON endpoints for XML and reports the ones that switch format. | 🌐 http | 🔵 Low |
| `api_endpoint_bruteforce` | Requests a short list of conventional API paths and reports the ones not in the crawl. | 🌐 http | 🔵 Low |
| `api_unauthenticated_access` | Replays discovered API requests with the session removed and reports the ones that still return data. | 🌐 http | 🟠 High |
| `api_version_fallback` | Steps a versioned API path back one major version and reports the ones that answer. | 🌐 http | 🟡 Medium |
| `graphql_batching` | Posts an array of two operations to each GraphQL endpoint and reports the ones that answer both in a single request. | 🌐 http | 🔵 Low |
| `graphql_depth_abuse` | Sends a deeply nested introspection query and reports endpoints that answer it in full. | 🌐 http | 🔵 Low |
| `openapi_security_definition` | Reads the published schema and reports an empty or absent security section. | 🌐 http | 🔵 Low |

### ⚙️ Config — 7 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `cookie_scope_escape` | Reports cookies whose Domain is a single-label suffix. | 👁️ passive | 🟡 Medium |
| `cors_origin_reflection` | Sends a unique Origin and reports the endpoints that echo it back. | 🌐 http | 🟠 High |
| `http_method_override` | Sends X-HTTP-Method-Override and _method and reports responses that change. | 🌐 http | 🟡 Medium |
| `http_method_probe` | Probes whether the server accepts unsafe methods such as TRACE, PUT and DELETE on resources it should not modify. | 💥 destructive | 🟡 Medium |
| `mass_endpoint_discovery` | Reads the Allow header on discovered paths and reports destructive verbs. | 🌐 http | 🔵 Low |
| `rate_limit_bypass` | Trips the limit, then repeats the same traffic with rotating X-Forwarded-For values and reports the endpoints that stop resisting. | 🌐 http | 🟡 Medium |
| `verb_tampering` | Sends state-changing verbs to discovered paths and reports the ones that answer. | 🌐 http | 🟡 Medium |

### 🕵️ Disclosure — 5 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `error_page_fingerprint` | Requests a path that cannot exist and reports framework banners in the 404 page. | 🌐 http | 🔵 Low |
| `info_disclosure` | Detects stack traces, verbose framework errors, debug pages and internal hostnames leaked into responses. | 👁️ passive | 🟡 Medium |
| `secrets_in_javascript` | Reads every script the crawler fetched and reports credential patterns that belong on a server, not in a bundle. | 👁️ passive | 🟠 High |
| `sensitive_data_in_url` | Scans crawled URLs and links for tokens, keys and JWTs carried in the query string. | 👁️ passive | 🟡 Medium |
| `source_map_exposure` | Requests the source map for each script the crawler fetched and reports the ones that return original sources. | 🌐 http | 🟡 Medium |

### 🌐 Host — 5 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `dangling_dns` | Resolves the external hosts referenced by the site and reports the ones that no longer exist. | 👁️ passive | 🔵 Low |
| `dns_posture` | Checks that SPF, DMARC and CAA records exist and are not permissive, and looks for CNAMEs pointing at claimable hosting providers. | 🖧 host | 🟡 Medium |
| `pcap_analysis` | Parses a pcap or pcapng capture and reports cleartext credentials, API keys in URLs, DNS exfiltration, plaintext protocols carrying sensitive traffic and unusual flows. | 🧬 code | 🟡 Medium |
| `subdomain_takeover` | Looks for the placeholder pages providers serve for an unconfigured host - S3, GitHub Pages, Heroku, Fastly and others. | 🌐 http | 🟠 High |
| `tls_configuration` | Checks the negotiated TLS version, certificate validity, hostname matching and the cipher suites the server is willing to use. | 🖧 host | 🟡 Medium |

### 📦 Supplychain — 5 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `artifact_provenance` | Reports a release with no signature, checksum file or provenance attestation beside it. | 🧬 code | 🔵 Low |
| `cicd_pipeline_security` | Audits workflow and pipeline definitions for untrusted pull request code running with secrets, unpinned third-party actions, expression injection into shell commands, and containers that hand the build the whole machine. | 🧬 code | 🔴 Critical |
| `lockfile_integrity` | Reports a dependency manifest with no lock beside it, or a lock that does not pin resolved hashes. | 🧬 code | 🟡 Medium |
| `sbom_presence` | Reports a repository that ships no SBOM in any common format. | 🧬 code | 🔵 Low |
| `tech_outdated` | Compares fingerprinted component versions against known-vulnerable release ranges for a small set of high-profile products. | 👁️ passive | 🟡 Medium |

### 📚 Deps — 4 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `dependency_confusion` | Finds declared dependencies whose names are unqualified but collide with an internal package, and unscoped names that exist on a public registry, so a public package could shadow an internal one during the build. | 📦 deps | 🟠 High |
| `dependency_vulnerabilities` | Resolves dependencies from lockfiles and manifests, then checks each against the OSV.dev advisory database. | 📦 deps | 🟡 Medium |
| `license_risk` | Identifies dependencies under strong copyleft, file-level copyleft and source-available licences that may conflict with a proprietary or closed-source distribution. | 📦 deps | 🟡 Medium |
| `typosquatting` | Compares every declared dependency name against the popular packages of its ecosystem and reports the ones that are within a typo of a real one. | 📦 deps | 🟠 High |

### 🧠 Logic — 4 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `coupon_reuse` | Applies the same coupon value twice and reports the forms that accept both. | 💥 destructive | 🟡 Medium |
| `idempotency_key_absent` | Submits the same checkout request twice and reports two successes. | 💥 destructive | 🟡 Medium |
| `pagination_boundary` | Raises limit/offset parameters past any sane cap and reports the ones that obey. | 🌐 http | 🔵 Low |
| `race_condition` | Sends six identical state-changing requests concurrently and reports when more than one succeeds. | 💥 destructive | 🟡 Medium |

### 🔑 Oauth — 4 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `oauth_pkce_missing` | Reads authorization-code requests and reports the ones with no code_challenge. | 👁️ passive | 🔵 Low |
| `oauth_redirect_bypass` | Finds authorization requests with a redirect_uri, replaces it with a host that cannot resolve, and reports the ones that redirect there. | 🌐 http | 🟠 High |
| `oauth_scope_escalation` | Replays an authorization request with an elevated scope and reports endpoints that issue the redirect anyway. | 🌐 http | 🟡 Medium |
| `oauth_state_missing` | Replays an authorization request with the state parameter removed and reports endpoints that still issue the redirect. | 🌐 http | 🟡 Medium |

### 🖥️ Browser — 3 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `reverse_tabnabbing` | Reports links that open a new tab with target=_blank but no rel=noopener or noreferrer. | 👁️ passive | 🔵 Low |
| `sensitive_data_in_storage` | Reads served JavaScript for tokens written to local or session storage. | 👁️ passive | 🔵 Low |
| `sri_missing` | Reports third-party scripts and stylesheets loaded without an integrity attribute. | 👁️ passive | 🔵 Low |

### ⚡ Cache — 3 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `cache_deception` | Appends a static extension to discovered paths and reports the ones that still return the private page. | 🌐 http | 🟡 Medium |
| `host_header_cache_poison` | Sends a forged host header and reports the ones echoed into a cached response. | 🌐 http | 🟠 High |
| `web_cache_poisoning` | Finds responses that a shared cache can store, and headers that reach the origin without being part of the cache key - the combination that lets one user poison what another user sees. | 🌐 http | 🟠 High |

### ⛓️ Blockchain — 2 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `defi_security` | Audits DeFi contracts for the failures that are specific to protocols that move value: manipulable oracles, unchecked token transfers, swaps with no slippage bound, and prices derived from the pool being traded. | 🧬 code | 🔴 Critical |
| `solidity_audit` | Audits Solidity sources for reentrancy, missing access control, unchecked arithmetic and return values, dangerous delegatecall and self-destruct paths, and insecure randomness. | 🧬 code | 🟠 High |

### 💳 Business — 2 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `business_logic` | Probes the parameters that carry a commercial decision - price, quantity, discount, role, state, step - and reports the ones the server appears to take from the client without validation. | 🌐 http | 🟡 Medium |
| `price_tampering` | Sends a price, quantity or amount the client should not control - negative, zero, a penny - and reports it when the server's own total follows the attacker's number. | 🌐 http | 🟠 High |

### 🧪 Forensics — 2 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `memory_dump_triage` | Identifies memory dump format, platform, page-table structure and the artifacts present in an image, before any verdict is formed. | 🧬 code | ⚪ Info |
| `memory_forensics` | Parses memory images and raw dumps for process inventory, command lines, injected memory, the network connection table, persistence keys and resident secrets. | 🧬 code | 🟠 High |

### 🎯 Ssrf — 2 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `cloud_attack_surface` | Checks the cloud metadata service, looks for exposed cloud storage and pre-signed URLs, and reports how much of the cloud an SSRF would reach. | 🌐 http | 🟠 High |
| `ssrf` | Supplies URLs pointing at loopback, link-local and cloud metadata addresses and reports when the server's response proves it fetched the resource itself. | 🌐 http | 🟠 High |

### 📁 Traversal — 2 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `directory_listing` | Detects autoindex-style directory listings that expose file names. | 👁️ passive | 🔵 Low |
| `path_traversal` | Attempts to read well-known system files through traversal sequences and reports only when the file content actually appears. | 🌐 http | 🟠 High |

### 💥 Dos — 1 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `resource_exhaustion` | Sends a deeply nested JSON body, an oversized field and a slow repeat and reports the ones the server accepted without complaint. | 🌐 http | 🔵 Low |

### 📮 Smuggling — 1 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `request_smuggling` | Probes for CL.TE and TE.CL desynchronisation by sending requests with conflicting framing headers and looking for a response that the front end never requested. | 🌐 http | 🟠 High |

### 📤 Upload — 1 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `file_upload` | Probes multipart upload endpoints for extension filtering bypass, content-type confusion, double extensions, path traversal in the filename and files that are stored and later served as active content. | 🌐 http | 🟠 High |

### 🔗 Websocket — 1 modules
| module | what it does | needs | severity |
|---|---|---|---|
| `websocket_security` | Checks the WebSocket upgrade handshake for origin validation, missing authentication and weak subprotocol negotiation, then tests the message channel for cross-site hijacking and unsanitised reflection. | 🌐 http | 🟡 Medium |

---

## 🚫 What it does not do

This is the part most scanners leave out. 🙈

- **No out-of-band listener.** 👂 Blind SSRF, blind XXE and blind command injection are
  reported as *not tested*, never as findings. They need a callback server, and nemesis
  does not pretend to have one.
- **No headless browser.** 🖥️ Anything that only exists after JavaScript runs — DOM XSS,
  client-side routing bugs, `postMessage` flaws — is out of reach.
- **No second account.** 👥 Multi-tenant IDOR and privilege escalation need two live
  sessions; those checks are listed as needing authentication, not silently skipped.
- **No cloud credentials, no gRPC reflection, no kernel or hardware work.** ☁️ The
  taxonomy ledger says so per item rather than implying coverage.

The 2,883-class taxonomy that ships with the tool is measured, not estimated:
**2,230 classes reachable (77.3 %)**, with the rest marked `needs infra`, `manual`,
`needs browser` or `out of scope`. `nemesis coverage` prints that ledger. The shorter
list of 309 named weaknesses, and what happened to each one, is in
[`docs/coverage-309.md`](docs/coverage-309.md).

---

## ✅ How this is verified, not asserted

| | |
|---|---|
| 🧪 tests | **478 passing** |
| 📏 line coverage | **77 %** (11,240 statements) |
| 🧹 lint | `ruff` clean |
| 🔁 CI | Python 3.10, 3.11, 3.12, 3.13 — ruff, compile, tests, build |
| 📦 packaging | sdist and wheel build from a clean tree |

Every detector has a **hardened twin** in the test suite: a fixture that looks like the
vulnerable one but is correctly implemented, which the module must stay silent on. 🎯 A
detector that fires on both is a false-positive generator, and the test fails.

Four tests exist purely to keep the tool honest about itself: 🧿 every module declares a
CWE and an OWASP category, every module has actionable remediation text, duplicate
findings collapse on fingerprint, and two runs over the same fixture produce
byte-identical findings.

---

## 📚 Documents

| file | what is in it |
|---|---|
| [`docs/modules.md`](docs/modules.md) | all 140 modules, one row each |
| [`docs/coverage-309.md`](docs/coverage-309.md) | every item from the 309-item list, with a verdict |
| [`docs/detector-roadmap.md`](docs/detector-roadmap.md) | the taxonomy map and what is honestly reachable |
| [`AUDIT.md`](AUDIT.md) | self-audit, including the defects that were found and fixed |
| [`CHANGELOG.md`](CHANGELOG.md) | what changed, and why |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | how to add a module |

---

## ⚖️ Authorised use

nemesis sends real attack payloads to whatever host you point it at. 🎯

**Only run it against systems you own or have explicit, written permission to test** —
pentests under an agreed scope, bug bounty programmes within their published rules,
CTFs, internal red teams, or your own infrastructure. Running it against third-party
systems without authorisation is a criminal offence in most jurisdictions, and being
open source is not a defence. 🚨

The rails that make an accident unlikely: 🛤️ scope is **default-deny** and every redirect
hop is checked against it, destructive modules need `--allow-destructive`, per-host rate
limiting is on by default, exclusions always beat inclusions, and credentials are redacted
out of evidence. Those rails reduce risk — they do not create authorisation. That has to
come from you.

## 📄 License

Apache-2.0. See [LICENSE](LICENSE).

<p align="center"><sub>Built by <a href="https://github.com/HexVandal">Hazel</a>.</sub></p>

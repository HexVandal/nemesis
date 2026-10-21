# Modules

110 modules, grouped by domain. *cap* is what the module needs (passive = reads what the crawl fetched, http = sends requests, destructive = changes state and needs `--allow-destructive`).


## code — 13

| module | what it does | cap | sev |
|---|---|---|---|
| `binary_exploit_primitives` | Reports whether a binary's mitigations are on - stack canary, NX, PIE, RELRO - and… | code | MEDIUM |
| `binary_triage` | Parses ELF, PE and Mach-O binaries: architecture, hardening posture, imported dangerous… | code | LOW |
| `crypto_misuse` | Detects ECB mode, static IVs, hardcoded keys, weak hash functions for passwords and… | code | MEDIUM |
| `dangerous_patterns` | Greps for constructs that are dangerous in context: shell execution, dynamic evaluation,… | code | HIGH |
| `fuzz_harness` | Finds the buffer-parsing functions in a C or C++ source tree and generates a libFuzzer… | code | INFO |
| `fuzzing_readiness` | Reports whether a project can be fuzzed at all: is there a harness, is there a corpus,… | code | LOW |
| `git_history_secrets` | Walks a git repository's history and finds credentials that were committed and then… | code | CRITICAL |
| `iac_misconfiguration` | Scans Terraform, Kubernetes, Dockerfiles and CloudFormation for public storage,… | code | HIGH |
| `logic_bugs` | Detects defect patterns that are bugs rather than vulnerabilities: mutable default… | code | LOW |
| `patch_regression` | Compares the working tree against the previous revision and reports dangerous patterns… | code | HIGH |
| `privilege_escalation` | Finds the building blocks of a local privilege escalation: SUID and file capabilities,… | code | MEDIUM |
| `sandbox_escape` | Audits container and pod configuration for the settings that remove the isolation… | code | CRITICAL |
| `secrets` | Finds API keys, tokens, private keys and passwords committed to source control using… | code | CRITICAL |

## auth — 12

| module | what it does | cap | sev |
|---|---|---|---|
| `csrf_missing` | Identifies state-changing forms that carry no anti-CSRF token, and checks whether the… | passive | MEDIUM |
| `csrf_token_reuse` | Submits a form twice with an identical token and reports the actions that accept both | destructive | MEDIUM |
| `default_credentials` | Attempts a short list of vendor defaults against login forms and reports the first pair… | destructive | CRITICAL |
| `host_header_injection` | Sends a foreign Host header and checks whether it is reflected into the response, a… | http | MEDIUM |
| `idor` | Substitutes object identifiers with values belonging to other records and reports when… | http | HIGH |
| `jwt_audience_missing` | Decodes issued tokens and reports the ones that name no audience | passive | MEDIUM |
| `jwt_lifetime_excessive` | Reports tokens valid for more than 30 days, or with no expiry at all | passive | MEDIUM |
| `jwt_weakness` | Decodes every JWT the application issues and checks the things an attacker checks: is it… | passive | HIGH |
| `mass_assignment` | Submits registration and profile forms with an extra privileged field - role, is_admin,… | destructive | HIGH |
| `open_redirect` | Supplies external URLs into redirect-like parameters and checks whether the server will… | http | MEDIUM |
| `rate_limiting` | Submits a short series of failed logins for accounts that cannot exist and reports the… | http | MEDIUM |
| `weak_password_policy` | Submits a single-character password to registration forms and reports the ones that… | destructive | MEDIUM |

## injection — 12

| module | what it does | cap | sev |
|---|---|---|---|
| `command_injection` | Sends shell metacharacters and looks for command output or a delayed response that the… | http | CRITICAL |
| `crlf_injection` | Sends CR and LF sequences inside parameters and checks whether the server emits the… | http | HIGH |
| `insecure_deserialization` | Probes endpoints that accept structured objects for gadget-chain markers left by Java,… | http | CRITICAL |
| `ldap_injection` | Sends LDAP filter metacharacters and reports the parameters that produce a… | http | HIGH |
| `nosql_injection` | Tests MongoDB-style operators such as `$ne` and `$gt` that can bypass authentication or… | http | HIGH |
| `sqli` | Probes parameters with SQL metacharacters and error-based, boolean and time-based… | http | CRITICAL |
| `ssi_injection` | Submits an SSI directive and reports the pages where the server executed it and printed… | http | HIGH |
| `stored_xss` | Submits a unique marker into ordinary text fields, then re-reads the page and its… | destructive | HIGH |
| `template_injection` | Probes for template expression evaluation across common engines (Jinja2, Twig,… | http | CRITICAL |
| `xml_external_entity` | Sends XML containing an external entity reference to endpoints that accept XML and… | http | CRITICAL |
| `xpath_injection` | Sends XPath metacharacters and reports the parameters that produce an XPath parser error… | http | HIGH |
| `xss` | Injects script-bearing payloads and analyses where they land | http | HIGH |

## exposure — 11

| module | what it does | cap | sev |
|---|---|---|---|
| `actuator_endpoints` | Checks for exposed Spring Boot actuator endpoints | http | MEDIUM |
| `api_schema_exposure` | Probes the conventional locations of OpenAPI and Swagger documents and reports the ones… | http | LOW |
| `backup_file_sweep` | Appends editor and backup suffixes to discovered paths and reports the ones served | http | HIGH |
| `ci_metadata` | Checks for pipeline definitions served from the web root | http | MEDIUM |
| `debug_console` | Checks for H2 console, phpinfo, werkzeug debugger and server-status pages | http | CRITICAL |
| `directory_listing_deep` | Reports discovered directories that render an index instead of a page | http | MEDIUM |
| `env_file_exposure` | Checks for .env files and confirms the response looks like a key-value environment | http | CRITICAL |
| `exposed_files` | Probes for version control directories, environment files, database dumps, backup… | http | HIGH |
| `graphql_introspection` | Queries the GraphQL introspection endpoint to see whether the full schema is exposed to… | http | LOW |
| `robots_disclosure` | Reads robots.txt, requests the disallowed paths that look sensitive, and reports the… | http | LOW |
| `vcs_metadata` | Checks for .git, .svn, .hg and .bzr directories in the web root | http | HIGH |

## headers — 11

| module | what it does | cap | sev |
|---|---|---|---|
| `browser_security` | Checks that the browser security headers actually protect: a CSP that permits… | passive | MEDIUM |
| `clickjacking` | Pages without X-Frame-Options or a CSP frame-ancestors directive can be embedded by an… | passive | MEDIUM |
| `cookie_flags` | Cookies issued without Secure, HttpOnly or SameSite can be stolen over plaintext, read… | passive | MEDIUM |
| `cors_misconfig` | Detects Access-Control-Allow-Origin wildcards and origins reflected from the request,… | passive | MEDIUM |
| `csp_analyzer` | Parses the Content-Security-Policy, resolves its directives, and reports the gaps that… | passive | MEDIUM |
| `csp_report_only` | Reports pages that send a CSP in report-only mode with no enforcing policy | passive | MEDIUM |
| `headers_security` | Detects missing response headers that browsers and proxies rely on for defence in depth,… | passive | MEDIUM |
| `ipv6_security` | Tests whether the application's address handling survives the forms of IPv6 that look… | http | MEDIUM |
| `mixed_content` | HTTPS pages that load sub-resources over plain HTTP can be downgraded or tampered with | passive | MEDIUM |
| `permissions_policy_gaps` | Reports pages with no Permissions-Policy, or one that grants sensitive features to all | passive | LOW |
| `proxy_security` | Checks whether the application takes the client address, the original host and the… | http | MEDIUM |

## config — 6

| module | what it does | cap | sev |
|---|---|---|---|
| `cookie_scope_escape` | Reports cookies whose Domain is a single-label suffix | passive | MEDIUM |
| `cors_origin_reflection` | Sends a unique Origin and reports the endpoints that echo it back | http | HIGH |
| `http_method_override` | Sends X-HTTP-Method-Override and _method and reports responses that change | http | MEDIUM |
| `http_method_probe` | Probes whether the server accepts unsafe methods such as TRACE, PUT and DELETE on… | destructive | MEDIUM |
| `mass_endpoint_discovery` | Reads the Allow header on discovered paths and reports destructive verbs | http | LOW |
| `verb_tampering` | Sends state-changing verbs to discovered paths and reports the ones that answer | http | MEDIUM |

## ai — 5

| module | what it does | cap | sev |
|---|---|---|---|
| `agent_tool_security` | Finds tool and function-calling surfaces on an AI agent, and reports the ones that a… | http | HIGH |
| `llm_endpoint_detection` | Finds model API endpoints, identifies the provider, and reports the ones that answered… | http | MEDIUM |
| `ml_model_security` | Finds model artefacts in unsafe serialisation formats, loading code that executes code… | code | HIGH |
| `model_extraction` | Reports model endpoints that return unusually complete outputs to systematic probing,… | passive | MEDIUM |
| `prompt_injection` | Sends instruction-shaped input to every discovered parameter and checks whether it is… | http | HIGH |

## disclosure — 5

| module | what it does | cap | sev |
|---|---|---|---|
| `error_page_fingerprint` | Requests a path that cannot exist and reports framework banners in the 404 page | http | LOW |
| `info_disclosure` | Detects stack traces, verbose framework errors, debug pages and internal hostnames… | passive | MEDIUM |
| `secrets_in_javascript` | Reads every script the crawler fetched and reports credential patterns that belong on a… | passive | HIGH |
| `sensitive_data_in_url` | Scans crawled URLs and links for tokens, keys and JWTs carried in the query string | passive | MEDIUM |
| `source_map_exposure` | Requests the source map for each script the crawler fetched and reports the ones that… | http | MEDIUM |

## deps — 4

| module | what it does | cap | sev |
|---|---|---|---|
| `dependency_confusion` | Finds declared dependencies whose names are unqualified but collide with an internal… | deps | HIGH |
| `dependency_vulnerabilities` | Resolves dependencies from lockfiles and manifests, then checks each against the OSV.dev… | deps | MEDIUM |
| `license_risk` | Identifies dependencies under strong copyleft, file-level copyleft and source-available… | deps | MEDIUM |
| `typosquatting` | Compares every declared dependency name against the popular packages of its ecosystem… | deps | HIGH |

## api — 3

| module | what it does | cap | sev |
|---|---|---|---|
| `accept_header_bypass` | Asks JSON endpoints for XML and reports the ones that switch format | http | LOW |
| `api_version_fallback` | Steps a versioned API path back one major version and reports the ones that answer | http | MEDIUM |
| `graphql_batching` | Posts an array of two operations to each GraphQL endpoint and reports the ones that… | http | LOW |

## host — 3

| module | what it does | cap | sev |
|---|---|---|---|
| `dns_posture` | Checks that SPF, DMARC and CAA records exist and are not permissive, and looks for… | host | MEDIUM |
| `pcap_analysis` | Parses a pcap or pcapng capture and reports cleartext credentials, API keys in URLs, DNS… | code | MEDIUM |
| `tls_configuration` | Checks the negotiated TLS version, certificate validity, hostname matching and the… | host | MEDIUM |

## logic — 3

| module | what it does | cap | sev |
|---|---|---|---|
| `coupon_reuse` | Applies the same coupon value twice and reports the forms that accept both | destructive | MEDIUM |
| `idempotency_key_absent` | Submits the same checkout request twice and reports two successes | destructive | MEDIUM |
| `pagination_boundary` | Raises limit/offset parameters past any sane cap and reports the ones that obey | http | LOW |

## oauth — 3

| module | what it does | cap | sev |
|---|---|---|---|
| `oauth_pkce_missing` | Reads authorization-code requests and reports the ones with no code_challenge | passive | LOW |
| `oauth_redirect_bypass` | Finds authorization requests with a redirect_uri, replaces it with a host that cannot… | http | HIGH |
| `oauth_state_missing` | Replays an authorization request with the state parameter removed and reports endpoints… | http | MEDIUM |

## blockchain — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `defi_security` | Audits DeFi contracts for the failures that are specific to protocols that move value:… | code | CRITICAL |
| `solidity_audit` | Audits Solidity sources for reentrancy, missing access control, unchecked arithmetic and… | code | HIGH |

## browser — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `reverse_tabnabbing` | Reports links that open a new tab with target=_blank but no rel=noopener or noreferrer | passive | LOW |
| `sri_missing` | Reports third-party scripts and stylesheets loaded without an integrity attribute | passive | LOW |

## business — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `business_logic` | Probes the parameters that carry a commercial decision - price, quantity, discount,… | http | MEDIUM |
| `price_tampering` | Sends a price, quantity or amount the client should not control - negative, zero, a… | http | HIGH |

## cache — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `host_header_cache_poison` | Sends a forged host header and reports the ones echoed into a cached response | http | HIGH |
| `web_cache_poisoning` | Finds responses that a shared cache can store, and headers that reach the origin without… | http | HIGH |

## forensics — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `memory_dump_triage` | Identifies memory dump format, platform, page-table structure and the artifacts present… | code | INFO |
| `memory_forensics` | Parses memory images and raw dumps for process inventory, command lines, injected… | code | HIGH |

## ssrf — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `cloud_attack_surface` | Checks the cloud metadata service, looks for exposed cloud storage and pre-signed URLs,… | http | HIGH |
| `ssrf` | Supplies URLs pointing at loopback, link-local and cloud metadata addresses and reports… | http | HIGH |

## supplychain — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `cicd_pipeline_security` | Audits workflow and pipeline definitions for untrusted pull request code running with… | code | CRITICAL |
| `tech_outdated` | Compares fingerprinted component versions against known-vulnerable release ranges for a… | passive | MEDIUM |

## traversal — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `directory_listing` | Detects autoindex-style directory listings that expose file names | passive | LOW |
| `path_traversal` | Attempts to read well-known system files through traversal sequences and reports only… | http | HIGH |

## smuggling — 1

| module | what it does | cap | sev |
|---|---|---|---|
| `request_smuggling` | Probes for CL.TE and TE.CL desynchronisation by sending requests with conflicting… | http | HIGH |

## upload — 1

| module | what it does | cap | sev |
|---|---|---|---|
| `file_upload` | Probes multipart upload endpoints for extension filtering bypass, content-type… | http | HIGH |

## websocket — 1

| module | what it does | cap | sev |
|---|---|---|---|
| `websocket_security` | Checks the WebSocket upgrade handshake for origin validation, missing authentication and… | http | MEDIUM |

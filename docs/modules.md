# Modules

140 modules, grouped by domain. *cap* is what the module needs (passive = reads what the crawl fetched, http = sends requests, destructive = changes state and needs `--allow-destructive`).


## injection — 18

| module | what it does | cap | sev |
|---|---|---|---|
| `client_side_validation_bypass` | Submits non-numeric text into fields that name themselves numeric and reports the servers that… | destructive | LOW |
| `command_injection` | Sends shell metacharacters and looks for command output or a delayed response that the baseline… | http | CRITICAL |
| `crlf_injection` | Sends CR and LF sequences inside parameters and checks whether the server emits the header that… | http | HIGH |
| `expression_language_injection` | Sends SpEL, OGNL, MVEL and JSP-EL arithmetic and reports the pages where the expression was eva… | http | HIGH |
| `http_parameter_pollution` | Sends a parameter twice with different values and reports endpoints whose answer depends on whi… | http | LOW |
| `insecure_deserialization` | Probes endpoints that accept structured objects for gadget-chain markers left by Java, Python,… | http | CRITICAL |
| `ldap_injection` | Sends LDAP filter metacharacters and reports the parameters that produce a directory-server err… | http | HIGH |
| `nosql_injection` | Tests MongoDB-style operators such as `$ne` and `$gt` that can bypass authentication or widen q… | http | HIGH |
| `null_byte_handling` | Compares a rejected value against the same value followed by a NUL and reports the pairs where… | http | MEDIUM |
| `redos_probe` | Times a pathological input against a benign one and reports large slowdowns on parameters that… | http | MEDIUM |
| `sqli` | Probes parameters with SQL metacharacters and error-based, boolean and time-based payloads, the… | http | CRITICAL |
| `ssi_injection` | Submits an SSI directive and reports the pages where the server executed it and printed its own… | http | HIGH |
| `stored_xss` | Submits a unique marker into ordinary text fields, then re-reads the page and its neighbours lo… | destructive | HIGH |
| `template_injection` | Probes for template expression evaluation across common engines (Jinja2, Twig, Freemarker, Velo… | http | CRITICAL |
| `unicode_normalization` | Sends a value and its full-width equivalent and reports endpoints that treat them as the same s… | http | INFO |
| `xml_external_entity` | Sends XML containing an external entity reference to endpoints that accept XML and reports when… | http | CRITICAL |
| `xpath_injection` | Sends XPath metacharacters and reports the parameters that produce an XPath parser error the ba… | http | HIGH |
| `xss` | Injects script-bearing payloads and analyses where they land. Only reports when the payload is… | http | HIGH |

## auth — 15

| module | what it does | cap | sev |
|---|---|---|---|
| `account_enumeration` | Submits two logins that cannot succeed - one for a common account name, one random - and report… | http | MEDIUM |
| `csrf_missing` | Identifies state-changing forms that carry no anti-CSRF token, and checks whether the server en… | passive | MEDIUM |
| `csrf_token_reuse` | Submits a form twice with an identical token and reports the actions that accept both. | destructive | MEDIUM |
| `default_credentials` | Attempts a short list of vendor defaults against login forms and reports the first pair the app… | destructive | CRITICAL |
| `function_level_authz` | Requests administrative paths anonymously and reports the ones that answer 200. | http | HIGH |
| `host_header_injection` | Sends a foreign Host header and checks whether it is reflected into the response, a Location he… | http | MEDIUM |
| `idor` | Substitutes object identifiers with values belonging to other records and reports when the serv… | http | HIGH |
| `jwt_audience_missing` | Decodes issued tokens and reports the ones that name no audience. | passive | MEDIUM |
| `jwt_lifetime_excessive` | Reports tokens valid for more than 30 days, or with no expiry at all. | passive | MEDIUM |
| `jwt_weakness` | Decodes every JWT the application issues and checks the things an attacker checks: is it signed… | passive | HIGH |
| `mass_assignment` | Submits registration and profile forms with an extra privileged field - role, is_admin, verifie… | destructive | HIGH |
| `open_redirect` | Supplies external URLs into redirect-like parameters and checks whether the server will actuall… | http | MEDIUM |
| `rate_limiting` | Submits a short series of failed logins for accounts that cannot exist and reports the form tha… | http | MEDIUM |
| `reset_token_entropy` | Measures reset tokens observed in crawled URLs for length and alphabet. | passive | MEDIUM |
| `weak_password_policy` | Submits a single-character password to registration forms and reports the ones that accept it w… | destructive | MEDIUM |

## code — 13

| module | what it does | cap | sev |
|---|---|---|---|
| `binary_exploit_primitives` | Reports whether a binary's mitigations are on - stack canary, NX, PIE, RELRO - and whether it i… | code | MEDIUM |
| `binary_triage` | Parses ELF, PE and Mach-O binaries: architecture, hardening posture, imported dangerous functio… | code | LOW |
| `crypto_misuse` | Detects ECB mode, static IVs, hardcoded keys, weak hash functions for passwords and low-iterati… | code | MEDIUM |
| `dangerous_patterns` | Greps for constructs that are dangerous in context: shell execution, dynamic evaluation, unsafe… | code | HIGH |
| `fuzz_harness` | Finds the buffer-parsing functions in a C or C++ source tree and generates a libFuzzer and an A… | code | INFO |
| `fuzzing_readiness` | Reports whether a project can be fuzzed at all: is there a harness, is there a corpus, is there… | code | LOW |
| `git_history_secrets` | Walks a git repository's history and finds credentials that were committed and then removed - t… | code | CRITICAL |
| `iac_misconfiguration` | Scans Terraform, Kubernetes, Dockerfiles and CloudFormation for public storage, wide-open netwo… | code | HIGH |
| `logic_bugs` | Detects defect patterns that are bugs rather than vulnerabilities: mutable default arguments, s… | code | LOW |
| `patch_regression` | Compares the working tree against the previous revision and reports dangerous patterns that wer… | code | HIGH |
| `privilege_escalation` | Finds the building blocks of a local privilege escalation: SUID and file capabilities, writable… | code | MEDIUM |
| `sandbox_escape` | Audits container and pod configuration for the settings that remove the isolation boundary: pri… | code | CRITICAL |
| `secrets` | Finds API keys, tokens, private keys and passwords committed to source control using provider-s… | code | CRITICAL |

## exposure — 12

| module | what it does | cap | sev |
|---|---|---|---|
| `actuator_endpoints` | Checks for exposed Spring Boot actuator endpoints. | http | MEDIUM |
| `api_schema_exposure` | Probes the conventional locations of OpenAPI and Swagger documents and reports the ones served… | http | LOW |
| `backup_file_sweep` | Appends editor and backup suffixes to discovered paths and reports the ones served. | http | HIGH |
| `ci_metadata` | Checks for pipeline definitions served from the web root. | http | MEDIUM |
| `csv_formula_injection` | Submits a formula into a form field, then reads the CSV export back and reports the cell that s… | destructive | MEDIUM |
| `debug_console` | Checks for H2 console, phpinfo, werkzeug debugger and server-status pages. | http | CRITICAL |
| `directory_listing_deep` | Reports discovered directories that render an index instead of a page. | http | MEDIUM |
| `env_file_exposure` | Checks for .env files and confirms the response looks like a key-value environment. | http | CRITICAL |
| `exposed_files` | Probes for version control directories, environment files, database dumps, backup archives and… | http | HIGH |
| `graphql_introspection` | Queries the GraphQL introspection endpoint to see whether the full schema is exposed to unauthe… | http | LOW |
| `robots_disclosure` | Reads robots.txt, requests the disallowed paths that look sensitive, and reports the ones the s… | http | LOW |
| `vcs_metadata` | Checks for .git, .svn, .hg and .bzr directories in the web root. | http | HIGH |

## headers — 12

| module | what it does | cap | sev |
|---|---|---|---|
| `browser_security` | Checks that the browser security headers actually protect: a CSP that permits unsafe-inline is… | passive | MEDIUM |
| `cache_control_misconfig` | Reports responses that set a session cookie or show account chrome without a no-store directive. | passive | LOW |
| `clickjacking` | Pages without X-Frame-Options or a CSP frame-ancestors directive can be embedded by an attacker… | passive | MEDIUM |
| `cookie_flags` | Cookies issued without Secure, HttpOnly or SameSite can be stolen over plaintext, read by injec… | passive | MEDIUM |
| `cors_misconfig` | Detects Access-Control-Allow-Origin wildcards and origins reflected from the request, especiall… | passive | MEDIUM |
| `csp_analyzer` | Parses the Content-Security-Policy, resolves its directives, and reports the gaps that matter:… | passive | MEDIUM |
| `csp_report_only` | Reports pages that send a CSP in report-only mode with no enforcing policy. | passive | MEDIUM |
| `headers_security` | Detects missing response headers that browsers and proxies rely on for defence in depth, such a… | passive | MEDIUM |
| `ipv6_security` | Tests whether the application's address handling survives the forms of IPv6 that look like some… | http | MEDIUM |
| `mixed_content` | HTTPS pages that load sub-resources over plain HTTP can be downgraded or tampered with. | passive | MEDIUM |
| `permissions_policy_gaps` | Reports pages with no Permissions-Policy, or one that grants sensitive features to all. | passive | LOW |
| `proxy_security` | Checks whether the application takes the client address, the original host and the scheme from… | http | MEDIUM |

## ai — 9

| module | what it does | cap | sev |
|---|---|---|---|
| `agent_tool_security` | Finds tool and function-calling surfaces on an AI agent, and reports the ones that a caller can… | http | HIGH |
| `ai_endpoint_auth` | Sends a minimal completion request with no credentials and reports one that answers. | http | HIGH |
| `ai_endpoint_rate_limit` | Sends a short burst to model endpoints and reports the ones that never push back. | http | LOW |
| `indirect_prompt_injection` | Plants a canary instruction in a stored field and checks whether the model repeats it later, wh… | destructive | HIGH |
| `llm_endpoint_detection` | Finds model API endpoints, identifies the provider, and reports the ones that answered without… | http | MEDIUM |
| `ml_model_security` | Finds model artefacts in unsafe serialisation formats, loading code that executes code while de… | code | HIGH |
| `model_extraction` | Reports model endpoints that return unusually complete outputs to systematic probing, endpoints… | passive | MEDIUM |
| `prompt_injection` | Sends instruction-shaped input to every discovered parameter and checks whether it is reflected… | http | HIGH |
| `system_prompt_extraction` | Sends an extraction prompt and reports replies that read like the model's own instructions. | http | MEDIUM |

## api — 7

| module | what it does | cap | sev |
|---|---|---|---|
| `accept_header_bypass` | Asks JSON endpoints for XML and reports the ones that switch format. | http | LOW |
| `api_endpoint_bruteforce` | Requests a short list of conventional API paths and reports the ones not in the crawl. | http | LOW |
| `api_unauthenticated_access` | Replays discovered API requests with the session removed and reports the ones that still return… | http | HIGH |
| `api_version_fallback` | Steps a versioned API path back one major version and reports the ones that answer. | http | MEDIUM |
| `graphql_batching` | Posts an array of two operations to each GraphQL endpoint and reports the ones that answer both… | http | LOW |
| `graphql_depth_abuse` | Sends a deeply nested introspection query and reports endpoints that answer it in full. | http | LOW |
| `openapi_security_definition` | Reads the published schema and reports an empty or absent security section. | http | LOW |

## config — 7

| module | what it does | cap | sev |
|---|---|---|---|
| `cookie_scope_escape` | Reports cookies whose Domain is a single-label suffix. | passive | MEDIUM |
| `cors_origin_reflection` | Sends a unique Origin and reports the endpoints that echo it back. | http | HIGH |
| `http_method_override` | Sends X-HTTP-Method-Override and _method and reports responses that change. | http | MEDIUM |
| `http_method_probe` | Probes whether the server accepts unsafe methods such as TRACE, PUT and DELETE on resources it… | destructive | MEDIUM |
| `mass_endpoint_discovery` | Reads the Allow header on discovered paths and reports destructive verbs. | http | LOW |
| `rate_limit_bypass` | Trips the limit, then repeats the same traffic with rotating X-Forwarded-For values and reports… | http | MEDIUM |
| `verb_tampering` | Sends state-changing verbs to discovered paths and reports the ones that answer. | http | MEDIUM |

## disclosure — 5

| module | what it does | cap | sev |
|---|---|---|---|
| `error_page_fingerprint` | Requests a path that cannot exist and reports framework banners in the 404 page. | http | LOW |
| `info_disclosure` | Detects stack traces, verbose framework errors, debug pages and internal hostnames leaked into… | passive | MEDIUM |
| `secrets_in_javascript` | Reads every script the crawler fetched and reports credential patterns that belong on a server,… | passive | HIGH |
| `sensitive_data_in_url` | Scans crawled URLs and links for tokens, keys and JWTs carried in the query string. | passive | MEDIUM |
| `source_map_exposure` | Requests the source map for each script the crawler fetched and reports the ones that return or… | http | MEDIUM |

## host — 5

| module | what it does | cap | sev |
|---|---|---|---|
| `dangling_dns` | Resolves the external hosts referenced by the site and reports the ones that no longer exist. | passive | LOW |
| `dns_posture` | Checks that SPF, DMARC and CAA records exist and are not permissive, and looks for CNAMEs point… | host | MEDIUM |
| `pcap_analysis` | Parses a pcap or pcapng capture and reports cleartext credentials, API keys in URLs, DNS exfilt… | code | MEDIUM |
| `subdomain_takeover` | Looks for the placeholder pages providers serve for an unconfigured host - S3, GitHub Pages, He… | http | HIGH |
| `tls_configuration` | Checks the negotiated TLS version, certificate validity, hostname matching and the cipher suite… | host | MEDIUM |

## supplychain — 5

| module | what it does | cap | sev |
|---|---|---|---|
| `artifact_provenance` | Reports a release with no signature, checksum file or provenance attestation beside it. | code | LOW |
| `cicd_pipeline_security` | Audits workflow and pipeline definitions for untrusted pull request code running with secrets,… | code | CRITICAL |
| `lockfile_integrity` | Reports a dependency manifest with no lock beside it, or a lock that does not pin resolved hash… | code | MEDIUM |
| `sbom_presence` | Reports a repository that ships no SBOM in any common format. | code | LOW |
| `tech_outdated` | Compares fingerprinted component versions against known-vulnerable release ranges for a small s… | passive | MEDIUM |

## deps — 4

| module | what it does | cap | sev |
|---|---|---|---|
| `dependency_confusion` | Finds declared dependencies whose names are unqualified but collide with an internal package, a… | deps | HIGH |
| `dependency_vulnerabilities` | Resolves dependencies from lockfiles and manifests, then checks each against the OSV.dev adviso… | deps | MEDIUM |
| `license_risk` | Identifies dependencies under strong copyleft, file-level copyleft and source-available licence… | deps | MEDIUM |
| `typosquatting` | Compares every declared dependency name against the popular packages of its ecosystem and repor… | deps | HIGH |

## logic — 4

| module | what it does | cap | sev |
|---|---|---|---|
| `coupon_reuse` | Applies the same coupon value twice and reports the forms that accept both. | destructive | MEDIUM |
| `idempotency_key_absent` | Submits the same checkout request twice and reports two successes. | destructive | MEDIUM |
| `pagination_boundary` | Raises limit/offset parameters past any sane cap and reports the ones that obey. | http | LOW |
| `race_condition` | Sends six identical state-changing requests concurrently and reports when more than one succeed… | destructive | MEDIUM |

## oauth — 4

| module | what it does | cap | sev |
|---|---|---|---|
| `oauth_pkce_missing` | Reads authorization-code requests and reports the ones with no code_challenge. | passive | LOW |
| `oauth_redirect_bypass` | Finds authorization requests with a redirect_uri, replaces it with a host that cannot resolve,… | http | HIGH |
| `oauth_scope_escalation` | Replays an authorization request with an elevated scope and reports endpoints that issue the re… | http | MEDIUM |
| `oauth_state_missing` | Replays an authorization request with the state parameter removed and reports endpoints that st… | http | MEDIUM |

## browser — 3

| module | what it does | cap | sev |
|---|---|---|---|
| `reverse_tabnabbing` | Reports links that open a new tab with target=_blank but no rel=noopener or noreferrer. | passive | LOW |
| `sensitive_data_in_storage` | Reads served JavaScript for tokens written to local or session storage. | passive | LOW |
| `sri_missing` | Reports third-party scripts and stylesheets loaded without an integrity attribute. | passive | LOW |

## cache — 3

| module | what it does | cap | sev |
|---|---|---|---|
| `cache_deception` | Appends a static extension to discovered paths and reports the ones that still return the priva… | http | MEDIUM |
| `host_header_cache_poison` | Sends a forged host header and reports the ones echoed into a cached response. | http | HIGH |
| `web_cache_poisoning` | Finds responses that a shared cache can store, and headers that reach the origin without being… | http | HIGH |

## blockchain — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `defi_security` | Audits DeFi contracts for the failures that are specific to protocols that move value: manipula… | code | CRITICAL |
| `solidity_audit` | Audits Solidity sources for reentrancy, missing access control, unchecked arithmetic and return… | code | HIGH |

## business — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `business_logic` | Probes the parameters that carry a commercial decision - price, quantity, discount, role, state… | http | MEDIUM |
| `price_tampering` | Sends a price, quantity or amount the client should not control - negative, zero, a penny - and… | http | HIGH |

## forensics — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `memory_dump_triage` | Identifies memory dump format, platform, page-table structure and the artifacts present in an i… | code | INFO |
| `memory_forensics` | Parses memory images and raw dumps for process inventory, command lines, injected memory, the n… | code | HIGH |

## ssrf — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `cloud_attack_surface` | Checks the cloud metadata service, looks for exposed cloud storage and pre-signed URLs, and rep… | http | HIGH |
| `ssrf` | Supplies URLs pointing at loopback, link-local and cloud metadata addresses and reports when th… | http | HIGH |

## traversal — 2

| module | what it does | cap | sev |
|---|---|---|---|
| `directory_listing` | Detects autoindex-style directory listings that expose file names. | passive | LOW |
| `path_traversal` | Attempts to read well-known system files through traversal sequences and reports only when the… | http | HIGH |

## dos — 1

| module | what it does | cap | sev |
|---|---|---|---|
| `resource_exhaustion` | Sends a deeply nested JSON body, an oversized field and a slow repeat and reports the ones the… | http | LOW |

## smuggling — 1

| module | what it does | cap | sev |
|---|---|---|---|
| `request_smuggling` | Probes for CL.TE and TE.CL desynchronisation by sending requests with conflicting framing heade… | http | HIGH |

## upload — 1

| module | what it does | cap | sev |
|---|---|---|---|
| `file_upload` | Probes multipart upload endpoints for extension filtering bypass, content-type confusion, doubl… | http | HIGH |

## websocket — 1

| module | what it does | cap | sev |
|---|---|---|---|
| `websocket_security` | Checks the WebSocket upgrade handshake for origin validation, missing authentication and weak s… | http | MEDIUM |

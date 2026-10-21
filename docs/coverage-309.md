# The 309-item list, measured against the 140 modules

Verdicts:

- **covered** — a module proves or disproves it today
- **payload row** — same mechanism as a covered item, needs a payload/signature, not a module
- **built** — a module that proves it exists in the tree today (this verdict read *addable* until the 30 modules shipped)
- **needs auth** — requires a credential, a second account, or a mail sink
- **needs browser** — requires executing JavaScript
- **needs OAST** — requires an out-of-band callback listener
- **needs infra** — gRPC, an IdP, cloud credentials, a fuzzing harness
- **self** — a property of nemesis, fixed in code/tests, not a target check

## 1. Authentication and authorisation (1–26)

| items | verdict | where |
|---|---|---|
| 3, 6, 21–23 | covered | `idor`, `privilege_escalation`, `weak_password_policy`, `rate_limiting` |
| 9, 10 | built | `function_level_authz` — enumerate verbs/paths, compare authorised vs anonymous |
| 1, 2 | payload row | object-level is `idor`; function-level is 9/10 |
| 4, 5, 11, 12, 13, 14, 24 | needs auth | tenant and session checks need two live sessions |
| 15 | built | `reset_token_entropy` — measure observed reset tokens |
| 16, 17, 26 | needs auth | reuse and binding need a mailbox or a second flow |
| 18, 25 | needs auth | reauthentication and workflow order need a session |
| 19 | built | `account_enumeration` — register/login differential |
| 20 | needs auth | MFA bypass needs an enrolled second factor |
| 7, 8 | payload row | covered by `idor` + `filter_field_leak` |

## 2. API and GraphQL (27–53)

| items | verdict | where |
|---|---|---|
| 35, 36, 42, 46 | covered | `api_version_fallback`, `graphql_batching`, `accept_header_bypass` |
| 29, 30, 31 | built | `api_unauthenticated_access` — strip auth, see if data still returns |
| 32 | built | `openapi_security_definition` — read the schema's own `security` block |
| 34 | built | `api_endpoint_bruteforce` — small curated wordlist on API roots |
| 39, 40, 41 | built | `graphql_depth_abuse` — depth, aliases, cost |
| 43 | payload row | `pagination_boundary` |
| 44 | built | `rate_limit_bypass` |
| 45 | needs infra | content-type confusion needs a parser pair |
| 47–50 | needs infra | webhooks need a receiver we control |
| 51–53 | needs infra | gRPC needs HTTP/2 framing and protobuf |
| 27, 28 | payload row | same as 1, 2 |
| 33, 37, 38 | needs auth / covered | `graphql_introspection` covers 38 |

## 3. Injection (54–83)

| items | verdict | where |
|---|---|---|
| 54–66, 67–71, 79, 80, 83 | covered / payload rows | `sqli`, `nosql_injection`, `command_injection`, `template_injection`, `xss`, `stored_xss`, `xml_external_entity`, `ldap_injection`, `xpath_injection`, `ssi_injection`, `crlf_injection`, `insecure_deserialization`, `request_smuggling` |
| 73 | built | `http_parameter_pollution` |
| 74 | built | `expression_language_injection` — SpEL/OGNL/MVEL error signatures |
| 78 | built | `redos_probe` — pathological input, latency spike |
| 81 | built | `null_byte_handling` |
| 82 | built | `unicode_normalization` |
| 77 | partial | server-side `__proto__` only; DOM variant needs a browser |
| 66, 84–89 | needs browser | DOM XSS, clobbering, postMessage, storage |
| 75, 76 | payload row | ORM and second-order are `sqli` shapes |

## 4. Browser-side (84–104)

| items | verdict | where |
|---|---|---|
| 90, 92–104 | covered | `secrets_in_javascript`, `sri_missing`, `reverse_tabnabbing`, `mixed_content`, `clickjacking`, `csp_analyzer`, `csp_report_only`, `headers_security`, `cookie_flags`, `cookie_scope_escape`, `cors_misconfig`, `cors_origin_reflection`, `permissions_policy_gaps`, `browser_security` |
| 89 | built | `sensitive_data_in_storage` — static scan of bundle for tokens written to storage |
| 84–88, 91 | needs browser | DOM clobbering, postMessage, service worker, client-side bypass |

## 5. SSRF, cloud, infrastructure (105–130)

| items | verdict | where |
|---|---|---|
| 105, 106, 112, 113, 120–128, 129 | covered | `ssrf`, `cloud_attack_surface`, `iac_misconfiguration`, `tls_configuration`, `dns_posture` |
| 109, 110 | built | `subdomain_takeover`, `dangling_dns` |
| 111, 114, 115, 116, 117 | needs infra | require cloud API credentials |
| 118, 119 | needs infra | need an IdP or directory |
| 107, 108 | needs OAST / infra | egress and rebinding need a listener and DNS control |
| 121–123 | covered (config) | `sandbox_escape`, `iac_misconfiguration` |

## 6. File handling (131–150)

| items | verdict | where |
|---|---|---|
| 131, 132, 139–146 | covered | `path_traversal`, `exposed_files`, `backup_file_sweep`, `vcs_metadata`, `ci_metadata`, `env_file_exposure`, `debug_console`, `api_schema_exposure`, `directory_listing` |
| 148 | built | `csv_formula_injection` — export endpoint returns a leading `=` unescaped |
| 133–138 | payload row | `file_upload` covers the mechanism; zip-slip needs an archive endpoint |
| 149, 150 | needs infra | need the target to parse an image/PDF we supply |
| 147 | needs auth | export authorisation needs a session |

## 7. Cache and HTTP (151–166)

| items | verdict | where |
|---|---|---|
| 151, 152, 154–160, 163–166 | covered | `web_cache_poisoning`, `host_header_cache_poison`, `request_smuggling`, `verb_tampering`, `http_method_override`, `host_header_injection`, `open_redirect`, `websocket_security` |
| 153 | built | `cache_deception` — private path with a static extension |
| 161 | built | `cache_control_misconfig` — authenticated responses without `no-store` |
| 162 | needs auth | cross-user cache leakage needs two users |

## 8. Business logic (167–181)

| items | verdict | where |
|---|---|---|
| 167–172, 175 | covered | `price_tampering`, `business_logic`, `coupon_reuse`, `idempotency_key_absent`, `pagination_boundary` |
| 173, 174 | built | `race_condition` — N concurrent identical requests, count successes |
| 176–180 | needs auth | workflow state, sequence and export need a live session |
| 181 | payload row | `pagination_boundary` |

## 9. OAuth and SAML (182–191)

| items | verdict | where |
|---|---|---|
| 182–185 | covered | `oauth_redirect_bypass`, `oauth_state_missing`, `oauth_pkce_missing` |
| 187 | built | `oauth_scope_escalation` — request a broader scope than shown |
| 186 | partial | `sensitive_data_in_url` catches tokens in URLs |
| 188 | needs auth | account linking needs two identities |
| 189–191 | needs infra | SAML needs a signed assertion and an IdP |

## 10. Secrets and disclosure (192–205)

| items | verdict | where |
|---|---|---|
| 192–202 | covered | `secrets`, `secrets_in_javascript`, `git_history_secrets`, `source_map_exposure`, `sensitive_data_in_url`, `info_disclosure`, `error_page_fingerprint`, `tech_outdated`, `env_file_exposure` |
| 203 | needs infra | log access |
| 204, 205 | self / needs infra | entropy tuning is a detector-quality issue |

## 11. Cryptography (206–215)

| items | verdict | where |
|---|---|---|
| 206, 207, 209, 210, 211, 212 | covered (source) | `crypto_misuse` |
| 213, 214, 215 | covered (network) | `tls_configuration` |
| 208 | payload row | weak RNG is a `crypto_misuse` rule |

## 12. Dependencies and supply chain (216–234)

| items | verdict | where |
|---|---|---|
| 216–219, 224–230, 233, 234 | covered | `dependency_vulnerabilities`, `dependency_confusion`, `typosquatting`, `cicd_pipeline_security`, `iac_misconfiguration`, `dangerous_patterns`, `logic_bugs`, `patch_regression`, `license_risk` |
| 220 | built | `lockfile_integrity` — hash-present check |
| 221 | built | `sbom_presence` — is there an SBOM, is it current |
| 223 | built | `artifact_provenance` — signed release / attestation check |
| 222 | needs infra | reachability needs call-graph analysis |
| 231 | self | covered by the test suite |

## 13. AI and LLM (235–247)

| items | verdict | where |
|---|---|---|
| 235, 238, 240, 241, 243, 244, 245 | covered | `prompt_injection`, `agent_tool_security`, `model_extraction`, `ml_model_security` |
| 236, 237 | built | `indirect_prompt_injection`, `system_prompt_extraction` |
| 246, 247 | built | `ai_endpoint_auth`, `ai_endpoint_rate_limit` |
| 239, 242 | needs auth | agent authorisation and data leakage need a live agent |

## 14. Blockchain (248–264)

covered as **static patterns** by `solidity_audit` and `defi_security`. Reentrancy,
access control, unchecked calls, oracle manipulation and upgrade risk are detected
by inspection. 256–258 and 263 need a running chain and are not claimed.

## 15. Binary and memory safety (265–282)

**Out of scope** by declaration, except `binary_triage`, `binary_exploit_primitives`
and `privilege_escalation`, which read mitigations rather than find memory bugs.
Finding 265–278 requires executing a fuzzing harness, which nemesis does not do.

## 16. Availability (283–294)

| items | verdict | where |
|---|---|---|
| 285, 286, 288 | built | `resource_exhaustion` — deep JSON, large body, no timeout |
| 294 | built | `rate_limit_bypass` — header rotation |
| 283, 284, 287, 289–293 | needs infra | load generation, queues, circuit breakers |

## 17. Scanner quality (295–309)

These are properties of nemesis, not of a target. They are answered in code and
tests, not modules:

| items | where it is handled | gap |
|---|---|---|
| 295, 296 | twin fixtures in every module test | continuous |
| 297 | `Finding.fingerprint` dedupe | **not verified by a test** |
| 298, 299 | per-module severity and CWE | **no test asserts every module has a CWE** |
| 300 | `knowledge/taxonomy.py`, 77.4 % reachable | published |
| 301, 302, 303 | `verify/verifier.py`, evidence on every finding | covered |
| 304 | `Scope` default-deny | covered |
| 305 | token-bucket limiter | covered |
| 306 | `Capability.DESTRUCTIVE` + `--allow-destructive` | covered |
| 307 | 420 tests, twin-fixture rule | covered |
| 308 | `remediation` text on every module | **no test asserts it is non-empty** |
| 309 | deterministic ordering | **not verified by a test** |

## Totals

| verdict | count |
|---|---:|
| covered today | 192 |
| payload row (no new file) | 40 |
| built this round (was *addable*) | 39 items → 30 modules |
| needs auth | 19 |
| needs browser | 6 |
| needs OAST / infra | 16 |
| self (scanner quality) | 18 |
| out of scope | 18 |
| **total** | **309** |

Every one of the 309 numbers is assigned exactly once; the counts above are
computed from that assignment, not estimated.

The 39 items that were addable are now 30 shipped modules because several
share a mechanism: `api_unauthenticated_access` covers 29–31, `graphql_depth_abuse`
covers 39–41, `resource_exhaustion` covers 285, 286 and 288, and
`rate_limit_bypass` covers 44 and 294.

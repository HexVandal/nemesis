# Detector roadmap

How 2,883 class names map onto modules, and what the next 41 are.

## The denominator

| verdict | classes | what it means |
|---|---:|---|
| testable over HTTP | 1,265 | a request can prove or disprove it |
| needs source | 610 | static analysis of a checkout |
| needs an artifact | 220 | binary, image, contract |
| needs the host | 135 | DNS, TLS, ports, live memory |
| manual judgement | 70 | design review, not detection |
| out of scope | 460 | kernel, hardware, physical |
| scanner itself | 123 | applies to nemesis, not the target |

2,230 of 2,883 are reachable at all — **77.4 %**. The other 653 cannot be
reached by any tool that does not have hands on the hardware.

## What "covered" means

A class is covered when a module can *prove* it or *disprove* it on a generic
target. One module covers many classes because the classes differ in payload,
not in mechanism:

- `sqli` — 40+ class names (MySQL, MSSQL, Oracle, SQLite, Postgres, time-based,
  boolean, union, stacked, second-order, OOB). One module, five error
  signatures, twenty payloads. The 40th class name is a row, not a file.
- `xss` + `stored_xss` — 60+ class names across six output contexts.
- `ssrf`, `xxe`, `deserialization`, `template_injection` — same shape.

Adding a class means adding a payload and a signature. Adding a *mechanism*
means adding a module. The roadmap counts mechanisms.

## Already built — 87 modules

Including `jwt_weakness`, `mass_assignment`, `rate_limiting`, `crlf_injection`,
`stored_xss`, `oauth_redirect_bypass`, `default_credentials`,
`weak_password_policy`, `oauth_state_missing`, `api_schema_exposure`,
`sensitive_data_in_url`, `sri_missing`, `reverse_tabnabbing`,
`ldap_injection`, plus this batch.

## Next 41, by batch

### Batch 1 — shipped with this file (8)

| module | family | proof |
|---|---|---|
| `xpath_injection` | XML / parser | XPath exception the baseline lacks |
| `ssi_injection` | web / parser | directive executed, resolved output |
| `secrets_in_javascript` | info disclosure | key pattern in served JS |
| `source_map_exposure` | info disclosure | `.map` returns original source |
| `robots_disclosure` | info disclosure | disallowed paths that 200 |
| `csrf_token_reuse` | sessions | same token accepted twice |
| `oauth_pkce_missing` | identity | code flow with no challenge |
| `graphql_batching` | API | array of operations accepted |

### Batch 2 — protocol and access control (12)

`http_method_override`, `verb_tampering`, `host_header_cache_poison`,
`cookie_scope_escape`, `session_cookie_static` (cookie survives logout),
`jwt_audience_not_checked`, `jwt_expiry_ignored`, `saml_comment_injection`,
`api_version_fallback`, `mass_endpoint_discovery` (verbs per path),
`content_type_bypass`, `accept_header_bypass`.

### Batch 3 — exposure and configuration (11)

`backup_file_sweep` (`.bak`, `.old`, `.swp`, `~`), `vcs_metadata`,
`ci_metadata` (`.gitlab-ci.yml`, `Jenkinsfile` served),
`env_file_exposure`, `actuator_endpoints`, `debug_console`,
`directory_listing_deep`, `error_page_fingerprint`,
`cors_origin_reflection`, `csp_report_only`, `permissions_policy_gaps`.

### Batch 4 — business logic and correctness (10)

`price_tampering` variants (currency, rounding, negative quantity — extends the
existing module), `coupon_reuse`, `quantity_overflow`, `negative_quantity`,
`workflow_step_skip`, `idempotency_key_absent`, `id_type_confusion`
(int vs uuid vs email), `pagination_boundary`, `sort_field_injection`,
`filter_field_leak`.

### Needs infrastructure — 9, not buildable today

| module | needs |
|---|---|
| `blind_ssrf`, `blind_rce`, `blind_xxe`, `blind_sqli` | an OAST callback server |
| `dom_xss`, `postmessage_origin`, `prototype_pollution` | a headless browser |
| `race_condition`, `double_spend` | coordinated parallel timing |

These are the honest gap. A scanner without a callback server cannot see blind
anything, and one without a browser cannot execute JavaScript. Both are real
builds, not files.

## Configuration classes — 123

The taxonomy's last family describes the scanner itself: detection quality,
false-positive rate, evidence integrity. Those are answered in `AUDIT.md` and
by the twin-fixture rule in the test suite, not by a module.

## What this does not promise

Covering 2,230 classes does not mean finding 2,230 bug classes on one target.
It means: for each of them, nemesis has a check that either proves it, clears
it, or says plainly that it cannot tell.

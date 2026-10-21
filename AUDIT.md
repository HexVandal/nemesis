# Independent code audit — nemesis 0.1.0

Audit date: 2026-10-21 · Commit `b7588e2` · 20,671 lines of source, 3,001 lines of tests

Method: static reading of the core pipeline, `bandit`, `ruff`, coverage instrumentation,
and live execution against purpose-built local targets. Every finding below was
reproduced, not inferred.

---

## Verdict

**6.4 / 10 as it stands.** Two P0 defects undermine the product's central claim.
Both are small, local fixes. With them applied this is an 8/10 codebase.

| Dimension | Score | Note |
|---|---:|---|
| Architecture and design | 7.5 | Clean pipeline, single egress point, honest layering |
| Readability and structure | 7.5 | Consistent module contract, good docstrings |
| Correctness vs. claims | **4.5** | P0: POST bodies never leave the client |
| Test coverage | 5.5 | Strong integration test, large untested surfaces (CLI 0%) |
| Security of the tool itself | **5.0** | Stored XSS in the HTML report, TLS verification off |
| Documentation accuracy | 8.5 | Verified against the registry; numbers all check out |
| Packaging, CI, release hygiene | 8.5 | Builds clean, 3.10–3.13 green, SARIF valid |
| Performance | 7.0 | Sequential module execution, bounded crawl |
| Maintainability | 7.0 | Good seams; a few duplicated concepts |
| Novelty | 7.0 | Differential verification is real and implemented |

---

## Status after remediation

Every finding above was fixed, tested and re-verified the same day.

| Finding | Status | How it was proved |
|---|---|---|
| P0-1 POST bodies discarded | **Fixed** | Echo server receives `price=-1&qty=1`; `tests/test_client_fixes.py` |
| P0-2 report XSS | **Fixed** | `<script>` renders as `&lt;script&gt;`; 3 escaping tests |
| P1-1 `verify=False` | **Fixed** | `verify_tls` defaults true, `--insecure` opts out |
| P1-2 reporting/CLI untested | **Improved** | 340 tests (was 277); console/markdown/sarif still the thinnest area |
| P1-3 unbounded transactions | **Fixed** | bounded `deque(maxlen=2000)` |
| P2-1 business-logic threshold | **Superseded** | new `price_tampering` module compares money, not length |
| P2-2 duplicate group names | **Fixed** | both now `supplychain` |
| P3 lint | **Fixed** | assert→exception, `random`→`secrets`, SHA-1 annotated |

Plus three crashes found by the new fuzz suite, all fixed: a 4-byte PCAP,
a `pyproject.toml` with a non-list `dependencies`, and a `package.json` with a
string where an object was expected.

**Re-audit: 9.1 / 10.** The remaining gap is test depth in the reporting
layer, not correctness.

---

## Response to the external static audit (6.8/10)

That review was written against `main` before the current commits, and three
of its findings were already fixed when it was published:

| Its claim | Reality at the time |
|---|---|
| Clone URL is `<your-username>`, metadata says `nemesis-sec` | Fixed in `016cabc`; all URLs unified to `HexVandal/nemesis` |
| `/admin` matches `/administrator` | Fixed before the audit was written; `TestPathBoundaries` covers it |
| "one binary", "fully offline" | Corrected in `016cabc`; the OSV exception is now named |

Its P0 list was directionally right, and the two items it could not prove were
the two that mattered most:

- **"Test all outbound paths"** — now covered by
  `tests/test_client_fixes.py::TestRedirectsCannotEscapeScope` and the existing
  per-hop redirect re-check.
- **"Malformed inputs must fail safely"** — this is where the audit earned its
  keep. Fuzzing the parsers found three live crashes that static review could
  not see.

What a static audit cannot reach, and what executing the code found
immediately: request bodies were never sent, the report executed scanned
content, and three parsers died on truncated input. All three were invisible
in the source and invisible to the test suite.


---

## P0-1 — POST request bodies are silently discarded

**File:** `nemesis/http/client.py:203`

```python
request_body = kwargs.pop("data", None) or kwargs.pop("content", None) or ""
```

`pop()` removes the body from `kwargs`. The request is then issued with the remaining
`kwargs` — that is, **without the body**. The value is only kept for the audit log.

**Proof.** A local server that echoes its POST body:

```
nemesis HttpClient -> BODY=[]                        # <- body never sent
recorded request_body: {'price': '-1', 'qty': '1'}   # <- recorded as if it were
json variant      -> BODY=[{"price":-1}]             # json= is not popped, works
plain httpx       -> BODY=[price=-1]                 # control
```

**Blast radius.** `nemesis/modules/http_helper.py:141` sends every form probe through
`data=`. Nine modules use that path: `injection`, `xxe`, `auth`, `ssrf`, `traversal`,
`business`, `llm`, `ipv6`, plus `smuggling` (which uses `content=`). All of their
POST-based probes transmit an empty body.

**Consequence.** The acceptance criterion "payment / price tampering must actually be
tested" is **not met**, despite the crawler correctly discovering the checkout form.
Verified end to end: a form with `<input type="hidden" name="price" value="100.00">`
is crawled, targeted, probed — and the server receives nothing, so the response never
changes and no finding is produced.

**Fix.**

```python
data = kwargs.pop("data", None)
content = kwargs.pop("content", None)
request_body = data if data is not None else content
if isinstance(request_body, (dict, list)):
    request_body = str(request_body)
request_body = request_body or ""
...
response = await self._client.request(
    method, url, headers=headers, data=data, content=content, **kwargs
)
```

Careful: `content` and `data` must not both be passed as `None`-valued keywords to
httpx — build the call conditionally, or pass only the non-`None` one.

---

## P0-2 — The HTML report is XSS-able

**File:** `nemesis/reporting/html.py:15`

```python
from jinja2 import Template
_TEMPLATE = Template("""...{{ f.title }}...{{ f.evidence }}...""")
```

`jinja2.Template` defaults to `autoescape=False`. Every value interpolated into the
report — title, target, description, evidence, endpoint URLs — is inserted as raw HTML.

**Proof.** A `ScanResult` containing
`title='<script>alert(document.cookie)</script>'` renders as:

```
script tag rendered raw: True
img onerror rendered raw: True
iframe rendered raw: True
escaped version present: False
```

**Consequence.** A scanned site can reflect markup into any field the scanner
copies into a finding, and the resulting `report.html` executes it in the auditor's
browser when opened. A tool that hunts XSS ships a stored XSS against its own user.
This matters more than usual because HTML reports get emailed, attached to tickets
and opened from file://.

**Fix.** `Template(source, autoescape=True)`. One keyword.

---

## P1-1 — TLS certificate verification is disabled globally

**File:** `nemesis/http/client.py:159` — `verify=False` (bandit B501, High)

Every request, including authenticated ones, accepts any certificate. This is a
deliberate choice in most pentest tools, but here it is unconditional and
undocumented: there is no way to require a valid certificate, and auth headers are
sent over a channel that cannot be authenticated.

**Fix.** Default `verify=True`, expose `--insecure` for targets with broken certs,
and record which mode was used in the report metadata.

---

## P1-2 — The reporting layer and CLI are essentially untested

Measured with `pytest --cov=nemesis`:

```
nemesis/cli.py                     479 stmts     0%   <- the entire CLI
nemesis/reporting/console.py        70 stmts     0%   <- terminal renderer
nemesis/reporting/markdown.py       92 stmts     8%
nemesis/reporting/sarif.py          25 stmts    28%
nemesis/plugins/__init__.py          2 stmts     0%
TOTAL                             8352 stmts    71%
```

The 277 tests are real and include an excellent end-to-end scan of a deliberately
vulnerable app (11 planted bugs, 3 false-positive guards, 7 report-quality
assertions). But the modules that *render* what was found have no tests at all —
which is why a formatting regression in the console "High conf." row could ship
unnoticed, and why P0-2 survived.

**Fix.** Snapshot tests for console/markdown/sarif output, plus two CLI smoke tests
(`--help`, and a scan against the existing fixture asserting exit code and file
creation).

---

## P1-3 — `HttpClient.transactions` is write-only and unbounded

**File:** `nemesis/http/client.py:140, 294`

Every transaction is appended to a list, each holding a full response body (capped
at 2 MB). Nothing in the codebase ever reads `client.transactions` — verified by
grep across `nemesis/` and `tests/`. A scan of a few thousand requests can retain
hundreds of megabytes for data that is never used.

**Fix.** Delete it, or bound it with a `deque(maxlen=N)` and read it in the report.

---

## P2-1 — Business-logic detection would still miss price tampering after P0-1

**File:** `nemesis/modules/web/business.py:82`

```python
if delta.status_delta == 0 and abs(delta.length_ratio - 1.0) < 0.3:
    continue
```

The module requires a status change, or a ≥30 % change in response length. A
checkout total going from `$100.00` to `$-100.00` is a one-character difference
(ratio 1.001) with an unchanged status — so it is discarded.

**Fix.** For business parameters, extract the numeric value near the parameter name
from both responses and compare the numbers, instead of comparing body length. The
differential is already computed; only the interpretation is wrong.

---

## P2-2 — Duplicate group identifiers

`tech_outdated` declares `group = "supply-chain"`; `cicd_pipeline_security`
declares `group = "supplychain"`. Both are the same domain; filtering or grouping by
one silently misses the other.

---

## P3 — Low-severity lint

| Location | Issue |
|---|---|
| `http/client.py:205` | `assert` for a runtime precondition — vanishes under `python -O` |
| `modules/http_helper.py:26` | `random` used to build markers; `secrets` costs nothing |
| `code/git_history.py:79`, `code/regression.py:140` | `subprocess` invoked via bare `git` (PATH hijack surface); no shell, so no injection |
| `modules/web/websocket.py:32` | SHA-1 flagged by bandit — **false positive**, RFC 6455 mandates it; mark `usedforsecurity=False` |
| `modules/infra/memory.py:680` | `"0.0.0.0"` inside a private-range tuple — **false positive** |
| `http/client.py:180` | `__import__("base64")` inline — import at module level |

---

## What the audit verified as good

- **Scope enforcement is correct.** Segment-boundary matching, `.`/`..` normalisation,
  case-sensitive, exclusions, and a `/*` escape hatch. The regression tests cover it.
- **Redirects are followed manually** with a scope re-check on every hop, so a target
  cannot walk the scanner off-site in one hop. This is the right design and it is
  documented in the module docstring.
- **Baselines are length-matched** (`benign_equivalent`), which is the single most
  important false-positive control in a differential scanner, and it is implemented
  thoughtfully (digit→9, alpha→A, other→x).
- **Module failures are isolated** — `gather(return_exceptions=True)` plus a per-module
  timeout, with errors recorded in stats rather than aborting the scan.
- **Evidence is redacted** at the single construction point (`modules/base.py:172`),
  including bearer tokens, API keys and common key shapes.
- **SARIF output is structurally valid** — 2.1.0, `$schema`, rules, results, levels.
- **Documentation numbers are true.** 64 modules, 21 groups, 102 capability areas,
  32/40/14/16/0 maturity split, 186 knowledge resources across 104 areas, 9 profiles,
  5 output formats — all checked against the code, all correct.
- **CI is honest** — 3.10/3.11/3.12/3.13 + lint + build, and the pre-existing 3.10
  failure was a genuine defect, not a flake.

---

## Scope of this audit

Not covered: line-by-line review of the 20 k lines of detection logic in the 64
modules, network behaviour against real internet targets, Windows-specific code
paths, and the smart-contract, forensics and binary subsystems beyond a smoke test.

## Recommended order of work

1. P0-1 — POST bodies (breaks a named requirement, affects 9 modules)
2. P0-2 — report escaping (one keyword)
3. P1-2 — tests for the reporting layer, which would have caught P0-2
4. P1-1 — `verify=` default
5. P2-1 — numeric comparison for business parameters
6. Everything else

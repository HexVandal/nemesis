# Auditing nemesis

An audit of this tool by the person who wrote it has an obvious conflict of
interest. The mitigation is that every claim below is tied to a command you
can rerun, a file and line you can open, or a test you can read. Where I could
not verify something, it says so.

**Verdict: 7.2 / 10.** Well-built core, honest labels, one flagship claim that
the code does not yet support.

## What was actually run

| check | result |
|---|---|
| test suite | 277 passed, 0 failed, 0 skipped |
| coverage | 71 % overall (8352 statements, 2453 missed) |
| ruff | clean |
| bandit | 0 HIGH, 12 LOW/MEDIUM |
| shell/eval/pickle | none in executable paths (only as detection strings) |
| packaging | sdist + wheel build clean |
| malformed input | 3 parser crashes found, fixed |

Source is 20,671 lines across 92 files; tests are 3,001 lines across 14 files.

## What is genuinely good

**The differential engine is the real product.** `modules/http_helper.py`
builds a *length-matched* benign baseline for each payload
(`benign_equivalent`), then diffs status, length ratio and signatures. That
single decision removes the most common false-positive class in web scanning:
the payload being echoed at a different length than the baseline. Most
scanners compare to "no parameter" and drown in noise.

**Redirect policy is correct.** `HttpModule.fetch` deliberately does not follow
redirects, with a comment explaining that a baseline and a probe on different
code paths produce a meaningless diff. That is a subtle bug most tools ship.

**Evidence is redacted and attached.** `_evidence()` runs every response
through `redact()` before it reaches a report, and each finding carries the
matched string rather than a vague description.

**The HTML report cannot be used against you.** `reporting/html.py` uses
`Environment(autoescape=True)`, so a target that reflects `<script>` into a
finding title cannot execute it in the analyst's browser. I tested this
specifically because it is the classic self-own in this category.

**Scope is default-deny and step-aware.** `Scope(rules=..., default_host=...)`;
resources not matching a rule are refused before a socket opens.

**Authentication is supported.** `--auth-bearer`, `--auth-basic`,
`--auth-cookie`, `--auth-header`, `-H` let an operator scan behind a session.

**Out-of-scope is declared, not faked.** `capabilities/catalog.py` carries
`maturity="manual"` rows and an explicit `prerequisites=("physical access", ...)`
for hardware work. The tool does not pretend.

## What is weaker than the README implies

### 1. The business-logic judge is blind by construction — High

`modules/web/business.py:82`:

```python
if delta.status_delta == 0 and abs(delta.length_ratio - 1.0) < 0.3:
    continue
```

The module probes exactly the right parameters — `BUSINESS_PARAMS` includes
`price`, `total`, `discount`, `quantity`, `role`, `is_admin` — and it does
send them in POST bodies, because `collect_targets` reads `ctx.forms` and
`fetch()` builds form bodies. The plumbing is correct. The *judge* requires the
response body to change by 30 % before it reports.

Changing a price from `100.00` to `1.00` alters a page by two characters, well
under one percent. A discount from 0 to 100 changes a few more. So the module
that exists to find client-controlled prices will fire only when the checkout
page changes size by a third — which is to say, almost never. This is worse
than not having the module: it implies coverage it does not deliver.

### 2. Test coverage stops at the edges — Medium

71 % overall, but `cli.py` (479 statements), `__main__.py` and `console.py`
are at **0 %**. Those are the paths every user touches first and the ones that
break on a Windows terminal with a different code page. The reporting layer -
what a client actually reads - is the thinnest tested area in the project.

### 3. No browser, so "entire website" has a caveat — Medium

The crawler is `requests` + BeautifulSoup. It cannot see anything rendered by
JavaScript, which describes most modern front ends. DOM XSS, `postMessage`
handling, client-side routing and single-page apps are unreachable. The README
labels browser-only *classes* as manual, which is honest, but the consequence
for **crawling** is not stated.

### 4. No callback server, so every blind class is out — Medium

Blind SSRF, blind XXE, blind RCE and most deserialization findings need an
out-of-band interaction. Without an OAST listener, nemesis can only find the
variants that reflect something back. These are listed as manual/out-of-scope
in the capability map, correctly, but it is the single largest gap between
"everything a hacker can do" and what this does.

### 5. No login flow — Low

Credentials can be *injected*, but there is no automation that discovers a
login form, authenticates, and continues the scan with the resulting session.
Every authenticated scan needs a token pasted in by hand.

### 6. The 102 capability areas flatter the coverage — Low

Many rows are `maturity="manual"`. Counting them beside native modules in one
number is technically accurate and rhetorically generous. The registry does
expose `by_maturity`, which is the honest view; the headline number is not.

## Defects found and fixed during this audit

| # | defect | where | status |
|---|---|---|---|
| 1 | `struct.error` on a pcap shorter than 24 bytes | `infra/pcap.py` | fixed |
| 2 | `TypeError` when `dependencies` is an int or list | `deps/manifest.py:96` | fixed |
| 3 | `AttributeError` on a string dependency map | `deps/manifest.py:140` | fixed |
| 4 | SHA-1 used for WebSocket handshake triggering B324 | `infra/` | annotated, false positive |

## The honest arithmetic

- 64 native modules, 21 groups, 5 output formats, 14 subcommands.
- Of the capabilities advertised, roughly two thirds are backed by a module
  that sends traffic; the rest are learning resources, manual procedure, or
  explicitly out of reach.
- 2,883-class taxonomy: not present in this version. Coverage claims should be
  made per-module, not per-taxonomy.

## What I would fix first

1. Replace the business-logic length gate with a **value diff**: extract the
   numeric field the parameter controls and compare the number, not the page
   size. This is a contained change and it turns a dead module into the most
   valuable one in the tool.
2. Add an OAST listener. It unlocks blind SSRF/XXE/RCE and is the difference
   between a scanner and a proxy.
3. Test `cli.py` and `console.py`. They are 479 + ~120 statements at zero.
4. Add a login flow (form discovery, credential fill, session reuse).

## Score breakdown

| dimension | score | why |
|---|---:|---|
| core detection engine | 8.5 | length-matched differential, correct redirect policy |
| breadth of checks | 7.0 | 64 modules, but several are shallow |
| evidence and reporting | 8.0 | redacted, reproducible, autoescaped HTML |
| honesty of claims | 7.5 | out-of-scope declared; one module overstates itself |
| test depth | 6.0 | 277 tests, 71 %, zero on CLI and console |
| blind/browser coverage | 3.0 | absent by design, and it is a real gap |
| **overall** | **7.2** | strong engineering, narrower than advertised |

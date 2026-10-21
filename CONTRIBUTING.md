# Contributing to nemesis

Thanks for taking the time. This document is short on purpose.

## The one rule

**A finding is a claim about a server's behaviour. Make it defensible.**

The difference between a scanner people trust and a scanner people mute is
whether its findings survive contact with a real application. Every change
is judged on that axis.

## Development setup

```bash
git clone https://github.com/HexVandal/nemesis
cd nemesis
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
ruff check nemesis tests
```

## The module contract

A module is a class that inherits from `nemesis.modules.base.Module` and
implements one async method:

```python
async def run(self, ctx: ScanContext) -> list[Finding]: ...
```

`ctx` gives you:

| Attribute | What it is |
|---|---|
| `ctx.responses` | Every HTTP response the crawler collected |
| `ctx.endpoints` | Every URL discovered, with its query parameters |
| `ctx.forms` | Every form, with method, action and fields |
| `ctx.client` | The HTTP client (the only way to make a request) |
| `ctx.scope` | The scope rules |
| `ctx.config` | The active `ScanConfig` |
| `ctx.host` | The target host |
| `ctx.code_path` | Local source tree, if `--code-path` was given |
| `ctx.stats` | A free-form dict for your own counters |

### Declaring yourself

```python
class MyCheck(Module):
    id = "my_check"                  # unique, snake_case
    name = "My Check"                # human readable
    description = "What this checks." # one line, shown in `nemesis modules`
    severity = Severity.MEDIUM       # worst case if the issue is real
    confidence = Confidence.HIGH     # your *prior*, before verification
    category = Category.WEB
    capability = Capability.HTTP
    group = "web"                    # used by profiles
    tags = ["custom"]
    cwe = "CWE-79"                  # optional
    owasp = "A03"                   # optional
```

`group` matters: profiles select modules with `group/*` patterns, so
`group = "injection"` makes your module part of every profile that
includes `injection/*`.

### Active checks

Never send a raw request. Use `HttpModule`, which handles baselines,
differential comparison and confidence scoring for you:

```python
from ..http_helper import HttpModule

class MyCheck(HttpModule):
    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for target in self.collect_targets(ctx):
            async for payload, delta in self.iter_deltas(
                ctx, target, MY_PAYLOADS, signatures=MY_SIGNATURES
            ):
                if not delta.has_behaviour_change:
                    continue
                findings.append(self.finding(
                    title="Something interesting",
                    target=target.url,
                    description="...",
                    evidence_text=delta.describe(),
                    matched=payload,
                ))
                break
        return findings
```

The baseline used by `iter_deltas` is **length-matched** to the payload. If
you write your own requests, match that behaviour — an unmatched baseline
makes every short payload look like a huge change.

### Passive checks

Iterate `ctx.responses`. Remember that error responses are where the
interesting things live: stack traces, leaked connection strings and
verbose errors all appear on 4xx and 5xx pages, not on the happy path.

## Adding a test

Every new module needs a test that proves it fires on a vulnerable input
and stays quiet on a clean one. `tests/fixtures/vulnerable_app.py` is a
deliberately broken application with one handler per CWE; add to it, then
assert in `tests/test_integration.py`.

A test that only proves the happy path is not enough. The false-positive
test matters more.

## Style

- `ruff check nemesis tests` must pass.
- Keep lines under 100 characters.
- Comments explain *why*, not *what*.
- No new runtime dependencies without discussion — the scanner is meant to
  stay installable with `pip install nemesis` and nothing else.

## Pull requests

- One logical change per PR.
- Say what you measured. "This reduced false positives on the fixture app
  from 30 findings to 3" is worth more than a list of files.
- Update the README module table if you add a module.

## Reporting a security issue in nemesis itself

Please do **not** open a public issue. Report it privately through
[GitHub's security advisory form](https://github.com/HexVandal/nemesis/security/advisories/new).

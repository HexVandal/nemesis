<div align="center">

# nemesis

### The offensive-security scanner that thinks like a red team.

**Crawl it. Fingerprint it. Exploit it. Prove it.**

[![CI](https://github.com/nemesis-sec/nemesis/actions/workflows/ci.yml/badge.svg)](https://github.com/nemesis-sec/nemesis/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-32%2B-blueviolet.svg)](nemesis/modules)
[![PyPI](https://img.shields.io/badge/pypi-nemesis-orange.svg)](https://pypi.org/project/nemesis/)
[![Offline](https://img.shields.io/badge/scanner-fully%20offline%20capable-brightgreen.svg)](nemesis)

</div>

---

## The problem with scanners

Almost every security scanner answers a question nobody asked: *"did a pattern
match?"* You get a list of template hits, a severity colour, and no way to
tell the one real SQL injection from the two hundred false positives. Then
you spend your afternoon triaging, which is exactly the work the tool was
supposed to do.

**nemesis answers a different question: *"did the server's behaviour change
when I attacked it?"***

Every active check is a **differential experiment**. nemesis sends a benign
request, sends a payload request to the *same* endpoint, and compares the
two responses — status, length, timing, headers, and where the payload came
back. A finding is only as strong as the evidence that something changed.

That is why every nemesis report carries a **proof**:

```
  CRITICAL SQL injection in parameter 'q' http://127.0.0.1:8899/search
╭──────────────────────────────────────────────────────────────────────────────╮
│ Baseline: 200 GET http://127.0.0.1:8899/search?q=x (48B, 0.00s)              │
│ Payload : '                                                                  │
│ Probe   : 500 GET http://127.0.0.1:8899/search?q=%27 (233B, 0.00s)           │
│ Delta   : status +300, length +185 bytes (4.85x), time +0.00s                │
╰──────────────────────────────────────────────────────────────────────────────╯
```

You do not have to trust the scanner. You can read the experiment.

---

## Why this is different

| | nuclei | Burp | Trivy / Grype | **nemesis** |
|---|---|---|---|---|
| Unit of work | template match | manual request | CVE match | **differential experiment** |
| Severity + confidence | severity only | judgement | severity only | **two separate axes** |
| Proof of exploitability | ✗ | manual | ✗ | **✓ every finding** |
| Whole-site crawl | optional | manual | ✗ | **✓ default** |
| Source analysis (SAST) | ✗ | ✗ | ✗ | **✓ secrets, logic bugs** |
| Dependency analysis (SCA) | ✗ | ✗ | ✓ | **✓ OSV-backed** |
| Licence risk | ✗ | ✗ | partial | **✓ copyleft / source-available** |
| Host posture (TLS, DNS) | ✗ | ✗ | ✗ | **✓** |
| Needs a browser/daemon | ✗ | ✓ | ✗ | **✗ one binary** |
| Fully offline | partial | ✗ | ✓ | **✓** |

The two-axis model is the important part. **Severity** answers *"how bad is
this if it is real?"* **Confidence** answers *"how sure are you that it is
real?"* A critical finding with medium confidence is a very different thing
from a critical finding that was confirmed by reading a leaked `/etc/passwd`
back out of the response — and collapsing them into one number is how
scanners lose people's trust.

---

## Install

```bash
pip install nemesis
```

or from source:

```bash
git clone https://github.com/nemesis-sec/nemesis
cd nemesis
pip install -e ".[dev]"
```

Python 3.10+. No browser, no daemon, no Docker.

---

## Use it

```bash
# Scan an entire site
nemesis scan https://app.example.com

# Just the source and its dependencies
nemesis scan https://app.example.com --code-path . --profile code

# Quiet, machine readable
nemesis scan https://app.example.com --json | jq '.findings[] | select(.severity=="CRITICAL")'

# Upload results to GitHub code scanning
nemesis scan https://app.example.com --format sarif --output ./results
```

### Profiles

| Profile | What it does |
|---|---|
| `quick` | Passive checks plus the highest-signal active probes. Seconds. |
| `web` | Full web application assessment. Everything that speaks HTTP. |
| `code` | Static analysis and supply-chain review of a local checkout. |
| `ai` | AI and LLM application security: endpoints, prompt injection, agent tools, models. |
| `blockchain` | Smart contract auditing of a local Solidity tree. |
| `forensics` | Memory images, crash dumps and packet captures. |
| `recon` | Passive and low-impact discovery. No exploitation. |
| `full` | Everything: web, host, source and dependency layers. |
| `passive` | No requests beyond the crawl. Zero noise. |

### Output formats

`console` · `json` · `markdown` · `html` · `sarif`

SARIF output means findings land in **GitHub code scanning** with no glue
code, which is how security stops being a separate ritual.

---

## From findings to something you can act on

A scan produces findings. These commands turn them into the things that
actually get used: a worklist, a detection rule, a disclosure report, a
write-up.

```bash
# What do I do first, and why?  Duplicates collapse into root causes.
nemesis triage results/nemesis.json

# Detection content, generated from what was actually observed.
nemesis yara  results/nemesis.json -o rules.yar
nemesis sigma results/nemesis.json -o rules.yml

# A bug bounty report in the shape the programme actually triages.
nemesis report results/nemesis.json --programme hackerone --asset https://app.example.com

# A public write-up draft, with the limits of the review stated.
nemesis writeup results/nemesis.json --author "you"

# Score a CVSS vector and see what each metric does.
nemesis cvss "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# The research library: papers, courses, books, labs and tools, by area.
nemesis knowledge --search "heap exploitation" --area heap-exploitation

# The research workspace: notes, open findings, research, portfolio.
nemesis lab init
nemesis lab note "Testing the PNG parser against fuzzilli"
nemesis lab finding "A race condition in the session cache"
```

`nemesis triage` is the one that changes how a report is read. It scores
each finding on three independent axes — impact, evidence quality, and
effort to confirm and fix — and explains every score. A critical finding
with a proven, reflected payload outranks a critical finding that was only
a status-code change, and the report says why.

### The capability map

nemesis tracks **102 capability areas** — from kernel exploitation to
security portfolio — and says honestly which of them it actually does.

```bash
nemesis capabilities              # the whole map
nemesis capabilities --domain ai  # one domain
nemesis capability request-smuggling
```

Every capability carries one of five maturity labels, and the registry is
**validated against the real module registry**: a capability that names a
module which does not exist is a test failure, not a documentation bug.

| Maturity | Meaning |
|---|---|
| `native` | nemesis does this itself, today. You can point at the module. |
| `partial` | nemesis covers a meaningful slice of it. |
| `integration` | nemesis produces or consumes the artifacts the work needs; a tool or a human does the rest. |
| `research` | Needs specialised hardware, a custom toolchain or a lab. |
| `manual` | A practice rather than a tool: reviewing, writing, disclosing. |

All 102 are backed by shipped code or a shipped component: **32 native, 40
partial, 14 integration, 16 research**. A capability that is only *partly*
covered says so, and the ones that need a lab bench, a disassembler or a
person with a soldering iron say that too — because a tool that claims to
do kernel exploitation and does not is worse than a tool that says it does
not.

Two components back the areas that are not scans:

- **`nemesis knowledge`** — a curated index of 136 real papers, books,
  courses, labs, standards and tools, mapped to the capability areas they
  serve, with the reason each one is worth your time.
- **`nemesis lab`** — a research workspace on disk. Lab notes, unsolved
  vulnerabilities, original research and a portfolio, each with a structure
  that makes it useful six months later.

```bash
nemesis knowledge --search "buffer overflow"
nemesis knowledge --area fuzzing
nemesis lab init
nemesis lab note "Testing the PNG parser"
nemesis lab finding "A race condition in the cache"
```

---

## What it finds

**Web application** — SQL injection, NoSQL injection, command injection, SSTI, XSS, XXE, insecure deserialization, path traversal, SSRF, open redirect, IDOR, CSRF, host header injection, GraphQL introspection, exposed files, directory listing, stack traces, missing security headers, weak cookies, CORS misconfiguration, clickjacking, mixed content, outdated technology, unsafe HTTP methods.

**Request-level** — CL.TE and TE.CL request smuggling, web cache poisoning, WebSocket origin validation, file upload handling, business-logic tampering of price, quantity, role and state parameters, and a real Content-Security-Policy parser that reports what the policy actually permits rather than whether the header exists.

**Source code** — hardcoded secrets (AWS, GCP, GitHub, GitLab, Slack, Stripe, private keys, JWTs, database URLs and more), command injection, `eval`, deserialisation, unsafe YAML, path traversal in code, weak crypto, privilege escalation patterns, and **logic bugs**: mutable default arguments, swallowed exceptions, float arithmetic on money, `== None`, unvalidated `assert` in production paths, off-by-one slice bugs, and more.

**Patch regression** — compares the working tree against `HEAD~1` and reports the dangerous patterns a change *introduced* or *resurrected*. This is the check that stops a fix from being quietly undone.

**Git history** — walks every revision of a repository and finds the credentials that were committed and then removed. Removing a secret from `HEAD` does not remove it from every clone, every fork or every CI cache that ever checked it out.

**Containers** — reads Dockerfiles, Compose files and Kubernetes manifests for the configurations that turn a container into an escape: the Docker socket mounted in, `privileged: true`, a root user, a host namespace, an added capability.

**Network evidence** — parses pcap and pcapng files directly, with no external dependency: cleartext credentials, DNS exfiltration in a long encoded label, plaintext protocols carrying sensitive traffic, and a bulk flow to a port nobody expected.

**Memory forensics** — parses memory images and crash dumps directly: the process inventory, the command lines, the network connection table, the persistence keys, the regions that exist in memory but not on disk, and the secrets that were resident in a process when it was seized.

**DeFi mechanics** — unchecked ERC-20 transfers, swaps with no `amountOutMin`, oracle reads with no staleness or round check, AMM pricing from the pool's own reserves, reachable token callbacks, and contracts that change state without emitting an event.

**Browser posture** — the security headers as a set rather than one at a time: a CSP that permits `unsafe-inline`, `unsafe-eval` or `data:`, an HSTS `max-age` below a year, a `__Host-` cookie that breaks its own rules, and missing cross-origin isolation.

**Fuzzing** — finds the functions that take a byte buffer, generates a libFuzzer harness for each, works out the project's build system, and writes a seed dictionary. A harness that only exists in a report is a harness nobody compiles, so this one is written to disk.

**Proxy and IPv6** — whether the application takes the client address, the original host and the scheme from headers any client can set, and whether an address filter that accepts `127.0.0.1` also accepts `::ffff:127.0.0.1`.

**Supply chain** — dependency confusion and typosquatting (a declared name compared against the popular packages of its ecosystem), CI/CD pipeline security (`pull_request_target` with untrusted checkout, unpinned third-party actions, expression injection into `run:` blocks, privileged containers, self-hosted runners), and infrastructure as code for Terraform, Kubernetes, Dockerfiles and CloudFormation.

**Binaries** — a real ELF / PE / Mach-O parser: architecture, hardening posture (NX, PIE, RELRO, stack canary), dangerous imports, packer detection and credentials embedded in the binary. Extensionless executables are found by magic bytes, because that is what ends up in a container image.

**AI and LLM** — model endpoint discovery and provider identification, prompt injection (gated on real evidence that a model is present, so it does not degenerate into a second XSS scanner), model extraction and system-prompt leakage, agent tool-listing exposure, and ML model security: unsafe `torch.load` / `pickle.load` deserialisation, PII in datasets, and credentials in model cards.

**Smart contracts** — Solidity auditing for reentrancy, missing access control, `tx.origin` authorisation, unchecked return values, unprotected initialisers, `ecrecover` without a zero-address check, and block-timestamp dependence.

**Dependencies** — PyPI, npm, crates.io, Go, Maven, RubyGems and Packagist manifests and lockfiles, resolved against the live **OSV.dev** advisory database, with CVSS vectors scored locally. Advisories are grouped per package, not per CVE, so one outdated Django release is one finding and not seventy-five.

**Host posture** — legacy TLS versions, expired certificates, weak ciphers, missing SPF / DMARC / CAA records, dangling CNAMEs.

---

## Architecture

```
                    ┌──────────────┐
   nemesis scan ───▶│    Scope     │  default-deny, every request checked
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │   Crawler    │  BFS, robots-aware, scope-enforced
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ Fingerprint  │  tech, versions, frameworks
                    └──────┬───────┘
                           ▼
        ┌──────────────────────────────────────────┐
        │                 Modules                   │
        │  web/ · code/ · deps/ · ai/ · blockchain/  │
        │  supplychain/ · plugins/                   │
        └──────────────────┬───────────────────────┘
                           ▼
                    ┌──────────────┐
                    │  Verifier    │  differential analysis → confidence
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │   Reports    │  console · json · md · html · sarif
                    └──────┬───────┘
                           ▼
        ┌──────────────────────────────────────────┐
        │        Action layer (CLI)                │
        │  triage · yara · sigma · report · writeup │
        └──────────────────────────────────────────┘
```

### Design commitments

- **Default-deny scope.** No request leaves the process without passing a scope check. Redirects are followed manually and re-checked at every hop, because a redirect is the classic way to smuggle a request out of scope.
- **One egress point.** Every HTTP request in the codebase goes through a single client that owns rate limiting, redirect handling, timeouts, and secret redaction. There is no second path.
- **Length-matched baselines.** A baseline request uses a benign value of the *same length* as the payload. Without this, a one-character payload looks like a huge behavioural change simply because the echoed value got shorter — and the scanner reports an injection on every parameter it touches.
- **Severity and confidence are orthogonal.** Neither is ever derived from the other.
- **Secrets are redacted** from evidence before it reaches a report.
- **Destructive modules are opt-in** via `--allow-destructive`.

---

## Writing a plugin

A module is a class. That is the whole plugin system.

```python
from nemesis.modules.base import Module, ScanContext
from nemesis.models import Capability, Category, Confidence, Finding, Severity

class MyCheck(Module):
    id = "my_check"
    name = "My Check"
    description = "Looks for something specific."
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    category = Category.WEB
    capability = Capability.HTTP
    group = "web"
    tags = ["custom"]

    async def run(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        for response in ctx.responses:
            if "x-secret-header" in response.headers:
                findings.append(self.finding(
                    title="Internal header exposed",
                    target=response.url,
                    description="The response contains an x-secret-header.",
                    evidence_text=str(dict(response.headers)),
                    matched="x-secret-header",
                ))
        return findings
```

Drop it in `nemesis/plugins/`, or publish it as a Python package that
registers a `nemesis_plugins` entry point, and it is picked up
automatically. No registry to edit, no base class to import from a
particular path.

```bash
nemesis scan https://app.example.com --plugins ./my_checks/
nemesis modules --detailed
```

---

## Responsible use

nemesis sends real attack payloads. It is a tool for **authorised security
testing**: penetration tests, bug bounties, CTFs, internal red teams, and
defensive audits of systems you own.

Do not point it at systems you do not have permission to test. It will find
real vulnerabilities, and finding a vulnerability on someone else's system
without authorisation is a legal problem, not a technical one.

- Scope is default-deny and must be widened explicitly.
- `--allow-destructive` is required for anything that changes server state.
- Rate limiting is on by default, per host.
- Use `--profile passive` when you need reconnaissance without exploitation.

---

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md)
first — it explains the module contract and how to add a check without
regressing the false-positive rate.

```bash
pip install -e ".[dev]"
pytest -q
ruff check nemesis tests
```

---

## License

Apache-2.0. See [LICENSE](LICENSE).

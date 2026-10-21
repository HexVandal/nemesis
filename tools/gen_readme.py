"""Generate README.md from the live registry so the module list can never drift."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from nemesis.config import ScanConfig
from nemesis.modules.base import ModuleRegistry

SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}
CAP_ICON = {
    "passive": "👁️ passive",
    "http": "🌐 http",
    "host": "🖧 host",
    "code": "🧬 code",
    "deps": "📦 deps",
    "destructive": "💥 destructive",
}
GROUP_ICON = {
    "injection": "💉",
    "auth": "🔐",
    "code": "🧬",
    "exposure": "🗂️",
    "headers": "🛡️",
    "ai": "🤖",
    "api": "🔌",
    "config": "⚙️",
    "supplychain": "📦",
    "host": "🌐",
    "disclosure": "🕵️",
    "logic": "🧠",
    "deps": "📚",
    "oauth": "🔑",
    "cache": "⚡",
    "browser": "🖥️",
    "business": "💳",
    "ssrf": "🎯",
    "traversal": "📁",
    "blockchain": "⛓️",
    "forensics": "🧪",
    "smuggling": "📮",
    "dos": "💥",
    "upload": "📤",
    "websocket": "🔗",
}


def clean(text: str) -> str:
    text = " ".join(text.split())
    text = text.replace("|", "\\|")
    if not text:
        return text
    return text[0].upper() + text[1:]


def main() -> None:
    reg = ModuleRegistry(ScanConfig())
    reg.load_builtin()
    modules = sorted(reg._modules.values(), key=lambda m: m.id)

    groups: dict[str, list] = defaultdict(list)
    for module in modules:
        groups[module.group].append(module)

    total = len(modules)
    sev_counts = defaultdict(int)
    for module in modules:
        sev_counts[module.severity.name] += 1

    catalogue: list[str] = []
    catalogue.append("## 📦 The complete catalogue — every module, what it needs and how bad it is\n")
    catalogue.append(
        f"**{total} modules** across **{len(groups)} groups**. "
        "`needs` is what the module requires to run at all: "
        "👁️ passive reads only what the crawl already fetched, "
        "🌐 http sends requests, 🖧 host talks to the host, "
        "🧬 code reads a local tree, 📦 deps reads manifests, "
        "💥 destructive changes state on the target and needs `--allow-destructive`.\n"
    )
    catalogue.append("| severity | modules |\n|---|---:|\n")
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        catalogue.append(f"| {SEV_ICON[level]} {level.title()} | {sev_counts[level]} |\n")
    catalogue.append("\n---\n")

    order = sorted(groups, key=lambda g: (-len(groups[g]), g))
    for group in order:
        items = sorted(groups[group], key=lambda m: m.id)
        icon = GROUP_ICON.get(group, "▸")
        catalogue.append(f"### {icon} {group.title()} — {len(items)} modules\n")
        catalogue.append("| module | what it does | needs | severity |\n|---|---|---|---|\n")
        for m in items:
            catalogue.append(
                f"| `{m.id}` | {clean(m.description)} | {CAP_ICON.get(m.capability.value, m.capability.value)} "
                f"| {SEV_ICON.get(m.severity.name, '')} {m.severity.name.title()} |\n"
            )
        catalogue.append("\n")

    head = """<p align="center">
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
.\\.venv\\Scripts\\activate        # Windows
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

"""

    tail = """---

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
"""

    Path("README.md").write_text(head + "".join(catalogue) + tail)
    print(f"README.md written: {total} modules, {len(groups)} groups")


if __name__ == "__main__":
    main()

# Security Policy

## Reporting a vulnerability in nemesis

If you find a security issue in nemesis itself, **please do not open a
public issue**.

Report it privately through GitHub's security advisory form:

**https://github.com/nemesis-sec/nemesis/security/advisories/new**

Include:

- A description of the issue and its impact
- Steps to reproduce, ideally against a local target
- The version or commit you tested
- Any proof-of-concept output

You can expect an acknowledgement within 72 hours and a status update
within seven days. Fixes for confirmed issues are released as quickly as
we can manage, and we are happy to credit you in the release notes unless
you would rather stay anonymous.

## Scope of the tool

nemesis is a security scanner. It sends real attack payloads to whatever
host you point it at.

**Only use it on systems you own or have explicit, written permission to
test.** That includes:

- Penetration tests under an agreed scope
- Bug bounty programs, within their published rules
- Capture-the-flag competitions
- Internal red team exercises
- Defensive audits of your own infrastructure

Running it against third-party systems without authorisation is a criminal
offence in most jurisdictions, and it does not matter that the tool is
open source.

## Built-in safety rails

nemesis is designed so that an accidental overreach is unlikely:

- **Default-deny scope.** Only the target host is in scope unless you widen
  it with `--scope`. Every request, including each redirect hop, is
  checked against the scope rules.
- **Destructive modules are off by default.** Anything that changes server
  state requires `--allow-destructive`.
- **Per-host rate limiting** is on by default.
- **Exclusions always win** over inclusions, so you can carve out paths
  from a wide scope.
- **Evidence is redacted** so credentials you pass in are not written into
  reports.

These rails reduce risk; they do not create authorisation. The
authorisation has to come from you.

## What a scan touches

A `nemesis scan` against a web target issues:

- One crawl of the site, honouring `robots.txt` by default
- A baseline and one payload request per active check, per parameter
- Some host-level checks (TLS handshake, DNS queries)

That is a real load. On a large site, use `--profile passive` for
reconnaissance, or lower `--rate`.

## Dependencies

nemesis pulls advisory data from [OSV.dev](https://osv.dev/) at scan time
when the dependency modules are enabled. Everything else works offline.

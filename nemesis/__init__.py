"""nemesis - the offensive-security scanner that thinks like a red team.

nemesis crawls a target, fingerprints its technology, actively probes it with
real exploitation techniques, and then *verifies* every finding with differential
analysis so the report contains signal rather than noise.

Layers, in order:

1. crawl      - discover every reachable endpoint, form, parameter and asset
2. fingerprint - identify frameworks, servers, versions and attack surface
3. exploit    - run active modules (SQLi, XSS, SSRF, traversal, IDOR, ...)
4. verify     - differentially confirm or refute every candidate finding
5. report     - SARIF / JSON / Markdown / HTML, with reproducible evidence
"""

__version__ = "0.1.0"
__all__ = ["__version__"]

"""Self-contained HTML report writer.

The output is a single file with no external assets, so it can be emailed,
attached to a ticket, or opened from a USB stick with no network.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment

from ..models import ScanResult

_ENV = Environment(autoescape=True)

_TEMPLATE = _ENV.from_string(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nemesis report - {{ target }}</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d; --text: #e6edf3;
    --muted: #8b949e; --accent: #58a6ff;
    --critical: #f85149; --high: #ff7b72; --medium: #d29922;
    --low: #3fb950; --info: #58a6ff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  .wrap { max-width: 1180px; margin: 0 auto; padding: 32px 24px 80px; }
  header { border-bottom: 1px solid var(--border); padding-bottom: 24px; margin-bottom: 28px; }
  h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -0.4px; }
  .sub { color: var(--muted); font-size: 13px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 24px 0 32px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .card .n { font-size: 28px; font-weight: 600; line-height: 1.1; }
  .card .l { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.7px; margin-top: 4px; }
  .sev-critical .n { color: var(--critical); } .sev-high .n { color: var(--high); }
  .sev-medium .n { color: var(--medium); } .sev-low .n { color: var(--low); }
  .sev-info .n { color: var(--info); }
  h2 { font-size: 16px; margin: 36px 0 14px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }
  .finding { background: var(--panel); border: 1px solid var(--border); border-left-width: 3px;
             border-radius: 8px; padding: 16px 18px; margin-bottom: 12px; }
  .finding.s-CRITICAL { border-left-color: var(--critical); }
  .finding.s-HIGH { border-left-color: var(--high); }
  .finding.s-MEDIUM { border-left-color: var(--medium); }
  .finding.s-LOW { border-left-color: var(--low); }
  .finding.s-INFO { border-left-color: var(--info); }
  .finding h3 { margin: 0 0 10px; font-size: 15px; }
  .meta { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 12px; }
  .tag { font-size: 11px; padding: 2px 8px; border-radius: 20px; border: 1px solid var(--border);
         color: var(--muted); background: rgba(255,255,255,0.03); }
  .tag.sev { color: #0d1117; font-weight: 600; border: none; }
  .tag.sev-CRITICAL { background: var(--critical); } .tag.sev-HIGH { background: var(--high); }
  .tag.sev-MEDIUM { background: var(--medium); } .tag.sev-LOW { background: var(--low); }
  .tag.sev-INFO { background: var(--info); }
  .tag.conf-CONFIRMED, .tag.conf-HIGH { color: var(--low); border-color: rgba(63,185,80,0.4); }
  .tag.conf-LOW, .tag.conf-MEDIUM { color: var(--medium); border-color: rgba(210,153,34,0.4); }
  .target { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--accent);
            word-break: break-all; }
  p.desc { margin: 0 0 12px; color: #c9d1d9; }
  details { margin: 12px 0; }
  summary { cursor: pointer; color: var(--muted); font-size: 12px; user-select: none; }
  pre { background: #010409; border: 1px solid var(--border); border-radius: 6px; padding: 12px;
        overflow-x: auto; font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
        white-space: pre-wrap; word-break: break-word; }
  .fix { border-left: 2px solid var(--low); padding: 6px 0 6px 12px; margin: 12px 0 0; color: #c9d1d9; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; }
  .empty { color: var(--muted); font-style: italic; }
  footer { margin-top: 48px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>nemesis</h1>
  <div class="sub">{{ target }} &middot; {{ started }} &rarr; {{ finished }} ({{ duration }}s)</div>
</header>

<div class="cards">
  <div class="card sev-critical"><div class="n">{{ counts.CRITICAL }}</div><div class="l">Critical</div></div>
  <div class="card sev-high"><div class="n">{{ counts.HIGH }}</div><div class="l">High</div></div>
  <div class="card sev-medium"><div class="n">{{ counts.MEDIUM }}</div><div class="l">Medium</div></div>
  <div class="card sev-low"><div class="n">{{ counts.LOW }}</div><div class="l">Low</div></div>
  <div class="card sev-info"><div class="n">{{ counts.INFO }}</div><div class="l">Info</div></div>
  <div class="card"><div class="n">{{ risk }}</div><div class="l">Risk score</div></div>
</div>

<h2>Findings ({{ total }})</h2>
{% if not findings %}
  <p class="empty">No findings were produced.</p>
{% else %}
{% for f in findings %}
<div class="finding s-{{ f.severity }}">
  <h3>{{ f.title }}</h3>
  <div class="meta">
    <span class="tag sev sev-{{ f.severity }}">{{ f.severity }}</span>
    <span class="tag conf-{{ f.confidence }}">{{ f.confidence }} confidence</span>
    {% if f.cwe %}<span class="tag">{{ f.cwe }}</span>{% endif %}
    {% if f.owasp %}<span class="tag">OWASP {{ f.owasp }}</span>{% endif %}
    <span class="tag">{{ f.module }}</span>
  </div>
  <div class="target">{{ f.target }}</div>
  <p class="desc">{{ f.description }}</p>
  {% if f.evidence %}
  <details><summary>Evidence</summary><pre>{{ f.evidence }}</pre></details>
  {% endif %}
  {% if f.remediation %}<div class="fix"><strong>Remediation.</strong> {{ f.remediation }}</div>{% endif %}
</div>
{% endfor %}
{% endif %}

{% if technologies %}
<h2>Fingerprint</h2>
<table><thead><tr><th>Technology</th><th>Version</th><th>Category</th><th>Source</th></tr></thead><tbody>
{% for t in technologies %}<tr><td>{{ t.name }}</td><td>{{ t.version or '-' }}</td><td>{{ t.category }}</td><td>{{ t.source }}</td></tr>{% endfor %}
</tbody></table>
{% endif %}

{% if endpoints %}
<h2>Attack surface ({{ endpoints|length }} endpoints, {{ forms|length }} forms)</h2>
<table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>Type</th><th>Params</th></tr></thead><tbody>
{% for e in endpoints[:120] %}<tr><td>{{ e.method }}</td><td class="target">{{ e.url }}</td><td>{{ e.status or '-' }}</td><td>{{ e.content_type[:40] }}</td><td>{{ e.params.keys()|list|join(', ') }}</td></tr>{% endfor %}
</tbody></table>
{% endif %}

<footer>
  {{ confirmed }} of {{ total }} findings are confirmed or high confidence.
  Generated by <strong>nemesis</strong> - the offensive-security scanner that thinks like a red team.
  Scope: {{ scope }}
</footer>
</div>
</body>
</html>
"""
)


def write_html(result: ScanResult, path: str | Path, scope: str = "") -> Path:
    """Write a self-contained HTML report."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    findings = [
        {
            "title": f.title,
            "severity": f.severity.name,
            "confidence": f.confidence.value,
            "target": f.target,
            "description": f.description,
            "cwe": f.cwe or "",
            "owasp": f.owasp or "",
            "module": f.module,
            "evidence": (f.evidence.response or "")[:2000],
            "remediation": f.remediation,
        }
        for f in result.findings
    ]

    document = _TEMPLATE.render(
        target=result.target.base_url,
        started=result.started_at,
        finished=result.finished_at,
        duration=result.duration_seconds,
        counts=result.counts(),
        risk=result.risk_score(),
        total=len(result.findings),
        confirmed=len(result.confirmed()),
        findings=findings,
        technologies=[t.to_dict() for t in result.technologies],
        endpoints=[e.__dict__ for e in result.endpoints],
        forms=result.forms,
        scope=scope or "-",
    )
    target.write_text(document, encoding="utf-8")
    return target

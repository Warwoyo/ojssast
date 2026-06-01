"""HTML report writer (Jinja2, self-contained single file)."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, select_autoescape

from .. import __version__
from ..models import SEVERITY_ORDER, ScanResult, sort_findings

_SEV_RANK = {s.value: s.rank for s in SEVERITY_ORDER}

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ojs-sast report — {{ meta.ojs_path }}</title>
<style>
  :root {
    --crit:#b00020; --high:#e8590c; --med:#f59f00; --low:#2f9e44; --info:#1971c2;
    --bg:#f4f6f8; --card:#fff; --ink:#1b1f24; --muted:#6b7682; --line:#e2e6ea;
  }
  * { box-sizing:border-box; }
  body { margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
         background:var(--bg); color:var(--ink); font-size:14px; }
  header { background:#0b1f33; color:#fff; padding:22px 28px; }
  header h1 { margin:0 0 4px; font-size:22px; }
  header .meta { color:#aebfd0; font-size:13px; line-height:1.6; }
  header code { color:#fff; background:rgba(255,255,255,.12); padding:1px 6px; border-radius:4px; }
  main { padding:24px 28px; max-width:1200px; margin:0 auto; }
  .cards { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:22px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px;
          padding:14px 18px; min-width:104px; box-shadow:0 1px 2px rgba(0,0,0,.04); }
  .card .n { font-size:26px; font-weight:700; }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .card.total .n { color:var(--ink); }
  .badge { display:inline-block; padding:2px 9px; border-radius:20px; color:#fff;
           font-size:12px; font-weight:600; }
  .CRITICAL{background:var(--crit);} .HIGH{background:var(--high);}
  .MEDIUM{background:var(--med);} .LOW{background:var(--low);} .INFO{background:var(--info);}
  .card.sev.CRITICAL .n{color:var(--crit);} .card.sev.HIGH .n{color:var(--high);}
  .card.sev.MEDIUM .n{color:var(--med);} .card.sev.LOW .n{color:var(--low);}
  .card.sev.INFO .n{color:var(--info);}
  .controls { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:12px; }
  .controls input { padding:7px 10px; border:1px solid var(--line); border-radius:8px; min-width:240px; }
  .filterbtn { cursor:pointer; border:1px solid var(--line); background:#fff; padding:6px 11px;
               border-radius:20px; font-size:12px; }
  .filterbtn.active { background:#0b1f33; color:#fff; border-color:#0b1f33; }
  table { width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:10px; overflow:hidden; }
  th,td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { background:#fbfcfd; cursor:pointer; user-select:none; font-size:12px;
       text-transform:uppercase; letter-spacing:.03em; color:var(--muted); white-space:nowrap; }
  th:hover { color:var(--ink); }
  tr.finding { cursor:pointer; }
  tr.finding:hover { background:#f8fbff; }
  .file { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; color:#0b3d66; }
  .rule { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:var(--muted); }
  .detail { display:none; background:#fbfcfd; }
  .detail.open { display:table-row; }
  .detail .box { padding:6px 4px 12px; }
  .kv { display:flex; flex-wrap:wrap; gap:6px 22px; margin:6px 0 10px; color:var(--muted); font-size:12.5px; }
  .kv b { color:var(--ink); font-weight:600; }
  pre { background:#0b1f33; color:#e6edf3; padding:11px 13px; border-radius:8px;
        overflow:auto; font-size:12.5px; margin:8px 0; }
  .rem { background:#fff7e6; border-left:3px solid var(--med); padding:9px 12px; border-radius:4px; }
  .none { padding:40px; text-align:center; color:var(--muted); }
  footer { text-align:center; color:var(--muted); font-size:12px; padding:18px; }
  a.cwe { color:#1971c2; text-decoration:none; }
</style>
</head>
<body>
<header>
  <h1>ojs-sast security report</h1>
  <div class="meta">
    Target: <code>{{ meta.ojs_path }}</code>
    &nbsp;·&nbsp; OJS version: <code>{{ meta.ojs_version or "unknown" }}</code><br>
    Tool: ojs-sast v{{ meta.version }} &nbsp;·&nbsp; Scanned: {{ meta.scan_timestamp }}
    &nbsp;·&nbsp; Modules: {{ meta.modules_run|join(", ") }}
  </div>
</header>
<main>
  <div class="cards">
    <div class="card total"><div class="n">{{ summary.total_findings }}</div><div class="l">Total</div></div>
    {% for sev in severities %}
    <div class="card sev {{ sev }}"><div class="n">{{ summary.by_severity.get(sev, 0) }}</div>
      <div class="l">{{ sev }}</div></div>
    {% endfor %}
  </div>

  {% if findings %}
  <div class="controls">
    <input id="q" type="search" placeholder="Filter by file, rule, CWE, text…" oninput="applyFilters()">
    <span class="filterbtn active" data-sev="ALL" onclick="toggleSev(this)">All</span>
    {% for sev in severities %}
    <span class="filterbtn" data-sev="{{ sev }}" onclick="toggleSev(this)">{{ sev }}</span>
    {% endfor %}
  </div>

  <table id="tbl">
    <thead><tr>
      <th onclick="sortBy(0,'num')">Severity</th>
      <th onclick="sortBy(1,'str')">Module</th>
      <th onclick="sortBy(2,'str')">Rule</th>
      <th onclick="sortBy(3,'str')">Location</th>
      <th onclick="sortBy(4,'str')">Finding</th>
    </tr></thead>
    <tbody>
    {% for f in findings %}
      <tr class="finding" data-sevrank="{{ sevrank[f.severity] }}" data-sev="{{ f.severity }}"
          data-text="{{ (f.rule_id ~ ' ' ~ (f.cwe or '') ~ ' ' ~ f.file_path ~ ' ' ~ f.title ~ ' ' ~ f.detail)|lower }}"
          onclick="toggleRow(this)">
        <td><span class="badge {{ f.severity }}">{{ f.severity }}</span></td>
        <td data-sort="{{ f.module }}">{{ f.module }}</td>
        <td class="rule" data-sort="{{ f.rule_id }}">{{ f.rule_id }}</td>
        <td class="file" data-sort="{{ f.file_path }}">{{ f.file_path }}{% if f.line %}:{{ f.line }}{% endif %}</td>
        <td data-sort="{{ f.title }}">▸ {{ f.title }}</td>
      </tr>
      <tr class="detail"><td colspan="5"><div class="box">
        <div class="kv">
          {% if f.cwe %}<span><b>CWE:</b> <a class="cwe" target="_blank"
             href="https://cwe.mitre.org/data/definitions/{{ f.cwe.replace('CWE-','') }}.html">{{ f.cwe }}</a></span>{% endif %}
          {% if f.owasp %}<span><b>OWASP:</b> {{ f.owasp }}</span>{% endif %}
          {% if f.cvss_score %}<span><b>CVSS:</b> {{ f.cvss_score }}</span>{% endif %}
          <span><b>Confidence:</b> {{ f.confidence }}</span>
          {% if f.taint_source %}<span><b>Taint source:</b> {{ f.taint_source }}</span>{% endif %}
          {% if f.layer %}<span><b>Layer:</b> {{ f.layer }}</span>{% endif %}
          {% if f.actual_mime %}<span><b>Detected MIME:</b> {{ f.actual_mime }}</span>{% endif %}
          {% if f.cve_references %}<span><b>CVE:</b> {{ f.cve_references|join(", ") }}</span>{% endif %}
        </div>
        <div>{{ f.detail }}</div>
        {% if f.code_snippet %}<pre>{{ f.code_snippet }}</pre>{% endif %}
        {% if f.remediation %}<div class="rem"><b>Remediation:</b> {{ f.remediation }}</div>{% endif %}
      </div></td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="card"><div class="none">✓ No findings at the selected severity threshold.</div></div>
  {% endif %}
</main>
<footer>Generated by ojs-sast v{{ meta.version }} — OJS-aware Extended SAST.</footer>
<script>
  var activeSev = "ALL";
  function toggleRow(r){ var d=r.nextElementSibling; if(d&&d.classList.contains('detail')) d.classList.toggle('open'); }
  function toggleSev(el){
    document.querySelectorAll('.filterbtn').forEach(function(b){b.classList.remove('active');});
    el.classList.add('active'); activeSev = el.getAttribute('data-sev'); applyFilters();
  }
  function applyFilters(){
    var q=(document.getElementById('q').value||'').toLowerCase();
    document.querySelectorAll('#tbl tbody tr.finding').forEach(function(r){
      var okSev = (activeSev==='ALL' || r.getAttribute('data-sev')===activeSev);
      var okQ = (!q || r.getAttribute('data-text').indexOf(q)>=0);
      var show = okSev && okQ;
      r.style.display = show ? '' : 'none';
      var d=r.nextElementSibling;
      if(d&&d.classList.contains('detail')){ if(!show){d.classList.remove('open');} d.style.display = show ? '' : 'none'; }
    });
  }
  function sortBy(col,type){
    var tb=document.querySelector('#tbl tbody');
    var pairs=[];
    var rows=tb.querySelectorAll('tr.finding');
    rows.forEach(function(r){ pairs.push([r, r.nextElementSibling]); });
    pairs.sort(function(a,b){
      var x,y;
      if(col===0){ x=+a[0].getAttribute('data-sevrank'); y=+b[0].getAttribute('data-sevrank'); return y-x; }
      x=a[0].children[col].getAttribute('data-sort')||''; y=b[0].children[col].getAttribute('data-sort')||'';
      return x.localeCompare(y);
    });
    pairs.forEach(function(p){ tb.appendChild(p[0]); if(p[1]) tb.appendChild(p[1]); });
  }
</script>
</body>
</html>
"""


def render_html(result: ScanResult) -> str:
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    template = env.from_string(_TEMPLATE)
    report = result.to_report_dict()
    return template.render(
        meta=report["scan_metadata"],
        summary=report["summary"],
        findings=[f.to_dict() for f in sort_findings(result.findings)],
        severities=[s.value for s in SEVERITY_ORDER],
        sevrank=_SEV_RANK,
    )


def write_html_report(result: ScanResult, output_dir: Path, filename: str = "report.html") -> Path:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / filename
    path.write_text(render_html(result), encoding="utf-8")
    return path

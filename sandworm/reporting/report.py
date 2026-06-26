"""Self-contained HTML report (jinja2).

Renders the attack narrative, the behavioral graph (inline SVG, no external JS),
the timeline, the ATT&CK mapping with per-technique evidence + confidence, IOCs
with confidence/FP-risk, the generated YARA + Sigma, and the coverage score. No
network calls happen at render time — everything is inlined.
"""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
from pathlib import Path

from jinja2 import Environment

from ..core.evidence import EvidenceStore
from ..detect.sigma_gen import SigmaRule
from ..detect.yara_gen import YaraRule
from ..reconstruct.attack_map import AttackMapping
from ..reconstruct.explain import confidence_breakdown
from ..reconstruct.narrative import (
    Phase,
)
from ..reconstruct.timeline import TimelineEntry
from ..reporting.coverage import CoverageReport
from ..reporting.summary import build_summary

try:
    from ._logo import LOGO_DATA_URI
except Exception:  # pragma: no cover - logo asset optional
    LOGO_DATA_URI = ""

_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SANDWORM report — {{ sample_name }}</title>
<style>
 :root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2230;--line:#30363d;--fg:#c9d1d9;--fg2:#e6edf3;--mut:#8b949e;--acc:#1f6feb}
 *{box-sizing:border-box}
 body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;margin:0;background:var(--bg);color:var(--fg);line-height:1.5}
 a{color:#79c0ff;text-decoration:none} a:hover{text-decoration:underline}
 code{background:#0d1117;border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:12px}
 /* hero */
 .hero{background:linear-gradient(135deg,#161b22,#0d1117);border-bottom:1px solid var(--line);padding:22px 28px}
 .hero-row{display:flex;align-items:center;gap:18px;flex-wrap:wrap;max-width:1140px;margin:auto}
 .hero .logo{height:64px;width:auto;filter:drop-shadow(0 2px 8px #0008)}
 .hero h1{margin:0;font-size:21px;color:var(--fg2);letter-spacing:.2px}
 .hero .sub{color:var(--mut);font-size:12.5px;margin-top:5px;word-break:break-all}
 .hero .promise{font-style:italic;color:#7ee787;font-size:12.5px;margin-top:6px}
 .riskbox{margin-left:auto;text-align:center;background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 18px;min-width:140px}
 .riskbox .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.6px;color:var(--mut)}
 /* sticky nav */
 nav{position:sticky;top:0;z-index:9;background:#0d1117e6;backdrop-filter:blur(6px);border-bottom:1px solid var(--line);padding:8px 28px;font-size:12.5px}
 nav .inner{max-width:1140px;margin:auto;display:flex;gap:6px;flex-wrap:wrap}
 nav a{color:var(--mut);padding:3px 9px;border-radius:6px}
 nav a:hover{background:var(--panel2);color:var(--fg2);text-decoration:none}
 main{padding:26px 28px;max-width:1140px;margin:auto}
 section{margin-bottom:30px;scroll-margin-top:54px}
 h2{color:var(--fg2);font-size:17px;border-bottom:1px solid var(--line);padding-bottom:7px;margin-bottom:12px}
 h3{color:var(--fg2);font-size:14px;margin:14px 0 6px}
 table{border-collapse:collapse;width:100%;font-size:13px;background:var(--panel);border-radius:8px;overflow:hidden}
 th,td{border-bottom:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
 th{background:var(--panel2);color:var(--fg2);font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.3px}
 tbody tr:hover{background:#1c223080}
 .conf{font-weight:bold}
 .hi{color:#f85149}.med{color:#d29922}.lo{color:#8b949e}
 pre{background:var(--panel);border:1px solid var(--line);padding:12px;border-radius:8px;overflow:auto;font-size:12px;line-height:1.45}
 .pill{display:inline-block;background:#1f6feb22;border:1px solid var(--acc);color:#79c0ff;border-radius:10px;padding:1px 8px;font-size:11px;margin:1px}
 .reached{color:#7ee787}.notreached{color:#6e7681}
 .bar{background:#21262d;border-radius:5px;height:13px;overflow:hidden;min-width:90px}
 .bar>span{display:block;height:100%;background:linear-gradient(90deg,#238636,#2ea043)}
 .layer{border-left:3px solid var(--acc);padding:4px 0 4px 12px;margin:8px 0}
 .muted{color:var(--mut);font-size:12px}
 svg{background:var(--panel);border:1px solid var(--line);border-radius:8px;width:100%;height:auto}
 .badge{display:inline-block;border-radius:4px;padding:1px 7px;font-size:10.5px;font-weight:bold;text-transform:uppercase;letter-spacing:.3px}
 .b-obs{background:#23863633;border:1px solid #238636;color:#7ee787}
 .b-inf{background:#9e6a0322;border:1px solid #d29922;color:#e3b341}
 .b-spec{background:#6e768122;border:1px solid #6e7681;color:#8b949e}
 .summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-top:10px}
 .card{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:12px 14px;transition:border-color .15s}
 .card:hover{border-color:#475067}
 .card .k{color:var(--mut);font-size:10.5px;text-transform:uppercase;letter-spacing:.4px}
 .card .v{font-size:16px;color:var(--fg2);margin-top:4px}
 .banner{background:var(--panel);border:1px solid var(--line);border-left:4px solid #f0883e;border-radius:8px;padding:12px 16px;margin-top:10px}
 .risk{display:inline-block;border-radius:6px;padding:3px 14px;font-weight:bold;font-size:15px}
 .r-Critical{background:#f8514922;border:1px solid #f85149;color:#ff7b72}
 .r-High{background:#db6d2822;border:1px solid #db6d28;color:#f0883e}
 .r-Medium{background:#9e6a0322;border:1px solid #d29922;color:#e3b341}
 .r-Low{background:#23863622;border:1px solid #238636;color:#7ee787}
 .mat{display:inline-block;font-size:11px;margin-right:6px;padding:1px 6px;border-radius:5px;border:1px solid var(--line)}
 .mat-on{color:#7ee787;border-color:#238636}.mat-off{color:#8b949e}
 /* runtime placeholders + process tree */
 .ph{background:repeating-linear-gradient(45deg,#161b22,#161b22 10px,#171d27 10px,#171d27 20px);border:1px dashed #30363d;color:#8b949e}
 .ph .v{color:#8b949e}
 .tree{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow:auto}
 .tree .row{white-space:pre;line-height:1.7}
 .tree .pname{color:#7ee787}.tree .ppid{color:var(--mut)}.tree .cmd{color:#79c0ff}
 details{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:6px 12px;margin-top:8px}
 details>summary{cursor:pointer;color:var(--fg2);font-size:13px;padding:6px 0;user-select:none}
 details[open]>summary{border-bottom:1px solid var(--line);margin-bottom:8px}
 details table{border-radius:0}
 /* interactive graph */
 #rg .node{cursor:pointer}
 #rg.sel .node{opacity:.22}#rg.sel .edge{opacity:.12}
 #rg .node.on{opacity:1}#rg .edge.on{opacity:1;stroke:#79c0ff !important;stroke-width:2}
 #rg .node.on circle{stroke:#fff;stroke-width:2}
 .hint{color:var(--mut);font-size:11.5px;margin:6px 0}
 footer{color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:14px;margin-top:10px}
</style></head>
<body>
<div class="hero"><div class="hero-row">
 <img class="logo" src="{{ logo_uri }}" alt="SANDWORM"/>
 <div>
  <h1>SANDWORM — Reverse-Engineering Report</h1>
  <div class="sub">{{ sample_name }} · <code>{{ sha256 }}</code> · run <code>{{ run_id }}</code></div>
  <div class="promise">Given a sample, reconstruct what happened, explain why, and emit detections.</div>
 </div>
 <div class="riskbox">
  <div class="lbl">Risk · Score</div>
  <div style="margin:5px 0">{{ risk_pill(summary.risk)|safe }} <b>{{ summary.maliciousness_score }}</b><span class="muted">/100</span></div>
  <div class="muted">{{ summary.family_hint if summary.family_hint!='unknown' else fmt|upper }} · exec {{ 'Yes' if summary.execution_confirmed else 'No' }}</div>
 </div>
</div></div>
<nav><div class="inner">
 <a href="#summary">Summary</a><a href="#lifecycle">Lifecycle</a><a href="#runtime">Runtime</a><a href="#timeline-temporal">Timeline</a><a href="#graph">Reasoning graph</a>
 {% if layers %}<a href="#deobf">Deobfuscation</a>{% endif %}<a href="#attack">ATT&amp;CK</a>
 <a href="#findings">Findings</a><a href="#differential">Differential</a><a href="#iocs">IOCs</a><a href="#coverage">Coverage</a>
 <a href="#detections">Detections</a><a href="#assessment">Assessment</a><a href="#appendix">Evidence</a>
</div></nav>
<main>

<section id="summary">
 <h2>Executive summary</h2>
 {% if summary.family_hint != 'unknown' %}
 <div class="banner">Suspected family: <b>{{ summary.family_hint }}</b>
   — <b>static similarity {{ '%.0f'|format(summary.family_confidence*100) }}%</b>
   · attribution confidence: <b>{{ summary.family_confidence_label }}</b>
   <span class="muted">({{ summary.family_basis }})</span><br>
   matched markers: {% for mk in summary.family_markers %}<span class="pill">{{ mk }}</span>{% endfor %}
   <table style="max-width:560px;margin-top:8px"><tr><th>Attribution dimension</th><th>Status</th></tr>
   {% for dim, status in summary.family_components %}<tr><td>{{ dim }}</td><td class="muted">{{ status }}</td></tr>{% endfor %}</table>
   <span class="muted">Similarity is from static markers only — not a confirmed/behavioral attribution.</span></div>
 {% endif %}
 <div class="summary">
  <div class="card"><div class="k">Risk</div><div class="v">{{ risk_pill(summary.risk)|safe }}</div></div>
  <div class="card"><div class="k">Maliciousness</div><div class="v">{{ summary.maliciousness_score }}<span class="muted">/100</span>
     <div class="bar" style="margin-top:5px"><span style="width:{{ summary.maliciousness_score }}%"></span></div></div></div>
  <div class="card"><div class="k">Family</div><div class="v">{{ summary.family_hint }}{% if summary.family_hint != 'unknown' %} <span class="muted">({{ '%.0f'|format(summary.family_confidence*100) }}% static · {{ summary.family_confidence_label }})</span>{% endif %}</div></div>
  <div class="card"><div class="k">Primary capability</div><div class="v">{{ summary.primary_capability }}</div></div>
  <div class="card"><div class="k">Evidence maturity</div><div class="v">{% for lane, state in summary.evidence_maturity %}<span class="mat {{ 'mat-on' if state=='complete' else 'mat-off' }}">{{ '✓' if state=='complete' else '⏳' }} {{ lane }}</span>{% endfor %}</div></div>
  <div class="card"><div class="k">Highest inferred phase</div><div class="v">{{ summary.highest_inferred_phase }} <span class="muted">(static)</span></div></div>
  <div class="card"><div class="k">ATT&amp;CK techniques</div><div class="v">{{ summary.technique_count }} <span class="muted">({{ summary.network_indicator_count }} net IOC)</span></div></div>
 </div>
 <p class="muted" style="margin-top:10px"><b>Evidence breakdown:</b> {% for label, n in evidence_classes %}<span class="pill">{{ label }} {{ n }}</span>{% endfor %}</p>
 <p class="muted"><b>Evidence weight:</b>
   {% for label, n, hint in evidence_weights %}<span class="pill" title="{{ hint }}">{{ label }} {{ n }}</span>{% endfor %}
   <span class="muted">— a high raw count is mostly weak strings; the verdict rests on the <b>Strong</b> signals.</span></p>
</section>

<section id="lifecycle">
 <h2>Execution status &amp; lifecycle</h2>
 <p>Format: <span class="pill">{{ fmt }}</span> · Isolation: <span class="pill">{{ isolation }}</span>
    · Runtime observed: <b>{{ 'Yes' if summary.runtime_observed else 'No' }}</b></p>
 <p class="muted">Highest <b>observed</b> phase (runtime/memory-confirmed):
    <b class="reached">{{ summary.highest_observed_phase }}</b> ·
    Highest <b>inferred</b> phase (static capability):
    <b class="reached">{{ summary.highest_inferred_phase }}</b></p>
 <ul>{% for p in phases %}{% if p.reached %}<li>{{ p.summary }}</li>{% endif %}{% endfor %}</ul>
 <table>
  <tr><th>Phase</th><th>Status</th><th>Standing</th><th>Techniques</th></tr>
  {% for p in phases %}
  <tr><td>{{ p.name }}</td>
   <td>{% if p.reached %}<span class="reached">reached</span>{% else %}<span class="notreached">—</span>{% endif %}</td>
   <td>{% if p.reached %}{{ badge(p.status) }}{% endif %}</td>
   <td>{% for t in p.techniques %}<span class="pill">{{ t.technique_id }}</span>{% endfor %}</td></tr>
  {% endfor %}
 </table>
</section>

<section id="runtime">
 <h2>Runtime behaviour {% if not runtime.observed %}<span class="muted">— pending</span>{% endif %}</h2>
 {% if runtime_mismatch %}<div class="banner" style="border-left-color:#f85149"><b>⚠ Mismatched runtime evidence.</b> The ingested dynamic/memory report is from a <b>Windows/PE</b> sandbox run, but this sample is <b>{{ fmt }}</b>. The events below describe a <i>different</i> binary and are shown for demonstration only — they are <b>not</b> this file's behaviour. Provide a {{ fmt }}-appropriate report (or run static-only) for an accurate runtime section.</div>{% endif %}
 {% if runtime.observed %}
 <p class="muted">Observed during detonation / recovered from memory. These are <b>real events</b> (standing: observed), which upgrade the matching ATT&amp;CK techniques from inferred → observed.</p>
 <h3>Process tree</h3>
 {% if proc_tree %}
 <div class="tree">{% for n in proc_tree %}<div class="row">{{ n.indent }}<span class="pname">{{ n.name }}</span> <span class="ppid">(pid {{ n.pid }})</span>{% if n.command_line %}  <span class="cmd">{{ n.command_line }}</span>{% endif %}</div>{% endfor %}</div>
 {% else %}<p class="muted">No process-spawn events in the recovered evidence.</p>{% endif %}
 <div class="summary" style="margin-top:12px">
  <div class="card"><div class="k">Network</div><div class="v">{% if runtime.network %}{% for h in runtime.network %}<span class="pill">{{ h }}</span>{% endfor %}{% else %}<span class="muted">none</span>{% endif %}</div></div>
  <div class="card"><div class="k">Dropped files</div><div class="v">{% if runtime.files %}{% for f in runtime.files %}<span class="pill">{{ f }}</span>{% endfor %}{% else %}<span class="muted">none</span>{% endif %}</div></div>
  <div class="card"><div class="k">Registry writes</div><div class="v">{% if runtime.registry %}{% for r in runtime.registry %}<span class="pill">{{ r }}</span>{% endfor %}{% else %}<span class="muted">none</span>{% endif %}</div></div>
  <div class="card"><div class="k">Injected regions (memory)</div><div class="v">{% if runtime.injected %}{% for i in runtime.injected %}<span class="pill">{{ i }}</span>{% endfor %}{% else %}<span class="muted">none</span>{% endif %}</div></div>
 </div>
 {% if runtime.hidden or runtime.hooks or runtime.config %}
 <h3>Memory forensics</h3>
 <div class="summary">
  <div class="card"><div class="k">Hidden processes (unlinked EPROCESS)</div><div class="v">{% if runtime.hidden %}{% for h in runtime.hidden %}<span class="pill" style="border-color:#f85149;color:#ff7b72">{{ h }}</span>{% endfor %}{% else %}<span class="muted">none</span>{% endif %}</div></div>
  <div class="card"><div class="k">In-memory API hooks</div><div class="v">{% if runtime.hooks %}{% for h in runtime.hooks %}<span class="pill">{{ h }}</span>{% endfor %}{% else %}<span class="muted">none</span>{% endif %}</div></div>
  <div class="card"><div class="k">Config carved from heap</div><div class="v">{% if runtime.config %}{% for c in runtime.config %}<span class="pill" style="border-color:#bc8cff;color:#d2a8ff">{{ c }}</span>{% endfor %}{% else %}<span class="muted">none</span>{% endif %}</div></div>
 </div>
 <p class="muted">These are recovered from the memory image — they confirm <b>events</b> (a process that hid itself, an API patched in place, the actual C2/keys/encrypted-file tally), not just capability.</p>
 {% endif %}
 {% else %}
 <p class="muted">No runtime evidence for this run. The sample was not detonated (isolation not verified) and no recorded report was ingested, so these views are <b>pending</b>. They populate automatically once a dynamic/memory report is available — the section layout does not change, the cards simply fill in.</p>
 <div class="summary">
  <div class="card ph"><div class="k">⏳ Process tree</div><div class="v">Pending — requires detonation / CAPE report</div></div>
  <div class="card ph"><div class="k">⏳ Runtime behaviour</div><div class="v">Pending — API calls, network, dropped files</div></div>
  <div class="card ph"><div class="k">⏳ Memory analysis</div><div class="v">Pending — injected regions, hidden processes</div></div>
 </div>
 <p class="hint">ℹ️ Provide a recorded report offline: <code>sandworm analyze sample --cape-report report.json --memory-report mem.json</code> (replay ingests prior evidence; it is not a live detonation). Or detonate inside a verified isolated environment.</p>
 {% endif %}
</section>

<section id="timeline-temporal">
 <h2>Temporal timeline {% if not temporal.observed %}<span class="muted">— pending</span>{% endif %}</h2>
 {% if temporal.observed %}
 <p class="muted">The order events happened in, reconstructed from recorded relative offsets. Malware is a story: <i>checked for analysis → called home → persisted → encrypted</i> is actionable; "it encrypted files" is not.</p>
 {{ temporal_svg|safe }}
 <div class="tree" style="margin-top:10px">{% for e in temporal.events %}<div class="row"><span class="ppid">{{ "%-11s"|format(e.label) }}</span>{% if e.abs_time %}<span class="muted">{{ e.abs_time }}  </span>{% endif %}<span style="color:{{ e.color }}">●</span> <span class="pname">{{ e.text }}</span> <span class="muted">[{{ e.status }}]</span></div>{% endfor %}</div>
 {% else %}
 <p class="muted">No timed events for this run. A relative-offset timeline populates from the dynamic lane (CAPE/DRAKVUF API-call timestamps); a static-only run has no observed timing to plot, so this stays <b>pending</b> rather than inventing an order.</p>
 {% endif %}
</section>

<section id="graph">
 <h2>Reasoning graph</h2>
 <div class="muted">{{ graph_stats }}</div>
 <p class="hint">💡 Click any node to trace its reasoning chain (Sample → Indicator → Capability → ATT&amp;CK → Detection). Click empty space to reset.</p>
 <p class="muted" style="margin:2px 0 8px">{% for color, label in graph_legend %}<span style="display:inline-block;margin-right:12px"><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:{{ color }};margin-right:5px;vertical-align:middle"></span>{{ label }}</span>{% endfor %}</p>
 {{ graph_svg|safe }}
 <script>
 (function(){
  var svg=document.getElementById('rg'); if(!svg)return;
  var nodes=[].slice.call(svg.querySelectorAll('.node'));
  var edges=[].slice.call(svg.querySelectorAll('.edge'));
  var adj={}; edges.forEach(function(e){
    var s=e.getAttribute('data-s'),d=e.getAttribute('data-d');
    (adj[s]=adj[s]||[]).push(d);(adj[d]=adj[d]||[]).push(s);
  });
  function reset(){svg.classList.remove('sel');nodes.forEach(function(n){n.classList.remove('on')});edges.forEach(function(e){e.classList.remove('on')});}
  function pick(i){
    reset();svg.classList.add('sel');
    var keep={}; keep[i]=1; (adj[i]||[]).forEach(function(x){keep[x]=1});
    nodes.forEach(function(n){if(keep[n.getAttribute('data-i')])n.classList.add('on')});
    edges.forEach(function(e){var s=e.getAttribute('data-s'),d=e.getAttribute('data-d');if(s==i||d==i)e.classList.add('on')});
  }
  nodes.forEach(function(n){n.addEventListener('click',function(ev){ev.stopPropagation();pick(n.getAttribute('data-i'));});});
  svg.addEventListener('click',reset);
 })();
 </script>
</section>

{% if layers %}
<section id="deobf">
 <h2>Deobfuscation — {{ layers|length }} layer(s) peeled</h2>
 {% for l in layers %}
 <div class="layer"><b>layer {{ l.depth }}</b> via <code>{{ l.function }}</code> ({{ l.wrapper }})
   → {{ l.after_len }} bytes<br><span class="muted">{{ l.after }}</span></div>
 {% endfor %}
 {% if final_payload %}<h3>Deobfuscated payload</h3><pre>{{ final_payload }}</pre>{% endif %}
</section>
{% endif %}

<section id="attack">
 <h2>ATT&amp;CK mapping <span class="muted">(every mapping explains <i>why</i>; standing = observed vs inferred)</h2>
 <table>
  <tr><th>Technique</th><th>Tactic</th><th>Standing</th><th class="conf">Confidence</th><th>Why</th><th>Evidence</th></tr>
  {% for m in mappings %}
  {% set bd = breakdowns[m.technique_id] %}
  <tr>
   <td><b>{{ m.technique_id }}</b><br>{{ m.technique_name }}</td>
   <td>{{ m.tactic }}</td>
   <td>{{ badge(m.status) }}</td>
   <td class="conf {{ conf_class(m.confidence) }}">{{ '%.2f'|format(m.confidence) }}</td>
   <td>{{ m.why }}</td>
   <td class="muted">{% for e in m.evidence_ids[:4] %}<a href="#{{ e }}">{{ e }}</a><br>{% endfor %}</td>
  </tr>
  <tr><td colspan="6" class="muted" style="background:#0d1117">
     <b>Why {{ '%.2f'|format(m.confidence) }}?</b> signals: {% for s in bd.signals %}<span class="pill">+ {{ s }}</span>{% endfor %}
     <br>by method: {% for meth, p in bd.by_method.items() %}<span class="pill">{{ meth }} {{ p }}%</span>{% endfor %}
     &nbsp;·&nbsp; by lane: {% for s, p in bd.by_source.items() %}<span class="pill">{{ s }} {{ p }}%</span>{% endfor %}
     &nbsp;·&nbsp; <b>timeline</b>: {% for lane, val in bd.lane_timeline() %}{{ lane }} <b>{{ val }}</b>{% if not loop.last %} → {% endif %}{% endfor %}
  </td></tr>
  {% endfor %}
 </table>
 <p class="muted">The confidence timeline shows the static value now and what the dynamic / memory lanes would still contribute (<i>pending</i> until detonation / memory analysis runs).</p>
</section>

<section id="findings">
 <h2>{{ 'Runtime timeline &amp; analysis findings' if summary.runtime_observed else 'Analysis findings' }}</h2>
 <p class="muted">{% if summary.runtime_observed %}Observed events are runtime/memory-confirmed; inferred rows are static findings.{% else %}Static-only run: these are <b>findings about the binary's capabilities</b>, not observed runtime events.{% endif %}</p>
 <details {{ 'open' if timeline|length <= 12 else '' }}><summary>{{ timeline|length }} finding(s)</summary>
 <table><tr><th>#</th><th>Source</th><th>Standing</th><th>Finding / event</th><th class="conf">Conf</th></tr>
 {% for e in timeline %}
 <tr><td>{{ e.seq }}</td><td class="muted">{{ e.source }}</td><td>{{ badge(e.status) }}</td><td>{{ e.text }}</td>
     <td class="{{ conf_class(e.confidence) }}">{{ '%.2f'|format(e.confidence) }}</td></tr>
 {% endfor %}
 </table>
 </details>
</section>

<section id="differential">
 <h2>Behaviour under differential conditions</h2>
 {% if differential %}
 <p class="muted">The sample was run under multiple conditions; behaviour that appears only under one condition reveals environment checks and dormant/staged payloads.</p>
 {% for d in differential %}
 <div class="banner"><b>{{ d.condition_a }}</b> vs <b>{{ d.condition_b }}</b> — {{ d.note }}
  {% if d.only_in_a %}<br><span class="muted">only under {{ d.condition_a }}:</span> {% for x in d.only_in_a %}<span class="pill">{{ x }}</span>{% endfor %}{% endif %}
  {% if d.only_in_b %}<br><span class="muted">only under {{ d.condition_b }}:</span> {% for x in d.only_in_b %}<span class="pill">{{ x }}</span>{% endfor %}{% endif %}
 </div>
 {% endfor %}
 {% else %}
 <p class="muted">Not run for this sample. Differential analysis (e.g. network on/off, Office present/absent) is a <b>dynamic-lane</b> capability — it executes the sample under several conditions and diffs the resulting evidence to expose staged downloaders and dormant payloads. Enable detonation in a verified isolated environment to populate this section.</p>
 {% endif %}
</section>

<section id="iocs">
 <h2>Indicators of Compromise</h2>
 {% if iocs %}
 <table><tr><th>Type</th><th>Value</th><th class="conf">Conf</th><th>FP risk</th></tr>
 {% for i in iocs %}
 <tr><td>{{ i.kind }}</td><td><code>{{ i.value }}</code></td>
     <td class="{{ conf_class(i.confidence) }}">{{ '%.2f'|format(i.confidence) }}</td>
     <td>{{ i.fp_risk }}</td></tr>
 {% endfor %}</table>
 {% else %}<p class="muted">No network IOCs extracted.</p>{% endif %}
 {% if library %}
 <details><summary>{{ library|length }} library / toolchain artifact(s) — benign, excluded from IOCs &amp; C2</summary>
  <p class="muted">Compiler/SDK/registry references (e.g. Go modules, package hosts). Surfaced for context; they are <b>not</b> C2 infrastructure.</p>
  {% for l in library %}<span class="pill">{{ l }}</span>{% endfor %}
 </details>
 {% endif %}
</section>

<section id="coverage">
 <h2>Detection coverage</h2>
 <p>Sample is <b>{{ 'DETECTABLE' if coverage.detectable else 'not yet detectable' }}</b> by
    {{ coverage.inventory.yara_rules }} YARA + {{ coverage.inventory.behavioral_rules + coverage.inventory.ioc_rules }} Sigma generated rule(s).
    <br>Technique-level rule coverage: <b>{{ '%.0f'|format(coverage.overall*100) }}%</b>
    ({{ coverage.inferred_techniques }} inferred technique(s), of which those with a dedicated behavioural/IOC rule are marked below).
    Runtime coverage of <b>observed</b> techniques: <b>{{ '%.0f%%'|format(coverage.runtime_coverage*100) if coverage.runtime_coverage is not none else 'N/A (nothing executed)' }}</b>.</p>
 {% if coverage.detectable and coverage.overall < 0.5 %}<p class="hint">ℹ️ A low technique-level percentage does not mean the sample is undetected — a YARA signature already flags it. It means few techniques have a dedicated <i>behavioural</i> rule, which typically requires dynamic evidence.</p>{% endif %}
 <h3>Detection readiness: <span class="risk r-{{ 'High' if readiness_level=='High' else 'Medium' if readiness_level=='Medium' else 'Low' }}">{{ readiness_level }}</span></h3>
 <div class="summary">
 {% for label, ok in readiness_rows %}
  <div class="card"><div class="k">{{ label }}</div><div class="v">{{ '✓ available' if ok else '— none' }}</div></div>
 {% endfor %}
 </div>
 <div class="summary">
  <div class="card"><div class="k">Inferred ATT&amp;CK</div><div class="v">{{ coverage.inferred_techniques }}</div></div>
  <div class="card"><div class="k">Observed ATT&amp;CK</div><div class="v">{{ coverage.observed_techniques }}</div></div>
  <div class="card"><div class="k">Behavioral rules</div><div class="v">{{ coverage.inventory.behavioral_rules }}</div></div>
  <div class="card"><div class="k">IOC rules</div><div class="v">{{ coverage.inventory.ioc_rules }}</div></div>
  <div class="card"><div class="k">YARA rules</div><div class="v">{{ coverage.inventory.yara_rules }}</div></div>
  <div class="card"><div class="k">Runtime rules</div><div class="v">{{ coverage.inventory.runtime_rules }} <span class="muted">(needs dynamic)</span></div></div>
 </div>
 <table><tr><th>Tactic</th><th>Observed</th><th>Covered</th><th>Score</th></tr>
 {% for t in coverage.per_tactic %}
 <tr><td>{{ t.tactic }}</td>
     <td>{% for x in t.observed %}<span class="pill">{{ x }}</span>{% endfor %}</td>
     <td>{% for x in t.covered %}<span class="pill">{{ x }}</span>{% endfor %}</td>
     <td><div class="bar"><span style="width:{{ (t.score*100)|int }}%"></span></div></td></tr>
 {% endfor %}</table>
</section>

<section id="detections">
 <h2>Generated detections</h2>
 <h3>YARA</h3>
 {% if yara %}{% for r in yara %}<pre>{{ r.to_yara() }}</pre>{% endfor %}
 <p class="muted">All rules verified against the bundled clean corpus (no false positives).</p>
 {% else %}<p class="muted">No clean-passing YARA rule could be synthesized.</p>{% endif %}
 <h3>Sigma <span class="muted">(behavioral rules survive infrastructure changes; IOC rules match rotating atoms)</span></h3>
 {% if sigma %}{% for r in sigma %}<div class="muted">{{ badge('inferred') if r.kind=='ioc' else badge('observed') }} {{ r.kind }} rule</div><pre>{{ r.to_yaml() }}</pre>{% endfor %}
 {% else %}<p class="muted">No behavioral Sigma rule generated.</p>{% endif %}
</section>

<section id="assessment">
 <h2>Analyst assessment</h2>
 <div class="summary">
  <div class="card"><div class="k">Risk</div><div class="v">{{ risk_pill(summary.risk)|safe }}</div></div>
  <div class="card"><div class="k">Likelihood</div><div class="v">{{ summary.likelihood }}</div></div>
  <div class="card"><div class="k">Maliciousness score</div><div class="v">{{ summary.maliciousness_score }}/100</div></div>
  <div class="card"><div class="k">Execution confirmed</div><div class="v">{{ 'Yes' if summary.execution_confirmed else 'No' }}</div></div>
 </div>
 <p><b>Score breakdown:</b></p>
 <table style="max-width:520px"><tr><th>Factor</th><th>Points</th></tr>
 {% for label, pts in summary.score_factors %}
 <tr><td>{{ label }}</td><td class="{{ 'reached' if pts>=0 else 'hi' }}">{{ '+' if pts>=0 else '' }}{{ pts }}</td></tr>
 {% endfor %}
 <tr><td><b>Total</b></td><td><b>{{ summary.maliciousness_score }}/100</b></td></tr>
 </table>
 <p><b>Rationale:</b></p>
 <ul>{% for r in summary.risk_reasons %}<li>{{ r }}</li>{% endfor %}</ul>
 <div class="banner">{{ assessment|safe }}</div>
 <p><b>Recommended next step:</b> {{ next_step }}</p>
</section>

<section id="appendix">
 <h2>Evidence appendix <span class="muted">(every claim above is auditable here)</span></h2>
 <details {{ 'open' if appendix|length <= 10 else '' }}><summary>{{ appendix|length }} evidence item(s) — click an evidence id above to jump here</summary>
 <table><tr><th>ID</th><th>Source</th><th>Standing</th><th class="conf">Conf</th><th>Observation</th><th>Raw refs</th></tr>
 {% for e in appendix %}
 <tr id="{{ e.id }}"><td class="muted">{{ e.id }}</td><td class="muted">{{ e.source }}</td>
     <td>{{ badge(e.status) }}</td>
     <td class="{{ conf_class(e.confidence) }}">{{ '%.2f'|format(e.confidence) }}</td>
     <td>{{ e.summary }}</td>
     <td class="muted">{{ e.refs }}<br><span class="muted">{{ e.ts }}</span></td></tr>
 {% endfor %}
 </table>
 </details>
</section>

<footer class="muted">Generated by SANDWORM · all analysis performed offline · no sample bytes executed without verified isolation.</footer>
</main></body></html>
"""


@dataclass
class ReportInputs:
    run_id: str
    sample_name: str
    sha256: str
    fmt: str
    isolation: str
    store: EvidenceStore
    mappings: list[AttackMapping]
    phases: list[Phase]
    timeline: list[TimelineEntry]
    yara: list[YaraRule]
    sigma: list[SigmaRule]
    coverage: CoverageReport
    graph: object | None = None


def _conf_class(c: float) -> str:
    return "hi" if c >= 0.75 else "med" if c >= 0.5 else "lo"


def _collect_layers(store: EvidenceStore):
    layers = []
    final = ""
    for it in store:
        if it.operation == "decode" and "layer" in it.object:
            layers.append(
                {
                    "depth": it.object.get("layer"),
                    "function": it.object.get("function"),
                    "wrapper": it.details.get("wrapper", ""),
                    "after": escape(str(it.details.get("decoded_preview", ""))),
                    "after_len": it.details.get("decoded_len", 0),
                }
            )
        if it.object.get("artifact") == "deobfuscated_payload":
            final = escape(str(it.details.get("final_payload_preview", "")))
    layers.sort(key=lambda x: x["depth"] if isinstance(x["depth"], int) else 0)
    return layers, final


def _collect_iocs(store: EvidenceStore):
    out = []
    for it in store:
        if it.details.get("ioc"):
            out.append(
                type("IOC", (), {
                    "kind": it.object.get("kind"),
                    "value": escape(str(it.object.get("value"))),
                    "confidence": it.confidence,
                    "fp_risk": it.details.get("false_positive_risk", "?"),
                })
            )
    return out


def _collect_library(store: EvidenceStore):
    """Benign toolchain/SDK references, kept OUT of the IOC list (reviewer ask:
    separate library artifacts from network IOCs)."""
    return [escape(str(it.object.get("library_artifact"))) for it in store if it.details.get("library_artifact")]


def _evidence_classes(store: EvidenceStore, mappings) -> list[tuple[str, int]]:
    """Break the raw evidence count into analyst-friendly classes."""
    iocs = caps = imports = sinks = strings = libs = decode = 0
    for it in store:
        o, d = it.object, it.details
        if d.get("library_artifact"):
            libs += 1
        elif d.get("ioc"):
            iocs += 1
        elif o.get("capability"):
            caps += 1
        elif o.get("import") or o.get("symbol"):
            imports += 1
        elif o.get("sink"):
            sinks += 1
        elif it.operation == "decode":
            decode += 1
        else:
            strings += 1
    classes = [
        ("ATT&CK techniques", len(mappings)),
        ("Capabilities", caps),
        ("Execution sinks", sinks),
        ("Imports/symbols", imports),
        ("IOCs", iocs),
        ("Deobfuscation layers", decode),
        ("Other strings", strings),
        ("Library artifacts", libs),
    ]
    return [(label, n) for label, n in classes if n]


def _detection_readiness(coverage, iocs, runtime) -> tuple[str, list[tuple[str, bool]]]:
    """Can a SOC actually detect this sample, and with what? Returns (level, rows).

    The matrix the reviewer asked for: YARA / Sigma-IOC / Sigma-behaviour /
    Network / Memory — each a concrete ✓ or ✗ a SOC can act on."""
    inv = coverage.inventory
    has_net = any(getattr(i, "kind", "") in {"url", "domain", "ipv4"} for i in iocs)
    rows = [
        ("YARA signature", inv.yara_rules > 0),
        ("Sigma (IOC)", inv.ioc_rules > 0),
        ("Sigma (behavioural)", inv.behavioral_rules > 0),
        ("Network IOC", has_net),
        ("Memory / runtime", bool(getattr(runtime, "observed", False)) or inv.runtime_rules > 0),
    ]
    score = sum(1 for _, ok in rows if ok)
    level = "High" if (inv.behavioral_rules and inv.yara_rules) else "Medium" if score >= 2 else "Low" if score else "None"
    return level, rows


def _evidence_weights(store: EvidenceStore, mappings) -> list[tuple[str, int, str]]:
    """Weight evidence Strong/Medium/Weak so a high raw count (e.g. 30 items) is
    not mistaken for 30 strong signals. Strong = runtime-observed, a capability, a
    sink, or anything backing an ATT&CK mapping; Medium = imports/symbols/decoded
    layers; Weak = loose strings / benign library artifacts."""
    mapped_ids = {eid for m in mappings for eid in m.evidence_ids}
    strong = medium = weak = 0
    for it in store:
        o, d = it.object, it.details
        if o.get("status") == "skipped":
            continue
        if d.get("library_artifact"):
            weak += 1
        elif it.source.startswith(("dynamic.", "memory.")) or o.get("capability") or o.get("sink") \
                or o.get("verdict") or it.id in mapped_ids:
            strong += 1
        elif o.get("import") or o.get("symbol") or it.operation == "decode" or d.get("ioc"):
            medium += 1
        else:
            weak += 1
    return [
        ("Strong", strong, "mapped to ATT&CK / observed / capability / sink"),
        ("Medium", medium, "imports, decoded layers, IOC atoms"),
        ("Weak", weak, "loose strings, benign toolchain artifacts"),
    ]


def _collect_differential(store: EvidenceStore):
    """Differential-analysis findings (behaviour that changed across conditions —
    network on/off, etc.). First-class because environment-sensitive behaviour is
    one of the strongest signals of staged/dormant malware."""
    out = []
    for it in store:
        if it.source == "enrich.differential":
            conds = it.object.get("conditions", ["A", "B"])
            out.append(
                type("Diff", (), {
                    "condition_a": escape(str(conds[0])),
                    "condition_b": escape(str(conds[1] if len(conds) > 1 else "?")),
                    "note": escape(str(it.details.get("note", ""))),
                    "only_in_a": [escape(str(x)) for x in it.details.get("only_in_a", [])],
                    "only_in_b": [escape(str(x)) for x in it.details.get("only_in_b", [])],
                })
            )
    return out


# Reasoning-graph tiers: read left → right as Sample → evidence-entity →
# capability → technique → detection. Evidence nodes are hidden (they back the
# drill-down/citations but would clutter the picture).
_TIER = {"Sample": 0, "Module": 1, "File": 1, "Host": 1, "Registry": 1, "Macro": 1,
         "String": 1, "ApiCall": 1, "Process": 1, "Capability": 2, "Technique": 3, "Detection": 4}
_TIER_LABELS = ["Sample", "Indicators", "Capability", "ATT&CK", "Detection"]
# Colour reads left→right as the reasoning chain: Sample (amber) → Indicators
# (blue, with network hosts in red since C2 is the highest-signal indicator) →
# Capability (purple) → ATT&CK (orange) → Detection (green).
_IND_BLUE = "#58a6ff"
_COLORS = {
    "Sample": "#e3b341",
    "Process": _IND_BLUE, "File": _IND_BLUE, "Registry": _IND_BLUE, "Module": _IND_BLUE,
    "Macro": _IND_BLUE, "ApiCall": _IND_BLUE, "String": _IND_BLUE,
    "Host": "#f85149",
    "Capability": "#bc8cff", "Technique": "#f0883e", "Detection": "#3fb950",
}
# (swatch colour, label) legend rendered under the graph.
_GRAPH_LEGEND = [
    ("#e3b341", "Sample"), (_IND_BLUE, "Indicator"), ("#f85149", "Network / C2"),
    ("#bc8cff", "Capability"), ("#f0883e", "ATT&CK technique"), ("#3fb950", "Detection"),
]


def _graph_svg(graph, max_per_tier: int = 12) -> tuple[str, str]:
    """Layered reasoning graph: a left→right chain with typed, labelled edges."""
    if graph is None:
        return "<svg viewBox='0 0 10 10'></svg>", "no graph"
    all_nodes = list(graph.nodes.values()) if hasattr(graph, "nodes") else []
    edges = list(graph.edges) if hasattr(graph, "edges") else []
    nodes = [n for n in all_nodes if n.label != "Evidence"]
    if not nodes:
        return "<svg viewBox='0 0 10 10'></svg>", "empty graph"

    # Bucket nodes by tier, cap each tier for legibility.
    tiers: dict[int, list] = {i: [] for i in range(5)}
    for n in nodes:
        tiers[_TIER.get(n.label, 1)].append(n)
    for i in tiers:
        tiers[i] = tiers[i][:max_per_tier]
    kept = {n.id for col in tiers.values() for n in col}

    w, h = 1100, 600
    col_x = [90, 330, 560, 790, 1010]
    pos: dict[str, tuple[float, float]] = {}
    for tier, col in tiers.items():
        k = len(col)
        for i, node in enumerate(col):
            y = (h - 40) * (i + 1) / (k + 1) + 20
            pos[node.id] = (col_x[tier], y)

    # Stable integer index per kept node (safe to embed in data-attributes,
    # unlike raw node ids which can contain sample-controlled characters).
    idx = {nid: i for i, nid in enumerate(kept)}

    parts = [f"<svg id='rg' viewBox='0 0 {w} {h}' xmlns='http://www.w3.org/2000/svg'>"]
    for tier, label in enumerate(_TIER_LABELS):
        parts.append(f"<text x='{col_x[tier]:.0f}' y='14' fill='#6e7681' font-size='11' text-anchor='middle'>{escape(label)}</text>")
    # edges (classed + index refs so JS can highlight a node's chain)
    for e in edges:
        if e.src in pos and e.dst in pos and e.src in kept and e.dst in kept:
            x1, y1 = pos[e.src]
            x2, y2 = pos[e.dst]
            parts.append(
                f"<line class='edge' data-s='{idx[e.src]}' data-d='{idx[e.dst]}' "
                f"x1='{x1:.0f}' y1='{y1:.0f}' x2='{x2:.0f}' y2='{y2:.0f}' stroke='#30363d' stroke-width='1'/>"
            )
            if e.rel in {"INDICATES", "DETECTED_BY", "CONTAINS"} and abs(x2 - x1) > 60:
                mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - 2
                parts.append(f"<text x='{mx:.0f}' y='{my:.0f}' fill='#484f58' font-size='8' text-anchor='middle'>{e.rel.lower()}</text>")
    # nodes (clickable groups)
    for node in nodes:
        if node.id not in pos:
            continue
        x, y = pos[node.id]
        color = _COLORS.get(node.label, "#8b949e")
        label = escape(str(node.props.get("display", node.id))[:24])
        anchor = "end" if _TIER.get(node.label, 1) == 4 else "start"
        dx = -11 if anchor == "end" else 11
        title = escape(f"{node.label}: {node.props.get('display', node.id)}")
        parts.append(
            f"<g class='node' data-i='{idx[node.id]}'><title>{title}</title>"
            f"<circle cx='{x:.0f}' cy='{y:.0f}' r='7' fill='{color}'/>"
            f"<text x='{x+dx:.0f}' y='{y+4:.0f}' fill='#c9d1d9' font-size='10' text-anchor='{anchor}'>{label}</text></g>"
        )
    parts.append("</svg>")
    stats = f"{len(kept)} nodes across {sum(1 for c in tiers.values() if c)} reasoning tiers, {len(edges)} typed edges (Evidence hidden)"
    return "".join(parts), stats


_BADGE = {"observed": "b-obs", "inferred": "b-inf", "speculative": "b-spec"}


def _badge(status: str) -> str:
    cls = _BADGE.get(status, "b-spec")
    return f'<span class="badge {cls}">{escape(str(status))}</span>'


def _risk_pill(risk: str) -> str:
    safe = risk if risk in {"Critical", "High", "Medium", "Low"} else "Low"
    return f'<span class="risk r-{safe}">{escape(str(risk))}</span>'


def _evidence_summary(it) -> str:
    obj = {k: v for k, v in it.object.items() if isinstance(v, (str, int, float, bool, list))}
    bits = ", ".join(f"{k}={v}" for k, v in obj.items()) or it.artifact
    return escape(f"{it.operation} — {bits}")[:300]


def _build_appendix(store: EvidenceStore):
    from ..core.provenance import provenance_of

    rows = []
    for it in store:
        rows.append(
            type("Ev", (), {
                "id": it.id,
                "source": it.source,
                "status": provenance_of(it.source, it.confidence),
                "confidence": it.confidence,
                "summary": _evidence_summary(it),
                "refs": escape(", ".join(it.evidence_refs) or "—"),
                "ts": escape(str(it.ts)),
            })
        )
    return rows


def _build_assessment(summary, phases) -> tuple[str, str]:
    """Generate the analyst assessment paragraph + recommended next step, phrased
    to respect epistemic standing (static-only = capabilities, not confirmation)."""
    fam = summary.family_hint
    caps = summary.primary_capability
    sims = [f"<b>Assessed risk: {escape(summary.risk)}</b> (likelihood {escape(summary.likelihood)} that this is malicious)."]
    if fam != "unknown":
        sims.append(f"This sample <b>statically resembles {escape(fam)}</b> ({summary.family_confidence:.0%} marker similarity).")
    sims.append(f"Static analysis identified its primary capability as <b>{escape(caps)}</b>"
                f" across {summary.technique_count} ATT&amp;CK technique(s) and {summary.network_indicator_count} network indicator(s).")
    if not summary.runtime_observed:
        sims.append("Because execution was intentionally prevented (isolation not verified), "
                    "network behavior, persistence, and encryption activity remain <b>unconfirmed</b> — "
                    "every technique above is an <i>inference</i> from the binary's contents, not an observed event.")
        nxt = ("Run the sample inside a verified isolated detonation environment "
               "(see docs/handling-real-samples.md) to validate the inferred behavior and upgrade "
               "the confidence timeline from static → dynamic → memory.")
    else:
        sims.append(f"Runtime behavior was observed; the highest confirmed phase was "
                    f"<b>{escape(summary.highest_observed_phase)}</b>.")
        nxt = "Capture a memory image post-detonation to corroborate injection/credential-access findings."
    return " ".join(sims), nxt


def render_html(inp: ReportInputs) -> str:
    env = Environment(autoescape=False)
    env.globals["conf_class"] = _conf_class
    env.globals["badge"] = _badge
    env.globals["risk_pill"] = _risk_pill
    tmpl = env.from_string(_TEMPLATE)
    layers, final_payload = _collect_layers(inp.store)
    iocs = _collect_iocs(inp.store)
    library = _collect_library(inp.store)
    differential = _collect_differential(inp.store)
    from ..reconstruct.runtime import build_runtime_view

    runtime = build_runtime_view(inp.store)
    # A Windows/PE sandbox report ingested for a non-PE sample describes a
    # different binary — warn so the runtime section is not read as this file's.
    _win_runtime = any(it.source == "dynamic.windows.cape" or it.source == "memory.vol3" for it in inp.store)
    runtime_mismatch = bool(runtime.observed and _win_runtime and inp.fmt not in {"pe", "dll", "unknown", "(replayed)", ""})
    proc_tree = [
        type("PT", (), {
            "name": escape(n.name),
            "pid": escape(n.pid),
            "command_line": escape(n.command_line[:80]),
            "indent": ("│  " * (n.depth - 1) + "└─ ") if n.depth else "",
        })
        for n in runtime.flatten()
    ]
    evidence_classes = _evidence_classes(inp.store, inp.mappings)
    evidence_weights = _evidence_weights(inp.store, inp.mappings)
    readiness_level, readiness_rows = _detection_readiness(inp.coverage, iocs, runtime)
    graph_svg, graph_stats = _graph_svg(inp.graph)
    from ..reconstruct.temporal import build_temporal_timeline, render_timeline_svg
    temporal = build_temporal_timeline(inp.store)
    temporal_svg = render_timeline_svg(temporal)
    isolated = inp.isolation.startswith("verified")
    summary = build_summary(inp.store, inp.mappings, inp.phases, isolated=isolated)
    breakdowns = {m.technique_id: confidence_breakdown(inp.store, m) for m in inp.mappings}
    assessment, next_step = _build_assessment(summary, inp.phases)
    appendix = _build_appendix(inp.store)
    return tmpl.render(
        logo_uri=LOGO_DATA_URI,
        run_id=inp.run_id,
        sample_name=escape(inp.sample_name),
        sha256=inp.sha256,
        fmt=inp.fmt,
        isolation=inp.isolation,
        summary=summary,
        phases=inp.phases,
        mappings=inp.mappings,
        breakdowns=breakdowns,
        timeline=inp.timeline,
        layers=layers,
        final_payload=final_payload,
        iocs=iocs,
        library=library,
        differential=differential,
        evidence_classes=evidence_classes,
        evidence_weights=evidence_weights,
        runtime=runtime,
        runtime_mismatch=runtime_mismatch,
        proc_tree=proc_tree,
        temporal=temporal,
        temporal_svg=temporal_svg,
        graph_legend=_GRAPH_LEGEND,
        readiness_level=readiness_level,
        readiness_rows=readiness_rows,
        yara=inp.yara,
        sigma=inp.sigma,
        coverage=inp.coverage,
        graph_svg=graph_svg,
        graph_stats=graph_stats,
        assessment=assessment,
        next_step=next_step,
        appendix=appendix,
    )


def write_report(inp: ReportInputs, path: str | Path) -> Path:
    html = render_html(inp)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
    return p

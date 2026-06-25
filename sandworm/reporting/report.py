"""Self-contained HTML report (jinja2).

Renders the attack narrative, the behavioral graph (inline SVG, no external JS),
the timeline, the ATT&CK mapping with per-technique evidence + confidence, IOCs
with confidence/FP-risk, the generated YARA + Sigma, and the coverage score. No
network calls happen at render time — everything is inlined.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from html import escape
from pathlib import Path

from jinja2 import Environment

from ..core.evidence import EvidenceStore
from ..detect.sigma_gen import SigmaRule
from ..detect.yara_gen import YaraRule
from ..reconstruct.attack_map import AttackMapping
from ..reconstruct.narrative import Phase, furthest_phase
from ..reconstruct.timeline import TimelineEntry
from ..reporting.coverage import CoverageReport

_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SANDWORM report — {{ sample_name }}</title>
<style>
 body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
 header{background:#161b22;padding:18px 28px;border-bottom:1px solid #30363d}
 h1{margin:0;font-size:20px;color:#e6edf3} h2{color:#e6edf3;border-bottom:1px solid #30363d;padding-bottom:6px}
 .sub{color:#8b949e;font-size:13px;margin-top:4px}
 main{padding:24px 28px;max-width:1100px;margin:auto}
 section{margin-bottom:34px}
 .promise{font-style:italic;color:#7ee787}
 table{border-collapse:collapse;width:100%;font-size:13px}
 th,td{border:1px solid #30363d;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#161b22}
 .conf{font-weight:bold}
 .hi{color:#f85149}.med{color:#d29922}.lo{color:#8b949e}
 pre{background:#161b22;border:1px solid #30363d;padding:12px;border-radius:6px;overflow:auto;font-size:12px}
 .pill{display:inline-block;background:#1f6feb22;border:1px solid #1f6feb;color:#79c0ff;border-radius:10px;padding:1px 8px;font-size:11px;margin:1px}
 .reached{color:#7ee787}.notreached{color:#6e7681}
 .bar{background:#21262d;border-radius:4px;height:14px;overflow:hidden}
 .bar>span{display:block;height:100%;background:#238636}
 .layer{border-left:3px solid #1f6feb;padding-left:10px;margin:8px 0}
 .muted{color:#8b949e;font-size:12px}
 svg{background:#161b22;border:1px solid #30363d;border-radius:6px;width:100%;height:auto}
</style></head>
<body>
<header>
 <h1>🪱 SANDWORM — Reverse-Engineering Report</h1>
 <div class="sub">{{ sample_name }} · sha256 <code>{{ sha256 }}</code> · run <code>{{ run_id }}</code></div>
 <div class="promise">Given a sample, reconstruct what happened, explain why, and emit detections.</div>
</header>
<main>

<section>
 <h2>Attack narrative &amp; lifecycle</h2>
 <p>Format: <span class="pill">{{ fmt }}</span> · Isolation: <span class="pill">{{ isolation }}</span>
    · Execution reached: <b class="reached">{{ furthest }}</b></p>
 <ul>{% for p in phases %}{% if p.reached %}<li>{{ p.summary }}</li>{% endif %}{% endfor %}</ul>
 <table>
  <tr><th>Phase</th><th>Status</th><th>Techniques</th></tr>
  {% for p in phases %}
  <tr><td>{{ p.name }}</td>
   <td>{% if p.reached %}<span class="reached">reached</span>{% else %}<span class="notreached">—</span>{% endif %}</td>
   <td>{% for t in p.techniques %}<span class="pill">{{ t.technique_id }}</span>{% endfor %}</td></tr>
  {% endfor %}
 </table>
</section>

<section>
 <h2>Behavioral graph</h2>
 <div class="muted">{{ graph_stats }}</div>
 {{ graph_svg|safe }}
</section>

{% if layers %}
<section>
 <h2>Deobfuscation — {{ layers|length }} layer(s) peeled</h2>
 {% for l in layers %}
 <div class="layer"><b>layer {{ l.depth }}</b> via <code>{{ l.function }}</code> ({{ l.wrapper }})
   → {{ l.after_len }} bytes<br><span class="muted">{{ l.after }}</span></div>
 {% endfor %}
 {% if final_payload %}<h3>Deobfuscated payload</h3><pre>{{ final_payload }}</pre>{% endif %}
</section>
{% endif %}

<section>
 <h2>ATT&amp;CK mapping <span class="muted">(every mapping explains <i>why</i>)</h2>
 <table>
  <tr><th>Technique</th><th>Tactic</th><th class="conf">Confidence</th><th>Why</th><th>Evidence</th></tr>
  {% for m in mappings %}
  <tr>
   <td><b>{{ m.technique_id }}</b><br>{{ m.technique_name }}</td>
   <td>{{ m.tactic }}</td>
   <td class="conf {{ conf_class(m.confidence) }}">{{ '%.2f'|format(m.confidence) }}</td>
   <td>{{ m.why }}</td>
   <td class="muted">{% for e in m.evidence_ids[:4] %}{{ e }}<br>{% endfor %}</td>
  </tr>
  {% endfor %}
 </table>
</section>

<section>
 <h2>Timeline</h2>
 <table><tr><th>#</th><th>Source</th><th>Event</th><th class="conf">Conf</th></tr>
 {% for e in timeline %}
 <tr><td>{{ e.seq }}</td><td class="muted">{{ e.source }}</td><td>{{ e.text }}</td>
     <td class="{{ conf_class(e.confidence) }}">{{ '%.2f'|format(e.confidence) }}</td></tr>
 {% endfor %}
 </table>
</section>

<section>
 <h2>Indicators of Compromise</h2>
 {% if iocs %}
 <table><tr><th>Type</th><th>Value</th><th class="conf">Conf</th><th>FP risk</th></tr>
 {% for i in iocs %}
 <tr><td>{{ i.kind }}</td><td><code>{{ i.value }}</code></td>
     <td class="{{ conf_class(i.confidence) }}">{{ '%.2f'|format(i.confidence) }}</td>
     <td>{{ i.fp_risk }}</td></tr>
 {% endfor %}</table>
 {% else %}<p class="muted">No IOCs extracted.</p>{% endif %}
</section>

<section>
 <h2>Detection coverage</h2>
 <p>Overall: <b>{{ '%.0f'|format(coverage.overall*100) }}%</b> of observed techniques are covered by generated rules.</p>
 <table><tr><th>Tactic</th><th>Observed</th><th>Covered</th><th>Score</th></tr>
 {% for t in coverage.per_tactic %}
 <tr><td>{{ t.tactic }}</td>
     <td>{% for x in t.observed %}<span class="pill">{{ x }}</span>{% endfor %}</td>
     <td>{% for x in t.covered %}<span class="pill">{{ x }}</span>{% endfor %}</td>
     <td><div class="bar"><span style="width:{{ (t.score*100)|int }}%"></span></div></td></tr>
 {% endfor %}</table>
</section>

<section>
 <h2>Generated detections</h2>
 <h3>YARA</h3>
 {% if yara %}{% for r in yara %}<pre>{{ r.to_yara() }}</pre>{% endfor %}
 <p class="muted">All rules verified against the bundled clean corpus (no false positives).</p>
 {% else %}<p class="muted">No clean-passing YARA rule could be synthesized.</p>{% endif %}
 <h3>Sigma</h3>
 {% if sigma %}{% for r in sigma %}<pre>{{ r.to_yaml() }}</pre>{% endfor %}
 {% else %}<p class="muted">No behavioral Sigma rule generated.</p>{% endif %}
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


def _graph_svg(graph, max_nodes: int = 40) -> tuple[str, str]:
    """Render the graph as an inline SVG with a simple circular layout."""
    if graph is None:
        return "<svg viewBox='0 0 10 10'></svg>", "no graph"
    nodes = list(graph.nodes.values()) if hasattr(graph, "nodes") else []
    edges = list(graph.edges) if hasattr(graph, "edges") else []
    # Drop Evidence nodes from the picture to keep it legible; keep entity nodes.
    nodes = [n for n in nodes if n.label != "Evidence"][:max_nodes]
    n = len(nodes)
    if n == 0:
        return "<svg viewBox='0 0 10 10'></svg>", "empty graph"
    w, h, r = 1000, 560, 230
    cx, cy = w / 2, h / 2
    colors = {
        "Process": "#f0883e", "File": "#58a6ff", "Registry": "#bc8cff",
        "Host": "#f85149", "Module": "#3fb950", "Macro": "#d29922",
        "ApiCall": "#79c0ff", "String": "#8b949e", "Technique": "#7ee787",
    }
    pos = {}
    for i, node in enumerate(nodes):
        ang = 2 * math.pi * i / n
        pos[node.id] = (cx + r * math.cos(ang), cy + r * math.sin(ang))
    parts = [f"<svg viewBox='0 0 {w} {h}' xmlns='http://www.w3.org/2000/svg'>"]
    for e in edges:
        if e.src in pos and e.dst in pos:
            x1, y1 = pos[e.src]
            x2, y2 = pos[e.dst]
            parts.append(f"<line x1='{x1:.0f}' y1='{y1:.0f}' x2='{x2:.0f}' y2='{y2:.0f}' stroke='#30363d' stroke-width='1'/>")
    for node in nodes:
        x, y = pos[node.id]
        col = colors.get(node.label, "#8b949e")
        label = escape(str(node.props.get("display", node.id))[:22])
        parts.append(f"<circle cx='{x:.0f}' cy='{y:.0f}' r='7' fill='{col}'/>")
        parts.append(f"<text x='{x+9:.0f}' y='{y+4:.0f}' fill='#c9d1d9' font-size='10'>{label}</text>")
    parts.append("</svg>")
    stats = f"{n} entity nodes, {len(edges)} edges (Evidence nodes hidden)"
    return "".join(parts), stats


def render_html(inp: ReportInputs) -> str:
    env = Environment(autoescape=False)
    env.globals["conf_class"] = _conf_class
    tmpl = env.from_string(_TEMPLATE)
    layers, final_payload = _collect_layers(inp.store)
    iocs = _collect_iocs(inp.store)
    graph_svg, graph_stats = _graph_svg(inp.graph)
    return tmpl.render(
        run_id=inp.run_id,
        sample_name=escape(inp.sample_name),
        sha256=inp.sha256,
        fmt=inp.fmt,
        isolation=inp.isolation,
        furthest=furthest_phase(inp.phases),
        phases=inp.phases,
        mappings=inp.mappings,
        timeline=inp.timeline,
        layers=layers,
        final_payload=final_payload,
        iocs=iocs,
        yara=inp.yara,
        sigma=inp.sigma,
        coverage=inp.coverage,
        graph_svg=graph_svg,
        graph_stats=graph_stats,
    )


def write_report(inp: ReportInputs, path: str | Path) -> Path:
    html = render_html(inp)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(html, encoding="utf-8")
    return p

"""Markdown and HTML network health reports (HTML includes inline SVG latency sparklines)."""
from __future__ import annotations
import html
from datetime import datetime

from . import db

SEV = {"critical": "#d1242f", "warning": "#bf8700", "info": "#0969da"}


def _sparkline(values: list[float | None], w: int = 160, h: int = 28) -> str:
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return ""
    lo, hi = min(vals), max(vals); span = (hi - lo) or 1
    pts, n = [], len(values)
    for i, v in enumerate(values):
        if v is None:
            continue
        pts.append(f"{i / (n - 1) * w:.1f},{h - (v - lo) / span * (h - 2) - 1:.1f}")
    gaps = "".join(f'<rect x="{i / (n - 1) * w:.1f}" y="0" width="{max(1, w / n):.1f}" height="{h}" fill="#d1242f33"/>' for i, v in enumerate(values) if v is None)
    return f'<svg width="{w}" height="{h}" role="img" aria-label="latency trend">{gaps}<polyline fill="none" stroke="#2f81f7" stroke-width="1.5" points="{" ".join(pts)}"/></svg>'


def markdown(con, topo) -> str:
    fs, up = db.findings(con), db.uptime(con)
    out = [f"# NetWatch network report", f"_Generated {datetime.now():%Y-%m-%d %H:%M}_", "", "## Topology (latest status)", "```", topo.ascii_tree(db.latest_status(con)), "```", "",
           "## Findings"]
    out += [f"- **[{f['severity'].upper()}] {f['summary']}** ({f['start_ts']} → {f['end_ts']}) — {f['detail']}" for f in fs] or ["No findings."]
    out += ["", "## Device health", "| Device | Uptime % | Avg latency ms | Max latency ms | Data sent (MB) |", "|---|---:|---:|---:|---:|"]
    out += [f"| {u['device']} | {u['uptime_pct']} | {u['avg_latency']} | {u['max_latency']} | {u['bytes_out'] / 1e6:,.1f} |" for u in up]
    return "\n".join(out)


def html_report(con, topo) -> str:
    e = html.escape
    fs, up = db.findings(con), db.uptime(con)
    rows = "".join(f"<tr><td><span class=sev style='background:{SEV[f['severity']]}'>{f['severity']}</span></td><td>{e(f['kind'])}</td><td><b>{e(f['summary'])}</b><br><small>{e(f['detail'])}</small></td><td>{e(f['start_ts'][11:16])}–{e(f['end_ts'][11:16])}</td></tr>" for f in fs)
    health = "".join(f"<tr><td>{e(u['device'])}</td><td>{u['uptime_pct']}%</td><td>{u['avg_latency']}</td><td>{_sparkline([r['latency_ms'] for r in db.series(con, u['device'])])}</td><td>{u['bytes_out'] / 1e6:,.0f} MB</td></tr>" for u in up)
    crit = sum(f["severity"] == "critical" for f in fs)
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>NetWatch report</title>
<style>body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0}}main{{max-width:1100px;margin:auto;padding:24px}}pre{{background:#161b22;padding:14px;border-radius:10px;border:1px solid #30363d;overflow:auto}}
table{{width:100%;border-collapse:collapse;background:#161b22;margin-bottom:22px}}td,th{{padding:9px;border-bottom:1px solid #30363d;text-align:left;font-size:13px;vertical-align:top}}th{{color:#8b949e}}small{{color:#8b949e}}
.sev{{color:#fff;border-radius:99px;padding:2px 8px;font-size:11px;font-weight:700;text-transform:uppercase}}.cards{{display:flex;gap:12px;margin:14px 0}}.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px 16px}}.card b{{font-size:22px;display:block}}</style></head>
<body><main><h1>📡 NetWatch report</h1><p><small>Generated {datetime.now():%Y-%m-%d %H:%M} · simulated network</small></p>
<div class=cards><div class=card><b>{len(topo.devices)}</b><small>devices</small></div><div class=card><b>{len(fs)}</b><small>findings</small></div><div class=card><b>{crit}</b><small>critical</small></div></div>
<h2>Topology</h2><pre>{e(topo.ascii_tree(db.latest_status(con)))}</pre>
<h2>Findings</h2><table><tr><th>Severity</th><th>Type</th><th>Finding</th><th>Time</th></tr>{rows or '<tr><td colspan=4>No findings</td></tr>'}</table>
<h2>Device health</h2><table><tr><th>Device</th><th>Uptime</th><th>Avg latency (ms)</th><th>Latency (red = offline)</th><th>Sent</th></tr>{health}</table></main></body></html>"""

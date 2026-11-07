from __future__ import annotations
import argparse
import sys
from pathlib import Path

from . import __version__, db
from .monitor import Thresholds, analyze
from .report import html_report, markdown
from .simulator import simulate
from .topology import Topology, sample_topology


def load_topo(path: str | None) -> Topology:
    return Topology.from_json(Path(path).read_text()) if path else sample_topology()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="netwatch", description="Network monitoring and simulation")
    p.add_argument("--db", default="netwatch.db"); p.add_argument("--topology", help="topology JSON (default: built-in sample)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("simulate", help="simulate traffic and incidents into the database"); s.add_argument("--minutes", type=int, default=240); s.add_argument("--seed", type=int, default=42); s.add_argument("--quiet-network", action="store_true", help="no injected incidents")
    sub.add_parser("analyze", help="detect outages and anomalies")
    sub.add_parser("status", help="topology tree with the latest status")
    sub.add_parser("findings", help="list findings")
    sub.add_parser("uptime", help="per-device uptime and latency")
    r = sub.add_parser("report", help="write report.md or report.html"); r.add_argument("out")
    sub.add_parser("export-topology", help="print the sample topology as JSON (edit it to model your own network)")
    d = sub.add_parser("demo", help="simulate → analyze → report"); d.add_argument("--out", default="demo_output")
    a = p.parse_args(argv)
    topo = load_topo(a.topology)
    if a.cmd == "demo":
        out = Path(a.out); out.mkdir(exist_ok=True); (out / "netwatch.db").unlink(missing_ok=True)
        base = ["--db", str(out / "netwatch.db")] + (["--topology", a.topology] if a.topology else [])
        for c in (["simulate"], ["analyze"], ["status"], ["report", str(out / "report.html")], ["report", str(out / "report.md")]):
            main(base + c)
        return 0
    if a.cmd == "export-topology":
        print(topo.to_json()); return 0
    con = db.connect(a.db)
    if a.cmd == "simulate":
        db.store_topology(con, topo)
        sim = simulate(topo, a.minutes, seed=a.seed, scenarios=[] if a.quiet_network else None)
        db.store_sim(con, sim)
        print(f"Simulated {a.minutes} minutes: {len(sim.metrics)} metric samples, {len(sim.connections)} connections.")
        for sc in sim.scenarios: print(f"  injected {sc.kind} on {sc.target} at minute {sc.start}")
    elif a.cmd == "analyze":
        fs = analyze(con, topo, Thresholds())
        new = db.store_findings(con, fs)
        print(f"{len(fs)} findings ({new} new)")
        for f in fs: print(f"  [{f.severity.upper():8}] {f.start:%H:%M}  {f.summary}")
    elif a.cmd == "status":
        print(topo.ascii_tree(db.latest_status(con)))
    elif a.cmd == "findings":
        for f in db.findings(con): print(f"[{f['severity']}] {f['start_ts']}  {f['summary']}")
    elif a.cmd == "uptime":
        print(f"{'device':10} {'uptime%':>8} {'avg ms':>8} {'max ms':>8}")
        for u in db.uptime(con): print(f"{u['device']:10} {u['uptime_pct']:>8} {u['avg_latency'] or 0:>8} {u['max_latency'] or 0:>8}")
    elif a.cmd == "report":
        Path(a.out).write_text(html_report(con, topo) if a.out.endswith(".html") else markdown(con, topo)); print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

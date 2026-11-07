"""Analysis: outages with root-cause grouping, flapping, latency and traffic anomalies, port scans, rogue devices."""
from __future__ import annotations
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import db
from .topology import Topology


@dataclass
class Finding:
    kind: str
    severity: str
    device: str | None
    start: datetime
    end: datetime
    summary: str
    detail: str = ""


@dataclass
class Thresholds:
    z_latency: float = 4.0
    z_bytes_out: float = 6.0
    baseline_samples: int = 20          # samples needed before anomaly scoring starts
    window: int = 30                    # rolling baseline length
    scan_window: timedelta = timedelta(seconds=60)
    scan_distinct: int = 20             # distinct (dst, port) pairs per source in the window
    flap_transitions: int = 3
    flap_window: timedelta = timedelta(minutes=15)
    merge_gap: timedelta = timedelta(minutes=2)


def _episodes(points: list[tuple[datetime, float]], gap: timedelta) -> list[list[tuple[datetime, float]]]:
    out = []
    for p in points:
        if out and p[0] - out[-1][-1][0] <= gap:
            out[-1].append(p)
        else:
            out.append([p])
    return out


def outages(con, topo: Topology, th: Thresholds) -> list[Finding]:
    """One finding per root-cause outage. Downstream 'unreachable' devices are listed, not alerted separately."""
    found = []
    for name in topo.devices:
        rows = db.series(con, name)
        down = [(db.parse_ts(r["ts"]), 0.0) for r in rows if r["status"] == "down"]
        for ep in _episodes(down, timedelta(minutes=1)):
            start, end = ep[0][0], ep[-1][0]
            affected = sorted({r["device"] for r in con.execute("SELECT DISTINCT device FROM metrics WHERE status='unreachable' AND ts BETWEEN ? AND ?", (start.isoformat(sep=" "), end.isoformat(sep=" ")))
                               if name in topo.path_to_root(r["device"])})
            mins = int((end - start).total_seconds() // 60) + 1
            sev = "critical" if affected or topo.devices[name].kind in {"router", "firewall", "server"} else "warning"
            found.append(Finding("outage", sev, name, start, end, f"{name} down for {mins} min" + (f"; {len(affected)} downstream device(s) unreachable" if affected else ""),
                                 ("Root cause of unreachable: " + ", ".join(affected)) if affected else ""))
    return found


def flapping(con, topo: Topology, th: Thresholds) -> list[Finding]:
    found = []
    for name in topo.devices:
        rows = db.series(con, name)
        changes, prev = deque(), None
        active = None
        for r in rows:
            st = r["status"] == "down"
            ts = db.parse_ts(r["ts"])
            if prev is not None and st != prev:
                changes.append(ts)
                while changes and ts - changes[0] > th.flap_window:
                    changes.popleft()
                if len(changes) >= th.flap_transitions:
                    if active and ts - active.end <= th.flap_window:
                        active.end = ts
                    else:
                        active = Finding("flapping", "warning", name, changes[0], ts, f"{name} is flapping (repeated up/down)", "Check cabling, power, or a failing port.")
                        found.append(active)
            prev = st
    return found


def _zscore_anomalies(con, topo, th, column, z_limit, kind, label, unit, min_ratio, scale=1.0):
    found = []
    for name in topo.devices:
        base: deque[float] = deque(maxlen=th.window)
        hits = []
        for r in db.series(con, name):
            v = r[column]
            if r["status"] != "up" or v is None:
                continue
            if len(base) >= th.baseline_samples:
                mean = statistics.fmean(base); sd = statistics.pstdev(base) or 1e-9
                z = (v - mean) / sd
                if z >= z_limit and v >= mean * min_ratio:
                    hits.append((db.parse_ts(r["ts"]), v, mean, z))
                    continue  # don't let the anomaly pollute the baseline
            base.append(v)
        for ep in _episodes([(h[0], h) for h in hits], th.merge_gap):
            peak = max(ep, key=lambda p: p[1][1])[1]
            sev = "critical" if kind == "traffic_spike" else "warning"
            found.append(Finding(kind, sev, name, ep[0][0], ep[-1][0],
                                 f"{label} on {name}: peak {peak[1] / scale:,.1f}{unit} vs baseline {peak[2] / scale:,.2f}{unit} (z={peak[3]:.0f})",
                                 f"{len(ep)} anomalous sample(s)."))
    return found


def latency_anomalies(con, topo, th):
    return _zscore_anomalies(con, topo, th, "latency_ms", th.z_latency, "latency_spike", "Latency spike", " ms", 2.0)


def traffic_anomalies(con, topo, th):
    out = _zscore_anomalies(con, topo, th, "bytes_out", th.z_bytes_out, "traffic_spike", "Outbound traffic spike", " MB/min", 5.0, scale=1e6)
    for f in out:
        f.detail += " Large unexpected uploads can indicate data exfiltration or a backup job. Verify which process sent the data."
    return out


def port_scans(con, topo: Topology, th: Thresholds) -> list[Finding]:
    found, by_src = [], defaultdict(list)
    for r in con.execute("SELECT ts, src_ip, dst_ip, dst_port FROM connections ORDER BY ts"):
        by_src[r["src_ip"]].append((db.parse_ts(r["ts"]), r["dst_ip"], r["dst_port"]))
    for src, rows in by_src.items():
        win, active = deque(), None
        for ts, dst, port in rows:
            win.append((ts, dst, port))
            while win and ts - win[0][0] > th.scan_window:
                win.popleft()
            distinct = {(d, p) for _, d, p in win}
            if len(distinct) >= th.scan_distinct:
                if active and ts - active.end <= th.scan_window:
                    active.end = ts; active._pairs |= distinct
                else:
                    dev = topo.by_ip.get(src)
                    active = Finding("port_scan", "critical", dev.name if dev else src, win[0][0], ts, "", "")
                    active._pairs = set(distinct); found.append(active)
    for f in found:
        dsts = sorted({d for d, _ in f._pairs}); ports = sorted({p for _, p in f._pairs})
        f.summary = f"Port scan from {f.device}: {len(f._pairs)} host/port combinations across {len(dsts)} host(s)"
        f.detail = f"Targets: {', '.join(dsts)}. Ports include {', '.join(map(str, ports[:12]))}{'…' if len(ports) > 12 else ''}. Isolate the source device and check it for malware."
        del f._pairs
    return found


def rogue_devices(con, topo: Topology, th: Thresholds) -> list[Finding]:
    found, seen = [], {}
    for r in con.execute("SELECT ts, mac, ip FROM sightings ORDER BY ts"):
        ts, mac, ip = db.parse_ts(r["ts"]), r["mac"], r["ip"]
        known = topo.by_mac.get(mac)
        if known is None:
            if mac not in seen:
                seen[mac] = Finding("rogue_device", "warning", None, ts, ts, f"Unknown device {mac} at {ip}", "Not in the device inventory. Confirm the owner or block it at the access point.")
                found.append(seen[mac])
            seen[mac].end = ts
        elif known.ip != ip:
            key = (mac, ip)
            if key not in seen:
                seen[key] = Finding("ip_conflict", "critical", known.name, ts, ts, f"{known.name} ({mac}) seen using {ip} instead of {known.ip}", "Possible ARP spoofing or a misconfigured static IP.")
                found.append(seen[key])
            seen[key].end = ts
    return found


ANALYZERS = [outages, flapping, latency_anomalies, traffic_anomalies, port_scans, rogue_devices]


def analyze(con, topo: Topology, th: Thresholds | None = None) -> list[Finding]:
    th = th or Thresholds()
    out = []
    for a in ANALYZERS:
        out.extend(a(con, topo, th))
    # A flapping device also produces short outages; keep the flapping finding and drop those outages.
    flappers = {(f.device) for f in out if f.kind == "flapping"}
    flap_ranges = [(f.device, f.start - th.flap_window, f.end + th.flap_window) for f in out if f.kind == "flapping"]
    out = [f for f in out if not (f.kind == "outage" and f.device in flappers and any(d == f.device and s <= f.start <= e for d, s, e in flap_ranges))]
    return sorted(out, key=lambda f: f.start)

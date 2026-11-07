"""Discrete-time network simulator (1 tick = 1 minute) with injectable incidents."""
from __future__ import annotations
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .topology import Topology


@dataclass
class Scenario:
    kind: str          # device_down | latency_spike | port_scan | exfiltration | rogue_device | flapping
    target: str
    start: int         # tick
    duration: int = 10
    extra: dict = field(default_factory=dict)


@dataclass
class SimOutput:
    metrics: list[tuple]      # (ts, device, status, latency_ms|None, bytes_in, bytes_out)
    connections: list[tuple]  # (ts, src_ip, dst_ip, dst_port, proto)
    sightings: list[tuple]    # (ts, mac, ip)   ARP/DHCP-style observations
    scenarios: list[Scenario]


DEFAULT_SCENARIOS = [
    Scenario("latency_spike", "db-srv", 70, 8),
    Scenario("device_down", "lab-sw", 110, 15),
    Scenario("port_scan", "camera", 150, 3, {"targets": ["10.0.0.10", "10.0.0.11"], "ports": 40}),
    Scenario("exfiltration", "laptop", 190, 6, {"mb_per_min": 180}),
    Scenario("rogue_device", "wifi-ap", 205, 30, {"mac": "de:ad:be:ef:00:99", "ip": "10.0.2.99"}),
    Scenario("flapping", "printer", 220, 12),
]


def simulate(topo: Topology, ticks: int = 240, start: datetime | None = None, seed: int = 42, scenarios: list[Scenario] | None = None) -> SimOutput:
    rnd = random.Random(seed)
    start = start or datetime(2026, 11, 7, 8, 0)
    scenarios = DEFAULT_SCENARIOS if scenarios is None else scenarios
    active = lambda kind, t: [s for s in scenarios if s.kind == kind and s.start <= t < s.start + s.duration]
    metrics, conns, sightings = [], [], []
    names = list(topo.devices)
    for t in range(ticks):
        ts = start + timedelta(minutes=t)
        down = {s.target for s in active("device_down", t)}
        down |= {s.target for s in active("flapping", t) if (t - s.start) % 4 < 2}
        # A device is effectively unreachable if any upstream device is down.
        status = {}
        for n in names:
            if n in down:
                status[n] = "down"
            elif any(p in down for p in topo.path_to_root(n)):
                status[n] = "unreachable"
            else:
                status[n] = "up"
        spikes = {s.target: s for s in active("latency_spike", t)}
        exfil = {s.target: s for s in active("exfiltration", t)}
        for n, d in topo.devices.items():
            if status[n] != "up":
                metrics.append((ts, n, status[n], None, 0, 0)); continue
            hops = len(topo.path_to_root(n))
            lat = d.base_latency_ms + hops * 0.4 + rnd.gauss(0, 0.25 * d.base_latency_ms ** 0.5)
            if n in spikes:
                lat *= 25
            base_bytes = {"server": 4_000_000, "workstation": 900_000, "iot": 600_000, "printer": 50_000}.get(d.kind, 200_000)
            bin_ = max(0, int(rnd.gauss(base_bytes, base_bytes * 0.15)))
            bout = max(0, int(rnd.gauss(base_bytes * 0.4, base_bytes * 0.06)))
            if n in exfil:
                bout += exfil[n].extra.get("mb_per_min", 150) * 1_000_000
            metrics.append((ts, n, "up", round(max(0.1, lat), 2), bin_, bout))
            # normal connections: workstations talk to servers on their known ports
            if d.kind in {"workstation", "iot"} and rnd.random() < 0.5:
                srv = rnd.choice([x for x in topo.devices.values() if x.kind == "server" and status[x.name] == "up"] or [None])
                if srv and srv.services:
                    conns.append((ts + timedelta(seconds=rnd.randint(0, 59)), d.ip, srv.ip, rnd.choice([p for p in srv.services if p != 22] or srv.services), "tcp"))
            if t % 15 == 0:
                sightings.append((ts, d.mac, d.ip))
        for s in active("port_scan", t):
            src = topo.devices[s.target].ip
            for dst in s.extra.get("targets", []):
                for p in rnd.sample(range(1, 1024), s.extra.get("ports", 30)):
                    conns.append((ts + timedelta(seconds=rnd.randint(0, 59)), src, dst, p, "tcp"))
        for s in active("rogue_device", t):
            if (t - s.start) % 5 == 0:
                sightings.append((ts, s.extra["mac"], s.extra["ip"]))
    conns.sort()
    return SimOutput(metrics, conns, sightings, scenarios)

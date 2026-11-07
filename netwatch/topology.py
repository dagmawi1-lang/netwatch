"""Network topology: devices, parent links (upstream path), and the expected services on each device."""
from __future__ import annotations
import json
from dataclasses import dataclass, field

KINDS = {"router", "firewall", "switch", "server", "workstation", "printer", "iot", "ap"}


@dataclass
class Device:
    name: str
    kind: str
    ip: str
    mac: str
    parent: str | None = None          # upstream device this one reaches the network through
    services: list[int] = field(default_factory=list)  # ports expected to be open/used
    base_latency_ms: float = 2.0


class Topology:
    def __init__(self, devices: list[Device]):
        self.devices = {d.name: d for d in devices}
        for d in devices:
            if d.kind not in KINDS:
                raise ValueError(f"{d.name}: unknown kind '{d.kind}'")
            if d.parent and d.parent not in self.devices:
                raise ValueError(f"{d.name}: parent '{d.parent}' does not exist")
        for d in devices:  # cycle check
            seen, cur = set(), d.name
            while cur:
                if cur in seen:
                    raise ValueError(f"cycle in topology at '{cur}'")
                seen.add(cur); cur = self.devices[cur].parent
        self.by_ip = {d.ip: d for d in devices}
        self.by_mac = {d.mac.lower(): d for d in devices}

    def path_to_root(self, name: str) -> list[str]:
        out, cur = [], self.devices[name].parent
        while cur:
            out.append(cur); cur = self.devices[cur].parent
        return out

    def children(self, name: str) -> list[str]:
        return sorted(d.name for d in self.devices.values() if d.parent == name)

    def roots(self) -> list[str]:
        return sorted(d.name for d in self.devices.values() if not d.parent)

    def ascii_tree(self, status: dict[str, str] | None = None) -> str:
        icon = {"up": "●", "down": "✖", "unreachable": "◌", "degraded": "▲"}
        lines = []
        def walk(n, prefix, last):
            d = self.devices[n]; st = (status or {}).get(n, "")
            lines.append(f"{prefix}{'└─ ' if last else '├─ '}{icon.get(st, '·')} {n} ({d.kind}, {d.ip}){' ' + st if st else ''}")
            kids = self.children(n)
            for i, k in enumerate(kids):
                walk(k, prefix + ('   ' if last else '│  '), i == len(kids) - 1)
        for i, r in enumerate(self.roots()):
            walk(r, "", i == len(self.roots()) - 1)
        return "\n".join(lines)

    @classmethod
    def from_json(cls, text: str) -> "Topology":
        return cls([Device(**d) for d in json.loads(text)["devices"]])

    def to_json(self) -> str:
        return json.dumps({"devices": [d.__dict__ for d in self.devices.values()]}, indent=2)


def sample_topology() -> Topology:
    """A small school/home-lab network."""
    D = Device
    return Topology([
        D("edge-fw", "firewall", "10.0.0.1", "00:1a:2b:00:00:01", None, [443], 1.0),
        D("core-sw", "switch", "10.0.0.2", "00:1a:2b:00:00:02", "edge-fw", [], 1.0),
        D("lab-sw", "switch", "10.0.1.2", "00:1a:2b:00:01:02", "core-sw", [], 1.5),
        D("wifi-ap", "ap", "10.0.2.2", "00:1a:2b:00:02:02", "core-sw", [], 2.0),
        D("web-srv", "server", "10.0.0.10", "00:1a:2b:00:00:10", "core-sw", [80, 443, 22], 1.5),
        D("db-srv", "server", "10.0.0.11", "00:1a:2b:00:00:11", "core-sw", [5432, 22], 1.5),
        D("lab-pc1", "workstation", "10.0.1.21", "00:1a:2b:00:01:21", "lab-sw", [], 2.5),
        D("lab-pc2", "workstation", "10.0.1.22", "00:1a:2b:00:01:22", "lab-sw", [], 2.5),
        D("printer", "printer", "10.0.1.30", "00:1a:2b:00:01:30", "lab-sw", [9100], 3.0),
        D("camera", "iot", "10.0.2.40", "00:1a:2b:00:02:40", "wifi-ap", [554], 6.0),
        D("laptop", "workstation", "10.0.2.50", "00:1a:2b:00:02:50", "wifi-ap", [], 5.0),
    ])

"""SQLite event database for network metrics, connections, device sightings, and findings."""
from __future__ import annotations
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (name TEXT PRIMARY KEY, kind TEXT NOT NULL, ip TEXT NOT NULL, mac TEXT NOT NULL, parent TEXT REFERENCES devices(name), services TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS metrics (ts TEXT NOT NULL, device TEXT NOT NULL REFERENCES devices(name), status TEXT NOT NULL CHECK (status IN ('up','down','unreachable')),
  latency_ms REAL, bytes_in INTEGER NOT NULL, bytes_out INTEGER NOT NULL, PRIMARY KEY (ts, device));
CREATE INDEX IF NOT EXISTS metrics_device ON metrics (device, ts);
CREATE TABLE IF NOT EXISTS connections (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL, dst_port INTEGER NOT NULL, proto TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS connections_src ON connections (src_ip, ts);
CREATE TABLE IF NOT EXISTS sightings (ts TEXT NOT NULL, mac TEXT NOT NULL, ip TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, severity TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  device TEXT, start_ts TEXT NOT NULL, end_ts TEXT NOT NULL, summary TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', UNIQUE (kind, device, start_ts));
"""


def connect(path: str = "netwatch.db") -> sqlite3.Connection:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def store_topology(con, topo) -> None:
    with con:
        # parents first so the foreign key is satisfied
        order = sorted(topo.devices.values(), key=lambda d: len(topo.path_to_root(d.name)))
        con.executemany("INSERT OR REPLACE INTO devices VALUES (?,?,?,?,?,?)", [(d.name, d.kind, d.ip, d.mac.lower(), d.parent, ",".join(map(str, d.services))) for d in order])


def store_sim(con, sim) -> None:
    iso = lambda t: t.isoformat(sep=" ")
    with con:
        con.executemany("INSERT OR REPLACE INTO metrics VALUES (?,?,?,?,?,?)", [(iso(m[0]), *m[1:]) for m in sim.metrics])
        con.executemany("INSERT INTO connections (ts, src_ip, dst_ip, dst_port, proto) VALUES (?,?,?,?,?)", [(iso(c[0]), *c[1:]) for c in sim.connections])
        con.executemany("INSERT INTO sightings VALUES (?,?,?)", [(iso(s[0]), s[1].lower(), s[2]) for s in sim.sightings])


def store_findings(con, findings) -> int:
    before = con.total_changes
    with con:
        con.executemany("INSERT OR IGNORE INTO findings (kind, severity, device, start_ts, end_ts, summary, detail) VALUES (?,?,?,?,?,?,?)",
                        [(f.kind, f.severity, f.device, f.start.isoformat(sep=" "), f.end.isoformat(sep=" "), f.summary, f.detail) for f in findings])
    return con.total_changes - before


def series(con, device: str) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM metrics WHERE device = ? ORDER BY ts", (device,)).fetchall()


def latest_status(con) -> dict[str, str]:
    rows = con.execute("SELECT m.device, m.status FROM metrics m JOIN (SELECT device, MAX(ts) ts FROM metrics GROUP BY device) l ON l.device = m.device AND l.ts = m.ts").fetchall()
    return {r["device"]: r["status"] for r in rows}


def uptime(con) -> list[sqlite3.Row]:
    return con.execute("""SELECT device, COUNT(*) samples, ROUND(100.0 * SUM(status = 'up') / COUNT(*), 2) uptime_pct,
        ROUND(AVG(latency_ms), 2) avg_latency, ROUND(MAX(latency_ms), 2) max_latency, SUM(bytes_out) bytes_out
        FROM metrics GROUP BY device ORDER BY uptime_pct, device""").fetchall()


def findings(con) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM findings ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, start_ts").fetchall()


def parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s)

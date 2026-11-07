import json
from datetime import timedelta

import pytest

from netwatch import db
from netwatch.cli import main
from netwatch.monitor import Thresholds, analyze
from netwatch.simulator import Scenario, simulate
from netwatch.topology import Device, Topology, sample_topology


def run(scenarios, minutes=120, seed=1):
    topo = sample_topology()
    con = db.connect(":memory:")
    db.store_topology(con, topo)
    db.store_sim(con, simulate(topo, minutes, seed=seed, scenarios=scenarios))
    return con, topo, analyze(con, topo, Thresholds())


def test_topology_validation_and_tree():
    with pytest.raises(ValueError, match="parent"):
        Topology([Device("a", "switch", "10.0.0.1", "aa", "missing")])
    with pytest.raises(ValueError, match="cycle"):
        Topology([Device("a", "switch", "1", "a", "b"), Device("b", "switch", "2", "b", "a")])
    with pytest.raises(ValueError, match="kind"):
        Topology([Device("a", "toaster", "1", "a")])
    t = sample_topology()
    assert t.path_to_root("lab-pc1") == ["lab-sw", "core-sw", "edge-fw"]
    assert "└─" in t.ascii_tree() and Topology.from_json(t.to_json()).devices.keys() == t.devices.keys()


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_quiet_network_has_no_findings(seed):
    _, _, fs = run([], minutes=180, seed=seed)
    assert fs == [], [f.summary for f in fs]


def test_outage_root_cause_suppresses_downstream_alerts():
    con, _, fs = run([Scenario("device_down", "lab-sw", 40, 10)])
    outs = [f for f in fs if f.kind == "outage"]
    assert len(outs) == 1 and outs[0].device == "lab-sw" and outs[0].severity == "critical"
    assert "lab-pc1" in outs[0].detail and "printer" in outs[0].detail
    statuses = {r["status"] for r in con.execute("SELECT status FROM metrics WHERE device='lab-pc1'")}
    assert statuses == {"up", "unreachable"}


def test_latency_and_traffic_anomalies():
    _, _, fs = run([Scenario("latency_spike", "db-srv", 50, 5), Scenario("exfiltration", "laptop", 80, 4, {"mb_per_min": 120})])
    kinds = {(f.kind, f.device) for f in fs}
    assert ("latency_spike", "db-srv") in kinds and ("traffic_spike", "laptop") in kinds
    assert len(fs) == 2


def test_port_scan_detected_and_normal_traffic_not():
    _, _, fs = run([Scenario("port_scan", "camera", 60, 2, {"targets": ["10.0.0.10"], "ports": 25})])
    scans = [f for f in fs if f.kind == "port_scan"]
    assert len(scans) == 1 and scans[0].device == "camera" and "10.0.0.10" in scans[0].detail


def test_flapping_replaces_individual_outages():
    _, _, fs = run([Scenario("flapping", "printer", 40, 12)])
    assert [f.kind for f in fs] == ["flapping"]


def test_rogue_device_and_ip_conflict():
    topo = sample_topology()
    con = db.connect(":memory:"); db.store_topology(con, topo)
    sim = simulate(topo, 60, seed=4, scenarios=[Scenario("rogue_device", "wifi-ap", 10, 20, {"mac": "DE:AD:BE:EF:00:01", "ip": "10.0.2.99"})])
    sim.sightings.append((sim.sightings[-1][0] + timedelta(minutes=1), topo.devices["web-srv"].mac, "10.0.0.66"))
    db.store_sim(con, sim)
    fs = analyze(con, topo)
    assert {f.kind for f in fs} == {"rogue_device", "ip_conflict"}
    assert any("de:ad:be:ef:00:01" in f.summary for f in fs), "MACs are normalized to lower case"


def test_findings_are_idempotent_and_reports_escape(tmp_path):
    con, topo, fs = run([Scenario("device_down", "web-srv", 30, 5)])
    assert db.store_findings(con, fs) == 1 and db.store_findings(con, fs) == 0
    from netwatch.report import html_report, markdown
    topo.devices["web-srv"].name  # unchanged
    h = html_report(con, topo)
    assert "<svg" in h and "web-srv down" in h and "<script" not in h
    assert "| web-srv |" in markdown(con, topo)


def test_cli_demo_and_custom_topology(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path / "d")]) == 0
    assert (tmp_path / "d" / "report.html").exists()
    out = capsys.readouterr().out
    for word in ["Latency spike", "Port scan", "flapping", "Unknown device", "Outbound traffic"]:
        assert word in out
    topo_file = tmp_path / "t.json"
    topo_file.write_text(json.dumps({"devices": [{"name": "r1", "kind": "router", "ip": "192.168.1.1", "mac": "aa:aa:aa:aa:aa:01"}, {"name": "pc", "kind": "workstation", "ip": "192.168.1.5", "mac": "aa:aa:aa:aa:aa:05", "parent": "r1"}]}))
    assert main(["--db", str(tmp_path / "c.db"), "--topology", str(topo_file), "simulate", "--minutes", "30", "--quiet-network"]) == 0
    assert main(["--db", str(tmp_path / "c.db"), "--topology", str(topo_file), "status"]) == 0
    assert "pc (workstation" in capsys.readouterr().out

# 📡 NetWatch — network monitoring and simulation

NetWatch simulates a small network (firewall → switches → servers, workstations, IoT), records traffic and status into SQLite, and detects problems. It finds outages and traces them to a root cause, flags flapping links, latency and traffic anomalies, port scans, rogue devices, and IP/MAC conflicts.

**Languages:** Python · SQL (SQLite) · standard library only
**Shows:** networking (topology, reachability, ports, ARP/MAC), security monitoring, statistics, and data management.

## Quick start
```bash
python -m netwatch demo          # simulate 4 hours → analyze → demo_output/report.html + report.md
python -m pytest -q              # 11 tests
```

```
6 findings
  [WARNING ] 09:10  Latency spike on db-srv: peak 63.4 ms vs baseline 2.30 ms (z=227)
  [CRITICAL] 09:50  lab-sw down for 15 min; 3 downstream device(s) unreachable
  [CRITICAL] 10:30  Port scan from camera: 232 host/port combinations across 2 host(s)
  [CRITICAL] 11:10  Outbound traffic spike on laptop: peak 180.4 MB/min vs baseline 0.36 MB/min
  [WARNING ] 11:25  Unknown device de:ad:be:ef:00:99 at 10.0.2.99
  [WARNING ] 11:40  printer is flapping (repeated up/down)
```

## What it does
| Feature | How |
|---|---|
| **Simulated devices** | Topology with parent links (each device's upstream path), expected service ports, and base latency. Load your own with `--topology my_net.json`. Start from `python -m netwatch export-topology`. |
| **Traffic and event monitoring** | 1-minute ticks: status, latency, bytes in/out, TCP connections, and MAC/IP sightings (like ARP/DHCP logs). |
| **Connection status tracking** | `status` draws the tree with ● up / ✖ down / ◌ unreachable. `uptime` shows uptime %, average and max latency. |
| **Network event database** | SQLite tables `devices`, `metrics`, `connections`, `sightings`, `findings`, with indexes on device/time and source IP/time. |
| **Anomaly identification** | See below. |

### Detection logic
- **Root-cause outages:** if `lab-sw` goes down, the PCs behind it are *unreachable*, not down. NetWatch raises **one** critical finding for the switch and lists the affected devices. This is alarm suppression, the way real NMS tools avoid alert storms.
- **Flapping:** 3 or more up/down changes within 15 minutes become one "flapping" finding instead of many short outages.
- **Latency / traffic:** rolling 30-sample baseline per device. A z-score ≥ 4 (latency) or ≥ 6 (bytes out) plus a minimum ratio means the value must be both statistically *and* practically large. Anomalies are kept out of the baseline so a long spike doesn't become "normal".
- **Port scans:** sliding 60-second window per source. 20 or more distinct (host, port) pairs is a scan.
- **Rogue devices / IP conflicts:** MAC not in inventory, or a known MAC using a different IP (possible ARP spoofing).

**Accuracy on the simulated data:** every injected incident was found and there were **zero findings on a quiet network** (tested across 3 random seeds).

## Limits
The traffic is simulated. Next steps (`ROADMAP.md`) are real data sources: ping/SNMP polling, Zeek/conn logs, and `arp -a`.

## License

**Permission required.** © 2026 Dagmawi Melaku. You need my written permission before using, copying, or modifying this code, and any approved use must credit me with a link to this repository. Viewing, forking on GitHub, and running it to judge or review a submission are allowed without asking. To ask, [open an issue](../../issues/new). See [LICENSE](LICENSE) for the full terms.

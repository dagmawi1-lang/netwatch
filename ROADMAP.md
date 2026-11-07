# NetWatch roadmap

## Done (v1.0.0)
- [x] Simulated network devices (JSON topology, 8 device kinds, parent links, services)
- [x] Network traffic and event monitoring (latency, bytes, connections, MAC/IP sightings)
- [x] Connection status tracking (up/down/unreachable, uptime %, ASCII topology tree)
- [x] Network event database (SQLite, indexed)
- [x] Anomaly identification (root-cause outages, flapping, latency, traffic, port scans, rogue devices, IP conflicts)
- [x] Reports: Markdown and HTML with SVG latency sparklines
- [x] 11 tests including zero false positives on quiet networks

## Next
- [ ] Live mode: ICMP ping and TCP port checks against real hosts on a lab network
- [ ] Import Zeek `conn.log` and `arp -a` output
- [ ] Unexpected-service detection (traffic to ports a device doesn't offer)
- [ ] Simple web dashboard with auto-refresh

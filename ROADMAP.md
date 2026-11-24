# SYNTRAF roadmap

`[X]` done, `[~]` partly done, `[ ]` to do. Updated 2026-11-23 (version 0.45).

## Done

v0.2 - Getting things done aka ANT
 [X] Multiple topologies (full mesh, hub & spoke, dual hub)
 [X] iperf3 test
 [X] TOML config file with validation of every field
 [X] Saving metrics to InfluxDB 2, then VictoriaMetrics (recommended)
 [X] Viewing metrics in Grafana dashboards
 [X] Dynamic IP client
 [X] 1 sec resolution
 [X] Basic webui with:
    [X] Clients system stats, system infos and status
    [X] Remote action: reconnect

v0.3 - A step back aka MOONWALK
 [ ] iperf3 libiperf integration (iperf3 still runs as a process)
 [X] Run as a service: systemd, launchd, Windows scheduled task (offline install packages)
 [X] Restart compatibility (Windows and Linux): supervisor, restart from the webui, rollback of a failed update
 [X] Fix high loss stability (db insertion not regular)

v0.4 - The makeover aka CINDERELLA
 [X] Edit clients, mesh groups, profiles, databases, tokens and server settings from the webui (no TOML editing)
 [X] Description field for group and client
 [X] Show in webui the potential and actual client bandwidth usage
 [~] Visual map: live map of probes and links with time replay; editing from the map still to do
 [X] Remote action: pause (the probe stays connected, nobody measures it)
 [X] Fix memory leak in client status webui [FIXED 2022-07-13 - LBS]

v0.5 - On the other side lies the truth - SUBMARINE
 [X] UDP ping: round-trip latency with TWAMP-Light, behind a NAT too
 [X] Voice quality score (MOS, ITU-T E-model), loss bursts, correlation matrix
 [X] Scheduled TCP throughput tests (auto window from the bandwidth-delay product)
 [X] DSCP marking check (rewrite detected in each direction)
 [X] Clients behind a NAT or a firewall (iperf3 --bidir, NAT detection and keepalive)
 [X] Inbound reachability test: peers try to reach the ports of a probe (firewall, NAT), automatic and on demand
 [X] Pairs left unmeasured (both probes outbound only) shown in the topology summary
 [ ] QUIC tunnel

v0.6 - Better understanding of what's going on - PULSAR
 [X] Alerts: robust baseline per flow and metric, out-of-baseline alerts in the webui and Grafana
 [X] Probe health alerts (disconnected, buffered measurements) and clock offset / drift alerts
 [X] Maintenance windows per probe or mesh group (once or weekly)
 [X] Network path (MTR-like traceroute) on demand and automatically when an alert opens
 [X] SYNTRAF health on /metrics (Prometheus format), health dashboard, Zabbix template
 [X] Save client logs to server, search, syslog / CEF forwarding to a SIEM
 [ ] Saving probe system stats (CPU, memory, interface usage) to the database
 [ ] Include probe system stats in a Grafana dashboard

v0.7 - Add security aka K9
 [X] User login and user management
 [X] API security (API tokens, CSRF, security headers, HTTPS)
 [X] Client auth: enrollment approval, pinned keys, per-client tokens, proof of possession
 [X] Server pinned by the probes, signed releases, CSR and certificates from your CA
 [ ] Roles (read only, operator, admin), access restricted per mesh group
 [ ] SSO (OIDC, LDAP / AD) and MFA (TOTP) for local accounts

v0.8 - Governance
 [X] Database retention status, VictoriaMetrics snapshots, purge of orphan data
 [X] Audit log, configuration versions (compare, restore)
 [X] Rename a probe without losing its history

v0.9 - Updates
 [X] Update clients remotely (light probe package, rollback, deployment groups / waves)
 [X] Offline install packages: Debian, RHEL, Alpine, Windows, macOS; server with VictoriaMetrics and Grafana

v0.91 - Translation
 [X] Translation framework (English, French)

v1.0
 [X] MTR extension (see network path, v0.6)
 [X] Documentation (docs/html/index.html)

## Next

v1.1 - Tell someone aka HERALD
 [ ] Alert notifications: webhook, ntfy, email, Teams / Slack
 [ ] Acknowledge and comment an alert (who, when, cause), in the audit log
 [ ] Group simultaneous alerts into one incident (same probe or common link, from the correlation)
 [ ] Absolute thresholds (SLO) beside the baseline: a flow that has always been bad must alert too

v1.2 - See further aka LENS
 [ ] IPv6 flows, side by side with IPv4
 [ ] Out-of-order packets (reported by iperf3, not stored yet)
 [ ] One-way latency (the probe clock offset is already measured)
 [ ] Path MTU discovery, alert when it drops
 [ ] Application probes: DNS resolution, HTTP(S) (TTFB, TLS), TCP connect to targets outside the mesh

v1.3 - Show the boss aka LEDGER
 [ ] Periodic SLA report (PDF / HTML): availability, loss / jitter / MOS percentiles, worst links, trend
 [ ] Export an incident's data (CSV / JSON around an alert)
 [ ] Tags on probes (site, region, provider, link type), filters and aggregates by tag

v1.4 - Automate aka GEARS
 [ ] Declarative configuration: export / import everything in one file, idempotent API (Ansible, Terraform)
 [ ] Scheduled changes (apply a change at a given time, with the existing preview and diff)
 [ ] Compress config before sending to client
 [ ] Docker images of the server and the probe

## Project hygiene

 [ ] CI: run the unit tests (lab/tests) and a linter on main (the workflow only tags, on "master")
 [X] Remove the old web interfaces (lib/web_ui, lib/webui_kindafixed, lib/st_webui.py1)
 [ ] Rename lib/web_ui_kindafixed2
 [X] Remove debug files from the repository root (thread_status.txt, threads.txt, client_status.txt, fake_data/)
 [ ] Split the large modules (st_mesh.py, st_conf_validation.py, st_mesh_group_ops.py)
 [ ] Finish the validation of listeners (TODO in st_conf_validation.py)

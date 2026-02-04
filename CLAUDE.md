# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SYNTRAF is a Python-based synthetic traffic generation and network QoE measurement tool. It creates mesh topologies of UDP traffic between nodes using iperf3, with centralized configuration management, InfluxDB for metrics storage, and Grafana for visualization.

**Current Version:** 0.45
**Platforms:** Linux, macOS, Windows
**Python:** 3.8+ (3.9+ recommended)

## Running SYNTRAF

```bash
# Server mode (manages mesh topology)
python3 syntraf.py -c /path/to/config.toml -l /path/to/logs/

# Client mode (same command, mode determined by config file)
python3 syntraf.py -c /path/to/client_config.toml -l /path/to/logs/
```

Example config: `etc/config_example.toml`

## Dependencies

```bash
# Server (full installation)
pip install -r requirements_server.txt

# Client-only (lighter)
pip install -r requirements_client.txt
```

Note: Flask is pinned to 2.0.3 due to `safe_join` deprecation issues with werkzeug.

## Architecture

### Component Overview

```
Server: Mesh Server + Control Channel (TCP/TLS) + WebUI (Flask) + InfluxDB Writer
   │
   └──► Clients: iperf3 Listeners + iperf3 Connectors + Control Channel Client
```

### Core Modules (`lib/st_*.py`)

| Module | Purpose |
|--------|---------|
| `st_mesh.py` (~1,800 lines) | Mesh engine: server accepts clients, distributes configs; clients manage iperf3 instances |
| `st_process_and_thread.py` (~900 lines) | Watchdog + thread/process management, respawning failed workers |
| `st_conf_validation.py` (~2,000 lines) | TOML parsing, mesh topology generation, extensive validation |
| `st_iperf.py` | iperf3 process spawning, UDP hole-punch for NAT traversal |
| `st_iperf3_readlog.py` | Real-time iperf3 log parsing for metrics extraction |
| `st_influxdb.py` | InfluxDB 2.0 client with write queue buffering |
| `st_crypto.py` | X.509 certificates, RSA keypairs for iperf3 auth, TLS |
| `st_logging.py` | Rotating file handlers, dual output (stdout + file) |
| `st_system_stats.py` | CPU/memory/disk/network collection per client |
| `st_latency.py`, `st_tcp_ping.py` | UDP/TCP latency measurement |

### Key Data Classes

- `cc_client` (in `syntraf.py`): Control channel client representation with JSON serialization
- `st_obj_process_n_thread`: Thread/process wrapper with monitoring

### Execution Model

- Multi-threaded with gevent for async operations
- Separate processes for each iperf3 instance
- Graceful shutdown via signal handlers (SIGINT, SIGTERM, SIGBREAK on Windows)
- PID file prevents duplicate instances

### Data Flow

1. TOML config loaded and validated
2. Server generates mesh topology, distributes to clients via TLS control channel
3. Clients spawn iperf3 listeners (servers) and connectors (clients)
4. iperf3 JSON output parsed in real-time
5. Metrics queued and written to InfluxDB
6. Grafana dashboards visualize data

## Configuration Structure (TOML)

- `[GLOBAL]`: Shared settings (logging level, iperf3 paths, timeouts)
- `[[DATABASE]]`: InfluxDB connections (supports multiple)
- `[SERVER]`: Server-mode settings (bind address, port, tokens, certificates)
- `[[MESH_GROUP]]`: Test profiles (bandwidth, DSCP, packet size, interval)
- `[[SERVER_CLIENT]]`: Node definitions (UID, IP, group membership, exclusions)
- `[CLIENT]`: Client-mode settings (server connection, authentication)
- `[CONNECTORS]`/`[LISTENERS]`: Standalone iperf3 configurations

## WebUI

Three variants exist under active development:
- `lib/web_ui/`
- `lib/web_ui_kindafixed2/`
- `lib/webui_kindafixed/`

Uses Flask 2.0.3, Flask-Login, SQLite (`users.db`), Cytoscape.js for graph visualization.

## Known Issues

- Flask `safe_join` deprecation with werkzeug (pinned to 2.0.3)
- gevent/libuv timer resolution warnings on Windows
- Clock skew tolerance needed for distributed measurements

## Build/Test/Lint

Currently no pytest infrastructure, linting, or type checking configured. Installation handled by `install_syntraf.sh` which:
- Creates Python virtual environment
- Installs dependencies
- Compiles iperf3 from source
- Sets up systemd service (Linux)

## Compilation Modes

The codebase supports two compilation modes via `CompilationOptions.client_only`:
- **Server mode**: Full functionality including mesh server, WebUI, database writers
- **Client-only mode**: Lighter build for nodes that only run as mesh clients

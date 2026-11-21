"""Santé du lab : attente de l'état sain, instantanés de processus par nœud."""
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import docker, influx, topology


@dataclass
class NodeSnapshot:
    iperf3_count: int
    zombies: int
    threads: int
    rss_kb: int


def read_env(path: Path = docker.ENV_FILE) -> dict[str, str]:
    env = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def influx_client() -> influx.Client:
    env = read_env()
    return influx.Client(f"http://127.0.0.1:{env.get('INFLUX_HOST_PORT', '18086')}",
                         env["INFLUX_TOKEN"], env["INFLUX_ORG"], env["INFLUX_BUCKET"])


def snapshot(service: str) -> NodeSnapshot:
    out = docker.exec_(service, ["ps", "-eo", "pid=,stat=,nlwp=,rss=,args="]).stdout
    iperf3 = zombies = threads = rss = 0
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        _pid, stat, nlwp, rss_kb, args = parts
        if stat.startswith("Z"):
            zombies += 1
            continue
        prog = args.split()[0].rsplit("/", 1)[-1]
        if prog == "iperf3":
            iperf3 += 1
        elif "syntraf.py" in args:
            threads, rss = int(nlwp), int(rss_kb)
    return NodeSnapshot(iperf3, zombies, threads, rss)


def stale_flows(client, flows: list[str], max_age_s: float) -> list[str]:
    now = datetime.now(timezone.utc)
    stale = []
    for f in flows:
        t = client.last_point_time(f)
        if t is None or (now - t).total_seconds() > max_age_s:
            stale.append(f)
    return stale


def wait_healthy(client: influx.Client, timeout_s: float = 180) -> None:
    """Sain = InfluxDB répond et chacun des 12 flux a un point de moins de 3·INTERVAL s."""
    deadline = time.monotonic() + timeout_s
    stale = topology.expected_flows()
    while time.monotonic() < deadline:
        if client.ping():
            stale = stale_flows(client, topology.expected_flows(), 3 * topology.INTERVAL)
            if not stale:
                return
        time.sleep(2)
    raise TimeoutError(f"lab non sain après {timeout_s:.0f} s ; flux sans point récent : {', '.join(stale)}")

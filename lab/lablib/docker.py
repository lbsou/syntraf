"""Appels à la CLI docker pour le lab."""
import json
import subprocess
from pathlib import Path

from . import topology

LAB_DIR = Path(__file__).resolve().parent.parent
COMPOSE_FILE = LAB_DIR / "docker-compose.yml"
ENV_FILE = LAB_DIR / "config" / "lab.env"


def run(args: list[str], check: bool = True, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], check=check, timeout=timeout,
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def compose(args: list[str], check: bool = True, timeout: float = 900) -> subprocess.CompletedProcess:
    return run(["compose", "-p", topology.PROJECT, "-f", str(COMPOSE_FILE),
                "--env-file", str(ENV_FILE), *args], check=check, timeout=timeout)


def exec_(service: str, cmd: list[str], check: bool = True, timeout: float = 60) -> subprocess.CompletedProcess:
    return run(["exec", topology.container(service), *cmd], check=check, timeout=timeout)


def inspect_state(service: str) -> dict:
    data = json.loads(run(["inspect", topology.container(service)]).stdout)[0]
    nets = data.get("NetworkSettings", {}).get("Networks") or {}
    return {
        "running": bool(data["State"]["Running"]),
        "paused": bool(data["State"]["Paused"]),
        "networks": {name: n.get("IPAddress", "") for name, n in nets.items()},
    }

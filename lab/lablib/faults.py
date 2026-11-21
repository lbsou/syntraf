"""Injection de pannes dans les conteneurs du lab (jamais sur l'hôte ni la VM WSL)."""
import subprocess
import time
from typing import Literal

from . import docker, topology

TAG = "syntraf-lab"
CutMode = Literal["drop", "disconnect", "pause"]


# ---------------------------------------------------------------------------
# Construction des commandes (fonctions pures)
# ---------------------------------------------------------------------------
def _netem_params(delay_ms: int, jitter_ms: int, loss_pct: float, rate: str | None) -> list[str]:
    params = []
    if delay_ms or jitter_ms:
        params += ["delay", f"{delay_ms}ms"] + ([f"{jitter_ms}ms"] if jitter_ms else [])
    if loss_pct:
        params += ["loss", f"{loss_pct:g}%"]
    if rate:
        params += ["rate", rate]
    return params


def netem_cmds(iface: str, delay_ms: int = 0, jitter_ms: int = 0, loss_pct: float = 0.0,
               rate: str | None = None, to_ip: str | None = None) -> list[list[str]]:
    params = _netem_params(delay_ms, jitter_ms, loss_pct, rate)
    if to_ip is None:
        return [["tc", "qdisc", "replace", "dev", iface, "root", "netem", *params]]
    # prio à 4 bandes : la priomap par défaut n'utilise que 1:1–1:3 ; la bande 1:4 reçoit
    # uniquement le trafic filtré vers to_ip, et c'est elle qui porte netem.
    return [
        ["tc", "qdisc", "replace", "dev", iface, "root", "handle", "1:", "prio", "bands", "4",
         "priomap", *"1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1".split()],
        ["tc", "qdisc", "replace", "dev", iface, "parent", "1:4", "handle", "40:", "netem", *params],
        ["tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip", "prio", "1",
         "u32", "match", "ip", "dst", f"{to_ip}/32", "flowid", "1:4"],
    ]


def drop_cmds(to_ip: str | None = None) -> list[list[str]]:
    src = ["-s", to_ip] if to_ip else []
    dst = ["-d", to_ip] if to_ip else []
    tag = ["-m", "comment", "--comment", TAG]
    return [
        ["iptables", "-I", "INPUT", *src, *tag, "-j", "DROP"],
        ["iptables", "-I", "OUTPUT", *dst, *tag, "-j", "DROP"],
    ]


def heal_cmds(iface: str) -> list[list[str]]:
    return [
        ["tc", "qdisc", "del", "dev", iface, "root"],
        ["sh", "-c", f"iptables-save | grep -v -- '{TAG}' | iptables-restore"],
    ]


def parse_lab_iface(ip_addr_output: str) -> str | None:
    """Nom de l'interface qui porte une IP du sous-réseau du lab (sortie de `ip -o -4 addr show`)."""
    for line in ip_addr_output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet" and parts[3].startswith(topology.SUBNET_PREFIX):
            return parts[1].split("@")[0]
    return None


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------
def lab_iface(service: str) -> str:
    iface = parse_lab_iface(docker.exec_(service, ["ip", "-o", "-4", "addr", "show"]).stdout)
    if iface is None:
        raise RuntimeError(f"{service} : aucune interface sur {topology.SUBNET_PREFIX}0/24 (réseau retiré ?)")
    return iface


def _ip_of(service_or_none: str | None) -> str | None:
    return None if service_or_none is None else topology.SERVICES[service_or_none]


def degrade(service: str, delay_ms: int = 0, jitter_ms: int = 0, loss_pct: float = 0.0,
            rate: str | None = None, to: str | None = None) -> None:
    iface = lab_iface(service)
    # Repartir d'une racine vide : deux degrade successifs remplacent, n'empilent jamais.
    docker.exec_(service, ["tc", "qdisc", "del", "dev", iface, "root"], check=False)
    for cmd in netem_cmds(iface, delay_ms, jitter_ms, loss_pct, rate, _ip_of(to)):
        docker.exec_(service, cmd)


def cut(service: str, mode: CutMode, to: str | None = None) -> None:
    if mode == "drop":
        for cmd in drop_cmds(_ip_of(to)):
            docker.exec_(service, cmd)
    elif to is not None:
        raise ValueError("--to n'est possible qu'avec --mode drop")
    elif mode == "disconnect":
        docker.run(["network", "disconnect", topology.NETWORK, topology.container(service)])
    elif mode == "pause":
        docker.run(["pause", topology.container(service)])
    else:
        raise ValueError(f"mode inconnu : {mode}")


def heal(service: str) -> None:
    """Retire toute panne du lab sur ce service ; sans effet si le service est sain."""
    state = docker.inspect_state(service)
    if not state["running"]:
        return
    if state["paused"]:
        docker.run(["unpause", topology.container(service)])
    if topology.NETWORK not in state["networks"]:
        docker.run(["network", "connect", "--ip", topology.SERVICES[service],
                    topology.NETWORK, topology.container(service)])
    for cmd in heal_cmds(lab_iface(service)):
        docker.exec_(service, cmd, check=False)


def heal_all() -> None:
    for svc in topology.SYNTRAF_NODES:
        try:
            heal(svc)
        except subprocess.CalledProcessError:
            pass  # conteneur absent


def active(service: str) -> list[str]:
    """Descriptions lisibles des pannes actives sur ce service."""
    state = docker.inspect_state(service)
    if not state["running"]:
        return []
    found = []
    if state["paused"]:
        return ["en pause"]
    if topology.NETWORK not in state["networks"]:
        return ["réseau du lab retiré"]
    qdisc = docker.exec_(service, ["tc", "qdisc", "show"], check=False).stdout
    for line in qdisc.splitlines():
        if "netem" in line:
            found.append("netem " + line.split("netem", 1)[1].split(" seed")[0].strip())
    rules = docker.exec_(service, ["iptables-save"], check=False).stdout
    n = sum(1 for line in rules.splitlines() if TAG in line)
    if n:
        found.append(f"iptables DROP ({n} règles)")
    return found


def kill_iperf(service: str, signal: str = "KILL") -> None:
    docker.exec_(service, ["pkill", f"-{signal}", "-x", "iperf3"], check=False)


def restart(service: str) -> None:
    docker.run(["restart", topology.container(service)], timeout=120)


def flap(service: str, mode: CutMode, off_s: float, on_s: float, count: int) -> None:
    try:
        for _ in range(count):
            cut(service, mode)
            time.sleep(off_s)
            heal(service)
            time.sleep(on_s)
    finally:
        heal(service)

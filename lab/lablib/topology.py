"""Description statique du lab : services, adresses, identifiants, flux attendus."""
from typing import Literal

PROJECT = "syntraf-lab"
NETWORK = "syntraf_lab"
SUBNET_PREFIX = "172.30.0."

SERVICES: dict[str, str] = {
    "victoriametrics": "172.30.0.10",
    "server": "172.30.0.20",
    "c1": "172.30.0.31",
    "c2": "172.30.0.32",
    "c3": "172.30.0.33",
    "c4": "172.30.0.34",
    "grafana": "172.30.0.40",
}
CLIENTS = ("c1", "c2", "c3", "c4")
SYNTRAF_NODES = ("server",) + CLIENTS
CLIENT_UID: dict[str, str] = {c: f"LAB_C{c[1]}" for c in CLIENTS}
FIXED = ("c1", "c2")
DYNAMIC = ("c3", "c4")

DSCP = "0"
INTERVAL = 1
WATCHDOG = 2
RECOVERY_S = 2 * INTERVAL + WATCHDOG + 10
# Âge maximal du dernier point pour qu'un flux soit « vivant » : intervalle iperf3 + envoi du client
# + écriture serveur + visibilité VictoriaMetrics (≈ 4 s mesurées).
FRESH_S = 10


def container(service: str) -> str:
    return f"{PROJECT}-{service}"


def flow_uid(src_uid: str, dst_uid: str) -> str:
    return f"{src_uid}__TO__{dst_uid}__ON__DSCP{DSCP}"


def expected_flows() -> list[str]:
    uids = [CLIENT_UID[c] for c in CLIENTS]
    return [flow_uid(a, b) for a in uids for b in uids if a != b]


def flows_involving(uid: str, direction: Literal["from", "to", "both"]) -> list[str]:
    out = []
    for f in expected_flows():
        src, dst = f.split("__ON__")[0].split("__TO__")
        if (direction in ("from", "both") and src == uid) or (direction in ("to", "both") and dst == uid):
            out.append(f)
    return out

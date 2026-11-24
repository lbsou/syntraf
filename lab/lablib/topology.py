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
    "c4": "10.99.0.34",           # STARLINK, derrière le routeur NAT starlink-gw
    "starlink-gw": "10.99.0.2",   # côté LAN du routeur (10.99.0.1 : le pont Docker) (sa patte WAN : 172.30.0.35)
    "c5": "10.98.0.35",           # LTE_5G, derrière le routeur mobile-gw (CGNAT d'un opérateur mobile)
    "mobile-gw": "10.98.0.2",     # côté LAN du routeur (sa patte WAN : 172.30.0.36)
    "grafana": "172.30.0.40",
}
# Réseau Docker de chaque service hors du réseau principal du lab, et préfixe de chaque réseau
LAN_NETWORK, LAN_PREFIX = "syntraf_starlink_lan", "10.99.0."
MOBILE_NETWORK, MOBILE_PREFIX = "syntraf_mobile_lan", "10.98.0."
NETWORK_OF: dict[str, str] = {"c4": LAN_NETWORK, "starlink-gw": LAN_NETWORK,
                              "c5": MOBILE_NETWORK, "mobile-gw": MOBILE_NETWORK}
PREFIX_OF: dict[str, str] = {NETWORK: SUBNET_PREFIX, LAN_NETWORK: LAN_PREFIX, MOBILE_NETWORK: MOBILE_PREFIX}
GATEWAY_OF: dict[str, str] = {"c4": "starlink-gw", "c5": "mobile-gw"}  # sonde derrière un NAT → son routeur
GATEWAY_WAN_IP = "172.30.0.35"


def network_of(service: str) -> str:
    return NETWORK_OF.get(service, NETWORK)


def subnet_prefix(service: str) -> str:
    return PREFIX_OF[network_of(service)]


CLIENTS = ("c1", "c2", "c3", "c4", "c5")
SYNTRAF_NODES = ("server",) + CLIENTS
CLIENT_UID: dict[str, str] = {c: f"LAB_C{c[1]}" for c in CLIENTS}
CLIENT_UID["c4"] = "STARLINK"  # nœud satellite derrière un NAT : latence, gigue et pertes (labctl.py degrade)
CLIENT_UID["c5"] = "LTE_5G"    # nœud mobile 5G/LTE derrière un CGNAT (labctl.py degrade, profil dans le README)
BEHIND_NAT = tuple(GATEWAY_OF)
FAULT_TARGETS = SYNTRAF_NODES + tuple(GATEWAY_OF.values())
FIXED = ("c1", "c2")
DYNAMIC = ("c3", "c4", "c5")

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
    """Maillage complet, sauf entre deux sondes derrière un NAT (aucune ne peut joindre l'autre)."""
    nat = {CLIENT_UID[c] for c in BEHIND_NAT}
    uids = [CLIENT_UID[c] for c in CLIENTS]
    return [flow_uid(a, b) for a in uids for b in uids if a != b and not (a in nat and b in nat)]


def flows_involving(uid: str, direction: Literal["from", "to", "both"]) -> list[str]:
    out = []
    for f in expected_flows():
        src, dst = f.split("__ON__")[0].split("__TO__")
        if (direction in ("from", "both") and src == uid) or (direction in ("to", "both") and dst == uid):
            out.append(f)
    return out

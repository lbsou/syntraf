"""Adresses d'une sonde : celles qu'elle a (ses interfaces, envoyées à chaque connexion), celle que le serveur voit,
celles ajoutées à la main (SERVER_CLIENT.EXTRA_ADDRESSES), et l'adresse par laquelle chaque pair la joint.

Choix, pour un pair A qui se connecte à la sonde B (une seule adresse par paire) :
  1. forcée : A.OVERRIDE_DST_NODE_IP[B] ;
  2. même réseau : une adresse de B dans un sous-réseau où A a lui-même une adresse (B a une patte dans le réseau
     interne de A : A passe par là plutôt que par Internet) ;
  3. sinon l'adresse déclarée de B (IP_ADDRESS : fixe, ou celle vue par le serveur pour une sonde dynamique).
Ne comptent jamais comme réseau commun : la boucle locale, les adresses lien-local, les ponts de conteneurs et de
machines virtuelles (docker0 est souvent 172.17.0.1/16 sur deux hôtes sans lien), ni une adresse que A a lui-même
(un même LAN privé recopié sur deux sites).

Les adresses apprises restent en mémoire (Learned) : une sonde les renvoie à chaque connexion. Bibliothèque standard
(psutil pour lire les interfaces de la sonde, s'il est là).
"""
import ipaddress
import socket
import threading
import time

DYNAMIC = "0.0.0.0"
# Interfaces jamais retenues : ponts et interfaces virtuelles locales (Docker, Podman, Kubernetes, libvirt...)
EXCLUDED_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "cilium", "kube", "podman",
                     "lxcbr", "lxdbr", "vmnet", "vboxnet",
                     # Windows : cartes des machines virtuelles (souvent le même 192.168.x.1/24 d'un PC à l'autre)
                     "vmware", "virtualbox")
# Windows, Hyper-V : commutateurs internes seulement ; un commutateur externe (« vEthernet (Externe) ») porte la vraie
# adresse du poste et reste retenu (« veth » ci-dessus ne vise que les paires Linux, pas « vEthernet »)
HYPERV_INTERNAL = ("vethernet (wsl", "vethernet (default switch)", "vethernet (nat)")


def _usable(address, interface=""):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
        return False
    name = str(interface or "").lower()
    if name.startswith("vethernet"):
        return not name.startswith(HYPERV_INTERNAL)
    return not name.startswith(EXCLUDED_PREFIXES)


def _clean(interfaces):
    out = []
    for a in interfaces or []:
        if not isinstance(a, dict):
            continue
        address, prefix, name = a.get("address"), a.get("prefix"), str(a.get("interface") or "")
        if not isinstance(prefix, int) or isinstance(prefix, bool) or not 0 <= prefix <= 32:
            continue
        if _usable(address, name):
            out.append({"address": str(address), "prefix": prefix, "interface": name[:32]})
    return sorted(out, key=lambda a: tuple(int(p) for p in a["address"].split(".")))


def local_interfaces():
    """Côté sonde : [{address, prefix, interface}] de ses interfaces IPv4 utilisables."""
    try:
        import psutil
        found = []
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.netmask:
                    prefix = ipaddress.ip_network(f"0.0.0.0/{a.netmask}").prefixlen
                    found.append({"address": a.address, "prefix": prefix, "interface": name})
        return _clean(found)
    except Exception:  # noqa: BLE001 - simple indication pour le serveur
        return []


class Learned:
    """{uid: {interfaces, observed, seen_at}}, partagé entre les fils du serveur."""

    def __init__(self):
        self._lock = threading.Lock()
        self._by_uid = {}

    def record(self, uid, interfaces, observed, now=None):
        """Mémorise ce que la sonde vient d'annoncer ; True si ses adresses ont changé."""
        entry = {"interfaces": _clean(interfaces), "observed": observed,
                 "seen_at": time.time() if now is None else now}
        with self._lock:
            old = self._by_uid.get(uid)
            self._by_uid[uid] = entry
        return old is None or (old["interfaces"], old["observed"]) != (entry["interfaces"], entry["observed"])

    def get(self, uid):
        with self._lock:
            entry = self._by_uid.get(uid)
            return dict(entry, interfaces=list(entry["interfaces"])) if entry else None

    def interfaces(self, uid):
        entry = self.get(uid)
        return entry["interfaces"] if entry else []

    def rename(self, old, new):
        with self._lock:
            if old in self._by_uid:
                self._by_uid[new] = self._by_uid.pop(old)


LEARNED = Learned()


def _manual(client):
    """Adresses ajoutées à la main : (adresse, réseau ou None) ; « 10.9.0.5/24 » donne aussi son réseau."""
    out = []
    for text in client.get("EXTRA_ADDRESSES") or []:
        text = str(text).strip()
        address, _, prefix = text.partition("/")
        try:
            net = ipaddress.ip_network(f"{address}/{prefix}", strict=False) if prefix else None
        except ValueError:
            net = None
        out.append((address, net))
    return out


def _networks(client, store):
    nets = [ipaddress.ip_network(f"{a['address']}/{a['prefix']}", strict=False) for a in store.interfaces(client["UID"])]
    return nets + [net for _, net in _manual(client) if net is not None]


def _own(client, store):
    return ({a["address"] for a in store.interfaces(client["UID"])} | {a for a, _ in _manual(client)}
            | {str(client.get("IP_ADDRESS") or "")})


def candidates(client, store=None):
    """[(adresse, réseau ou None, source)] de la sonde, l'adresse déclarée en premier."""
    store = store or LEARNED
    out = [(str(client.get("IP_ADDRESS") or ""), None, "declared")]
    for a in store.interfaces(client["UID"]):
        out.append((a["address"], ipaddress.ip_network(f"{a['address']}/{a['prefix']}", strict=False), "interface"))
    out += [(address, net, "manual") for address, net in _manual(client)]
    return out


def choose(src, dst, store=None):
    """(adresse, raison) par laquelle src joint dst : forced, same_network, declared ou unknown."""
    store = store or LEARNED
    forced = (src.get("OVERRIDE_DST_NODE_IP") or {}).get(dst["UID"])
    if forced:
        return str(forced), "forced"
    declared = str(dst.get("IP_ADDRESS") or "")
    if declared in ("", DYNAMIC):
        return DYNAMIC, "unknown"  # sonde dynamique déconnectée : ses pairs ne la cherchent pas
    nets, own = _networks(src, store), _own(src, store)
    for address, _net, _source in candidates(dst, store):
        if address in own or not _usable(address):
            continue
        ip = ipaddress.ip_address(address)
        if any(ip in net for net in nets):
            return address, "same_network"
    return declared, "declared"

"""Adresses d'une sonde (lib/st_addresses.py) : apprises (interfaces, adresse vue par le serveur), ajoutées à la main,
et choix, pour chaque paire, de l'adresse par laquelle un pair joint la sonde."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_addresses as sa  # noqa: E402


def iface(address, prefix, name="eth0"):
    return {"address": address, "prefix": prefix, "interface": name}


def learned(**by_uid):
    store = sa.Learned()
    for uid, (interfaces, observed) in by_uid.items():
        store.record(uid, interfaces, observed, now=1000.0)
    return store


X = {"UID": "X", "IP_ADDRESS": "203.0.113.7"}                         # interne 10.0.0.5/24 + Internet
INTERNE = {"UID": "INTERNE", "IP_ADDRESS": "10.0.0.21"}
DISTANT = {"UID": "DISTANT", "IP_ADDRESS": "198.51.100.40"}
STORE = learned(X=([iface("10.0.0.5", 24, "ens192"), iface("203.0.113.7", 28, "ens224"),
                    iface("172.17.0.1", 16, "docker0"), iface("127.0.0.1", 8, "lo")], "203.0.113.7"),
                INTERNE=([iface("10.0.0.21", 24), iface("172.17.0.1", 16, "docker0")], "10.0.0.21"),
                DISTANT=([iface("192.168.1.10", 24)], "198.51.100.40"))


def test_a_peer_on_the_same_network_uses_the_internal_address():
    assert sa.choose(INTERNE, X, STORE) == ("10.0.0.5", "same_network")


def test_a_remote_peer_uses_the_declared_address():
    assert sa.choose(DISTANT, X, STORE) == ("203.0.113.7", "declared")


def test_a_forced_address_wins_over_everything():
    forcing = dict(INTERNE, OVERRIDE_DST_NODE_IP={"X": "198.51.100.9"})
    assert sa.choose(forcing, X, STORE) == ("198.51.100.9", "forced")


def test_docker_bridges_and_loopback_are_never_used():
    """Deux hôtes ont souvent le même docker0 (172.17.0.1/16) : ce n'est pas un réseau commun."""
    assert [a["address"] for a in STORE.interfaces("X")] == ["10.0.0.5", "203.0.113.7"]
    assert sa.choose(DISTANT, dict(INTERNE), learned(INTERNE=([iface("172.17.0.1", 16, "docker0")], "x"),
                                                    DISTANT=([iface("172.17.0.2", 16, "eth0")], "y"))) \
        == ("10.0.0.21", "declared")


def test_an_address_the_peer_itself_owns_is_never_chosen():
    store = learned(A=([iface("192.168.50.1", 24, "eth1")], "192.0.2.1"),
                    B=([iface("192.168.50.1", 24, "eth1")], "192.0.2.2"))  # même LAN privé recopié sur deux sites
    assert sa.choose({"UID": "A", "IP_ADDRESS": "192.0.2.1"}, {"UID": "B", "IP_ADDRESS": "192.0.2.2"}, store) \
        == ("192.0.2.2", "declared")


def test_a_manual_address_with_a_prefix_counts_as_a_network():
    x = dict(X, EXTRA_ADDRESSES=["10.9.0.5/24"])
    peer = {"UID": "P", "IP_ADDRESS": "10.9.0.77"}
    assert sa.choose(peer, x, learned(P=([iface("10.9.0.77", 24)], "10.9.0.77"))) == ("10.9.0.5", "same_network")


def test_a_dynamic_probe_that_is_not_connected_stays_unknown():
    dyn = {"UID": "X", "IP_ADDRESS": "0.0.0.0"}
    assert sa.choose(INTERNE, dyn, STORE) == ("0.0.0.0", "unknown")


def test_without_learned_addresses_nothing_changes():
    assert sa.choose(INTERNE, X, sa.Learned()) == ("203.0.113.7", "declared")


def test_record_tells_whether_the_addresses_changed():
    store = sa.Learned()
    assert store.record("X", [iface("10.0.0.5", 24)], "203.0.113.7", now=1.0) is True
    assert store.record("X", [iface("10.0.0.5", 24)], "203.0.113.7", now=2.0) is False
    assert store.get("X")["seen_at"] == 2.0
    assert store.record("X", [iface("10.0.0.6", 24)], "203.0.113.7", now=3.0) is True
    assert store.record("Y", None, "192.0.2.9", now=4.0) is True  # ancienne sonde : rien que l'adresse vue
    assert store.interfaces("Y") == [] and store.get("Y")["observed"] == "192.0.2.9"


def test_malformed_interfaces_from_a_probe_are_ignored():
    store = sa.Learned()
    store.record("X", [{"address": "pas une ip", "prefix": 24}, {"address": "10.0.0.5", "prefix": 99},
                       "texte", iface("10.0.0.6", 24)], "1.2.3.4", now=1.0)
    assert [a["address"] for a in store.interfaces("X")] == ["10.0.0.6"]


def test_the_probe_reports_its_interfaces_with_their_prefix():
    found = sa.local_interfaces()
    assert isinstance(found, list)
    for a in found:
        assert set(a) == {"address", "prefix", "interface"} and 0 <= a["prefix"] <= 32

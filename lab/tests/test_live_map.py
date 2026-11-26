"""Carte de la topologie en direct (lib/st_live_map.py) : sondes, liens par paire, qualité de chaque sens.
Tourne dans l'image du lab (dépendances de SYNTRAF)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_live_map as lm  # noqa: E402

FLOWS = [{"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B"}, {"MESH_GROUP": "G", "CLIENT": "B", "SERVER": "A"},
         {"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "C"}, {"MESH_GROUP": "H", "CLIENT": "C", "SERVER": "B"}]
CLIENTS = [{"uid": "A", "status": "CONNECTED", "behind_nat": False}, {"uid": "B", "status": "CONNECTED"},
           {"uid": "C", "status": "DISCONNECTED", "behind_nat": True}]
METRICS = {
    "loss": {("A", "B", "G"): 0.0, ("B", "A", "G"): 6.0},
    "jitter": {("A", "B", "G"): 1.5, ("B", "A", "G"): 4.0},
    "mos": {("A", "B", "G"): 4.4, ("B", "A", "G"): 3.7},
    "rtt": {("A", "B"): 40.0},
}


def build(**kw):
    return lm.build(FLOWS, CLIENTS, METRICS, **kw)


def test_nodes_carry_status_and_nat():
    nodes = {n["id"]: n for n in build()["nodes"]}
    assert nodes["A"]["status"] == "CONNECTED" and nodes["C"]["behind_nat"] is True
    assert set(nodes) == {"A", "B", "C"}


def test_one_link_per_pair_with_both_directions():
    links = {tuple(sorted((l["a"], l["b"]))) + (l["mesh_group"],): l for l in build()["links"]}
    ab = links[("A", "B", "G")]
    assert {d["from"] for d in ab["directions"]} == {"A", "B"}
    assert ab["rtt_ms"] == 40.0


def test_a_link_takes_the_worst_direction():
    ab = [l for l in build()["links"] if {l["a"], l["b"]} == {"A", "B"}][0]
    assert ab["loss_pct"] == 6.0 and ab["mos"] == 3.7 and ab["jitter_ms"] == 4.0
    assert ab["grade"]["loss"] == "orange" and ab["grade"]["mos"] == "yellow"


def test_an_expected_flow_without_measurement_is_shown_as_no_data():
    ac = [l for l in build()["links"] if {l["a"], l["b"]} == {"A", "C"}][0]
    assert ac["loss_pct"] is None and ac["grade"]["loss"] == "nodata"


def test_filter_by_mesh_group():
    links = build(mesh_group="H")["links"]
    assert [(l["a"], l["b"]) for l in links] == [("B", "C")] or [(l["a"], l["b"]) for l in links] == [("C", "B")]
    assert {n["id"] for n in build(mesh_group="H")["nodes"]} == {"B", "C"}


def test_grades():
    assert lm.grade("loss", 0.2) == "green" and lm.grade("loss", 25) == "red"
    assert lm.grade("mos", 4.2) == "green" and lm.grade("mos", 2.0) == "red"
    assert lm.grade("rtt", 50) == "green" and lm.grade("rtt", 350) == "red"
    assert lm.grade("rtt", None) == "nodata"


def test_metrics_are_read_from_victoriametrics():
    class FakeVm:
        def query(self, expr):
            if "RX_PCT_LOSS" in expr:
                return [{"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G"}, "value": [0, "2.5"]}]
            if "LATENCY_RTT_MS" in expr:
                return [{"metric": {"CLIENT": "A", "SERVER": "B"}, "value": [0, "33"]}]
            return []

    m = lm.read_metrics(FakeVm())
    assert m["loss"][("A", "B", "G")] == 2.5 and m["rtt"][("A", "B")] == 33.0


def test_victoriametrics_instant_queries():
    pytest.importorskip("toml")
    try:
        from lib.st_vm_admin import VmAdmin
    except (ImportError, SystemExit):
        pytest.skip("dépendances du serveur absentes")
    import json
    calls = []

    def http(method, path, params=None, body=None):
        calls.append((path, params))
        return 200, json.dumps({"status": "success", "data": {"resultType": "vector", "result": [{"value": [0, "1"]}]}})

    assert VmAdmin({"DB_UID": "VM", "DB_SERVER": "h", "DB_PORT": "1"}, http=http).query("up") == [{"value": [0, "1"]}]
    assert calls == [("/api/v1/query", {"query": "up"})]


# ------------------------------------------------------------------------------- relecture d'un incident

class HistoryVm:
    """VictoriaMetrics au passé : chaque requête est notée avec son instant."""

    def __init__(self):
        self.calls = []

    def query(self, expr, time=None):
        self.calls.append((expr, time))
        if "RX_PCT_LOSS" in expr:
            return [{"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G"}, "value": [time, "30"]}]
        if "syntraf_client_connected" in expr:
            return [{"metric": {"client": "A"}, "value": [time, "1"]}, {"metric": {"client": "B"}, "value": [time, "0"]}]
        if "SYNTRAF_BASELINE_ALERT" in expr:
            return [{"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G", "METRIC": "loss"}, "value": [time, "1"]}]
        return []

    def query_range(self, expr, start, end, step):
        self.calls.append((expr, (start, end, step)))
        pts = lambda vals: [[start + i * step, str(v)] for i, v in enumerate(vals)]  # noqa: E731
        if "RX_PCT_LOSS" in expr:
            return [{"metric": {}, "values": pts([0.1, 25.0, 0.2])}]
        if "SYNTRAF_BASELINE_ALERT" in expr:
            return [{"metric": {}, "values": pts([0, 2, 1])}]
        return []


def test_the_map_is_read_at_a_past_instant():
    vm = HistoryVm()
    m = lm.read_metrics(vm, at=1000)
    assert m["loss"][("A", "B", "G")] == 30.0
    assert {t for _, t in vm.calls} == {1000}


def test_probe_states_and_open_alerts_at_that_instant():
    vm = HistoryVm()
    assert lm.read_status(vm, 1000) == {"A": "CONNECTED", "B": "DISCONNECTED"}
    assert lm.read_alerts(vm, 1000) == [{"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G", "METRIC": "loss"}]


def test_a_link_shows_the_alerts_open_on_either_direction():
    m = lm.build(FLOWS, CLIENTS, METRICS, alerts=[{"CLIENT": "B", "SERVER": "A", "MESH_GROUP": "G", "METRIC": "loss"},
                                                  {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G", "METRIC": "jitter"},
                                                  {"CLIENT": "A", "SERVER": "C", "MESH_GROUP": "H", "METRIC": "loss"}])
    ab = next(l for l in m["links"] if (l["a"], l["b"], l["mesh_group"]) == ("A", "B", "G"))
    ac = next(l for l in m["links"] if (l["a"], l["b"], l["mesh_group"]) == ("A", "C", "G"))
    assert ab["alerts"] == ["B → A loss", "A → B jitter"] and ac["alerts"] == []  # autre groupe : pas ce lien


def test_the_timeline_gives_the_worst_state_per_step_to_find_the_incident():
    vm = HistoryVm()
    t = lm.timeline(vm, 1000, 1120, 60, mesh_group='G"x')
    assert t["t"] == [1000, 1060, 1120]
    assert t["loss"] == [0.1, 25.0, 0.2] and t["alerts"] == [0, 2, 1]
    assert t["grade"]["loss"] == ["green", "red", "green"]
    exprs = [e for e, _ in vm.calls]
    assert all('MESH_GROUP="G\\"x"' in e for e in exprs if "RX_PCT_LOSS" in e)  # guillemets échappés


def test_victoriametrics_queries_at_an_instant():
    pytest.importorskip("toml")
    try:
        from lib.st_vm_admin import VmAdmin
    except (ImportError, SystemExit):
        pytest.skip("dépendances du serveur absentes")
    import json
    calls = []

    def http(method, path, params=None, body=None):
        calls.append((path, params))
        return 200, json.dumps({"status": "success", "data": {"resultType": "vector", "result": []}})

    VmAdmin({"DB_UID": "VM", "DB_SERVER": "h", "DB_PORT": "1"}, http=http).query("up", time=1234)
    assert calls == [("/api/v1/query", {"query": "up", "time": 1234})]


def test_each_direction_has_its_own_grade():
    """Carte : une flèche par sens, colorée par la qualité de CE sens (et non par le pire des deux)."""
    ab = [l for l in build()["links"] if {l["a"], l["b"]} == {"A", "B"}][0]
    by = {(d["from"], d["to"]): d for d in ab["directions"]}
    assert by[("A", "B")]["grade"]["loss"] == "green" and by[("B", "A")]["grade"]["loss"] == "orange"
    assert by[("A", "B")]["grade"]["mos"] == "green" and by[("B", "A")]["grade"]["mos"] == "yellow"
    ac = [l for l in build()["links"] if {l["a"], l["b"]} == {"A", "C"}][0]
    assert ac["directions"][0]["grade"]["loss"] == "nodata"


# --- Réseau local ou Internet : par l'adresse de destination de chaque flux (GLOBAL.INTERNAL_NETWORKS)

def test_an_address_is_local_when_it_belongs_to_an_internal_network():
    from lib import st_addresses as sa
    nets = sa.internal_networks({"GLOBAL": {"INTERNAL_NETWORKS": "10.0.0.0/8, 142.83.130.0/23"}})
    assert sa.classify("10.249.77.29", nets) == "local"
    assert sa.classify("142.83.130.23", nets) == "local"          # plage publique déclarée interne
    assert sa.classify("69.159.150.87", nets) == "internet"
    assert sa.classify("192.168.1.10", nets) == "internet"        # non déclarée : la configuration décide
    assert sa.classify("0.0.0.0", nets) == sa.classify("probe.example.org", nets) == "unknown"


def test_the_internal_networks_default_to_10_slash_8_and_ignore_mistakes():
    from lib import st_addresses as sa
    assert [str(n) for n in sa.internal_networks({})] == ["10.0.0.0/8"]
    assert [str(n) for n in sa.internal_networks({"GLOBAL": {"INTERNAL_NETWORKS": "10.0.0.0/8;pas un réseau 172.16.0.0/12"}})] \
        == ["10.0.0.0/8", "172.16.0.0/12"]


def test_each_direction_knows_its_path_from_the_generated_connectors():
    generated = {
        "A": {"CONNECTORS": {"k1": {"UID_CLIENT": "A", "UID_SERVER": "B", "DESTINATION_ADDRESS": "10.0.0.2",
                                    "MESH_GROUP": "G", "BIDIR": False}}},
        "B": {"CONNECTORS": {"k2": {"UID_CLIENT": "B", "UID_SERVER": "A", "DESTINATION_ADDRESS": "203.0.113.1",
                                    "MESH_GROUP": "G", "BIDIR": False}}},
        "C": {"CONNECTORS": {"k3": {"UID_CLIENT": "C", "UID_SERVER": "A", "DESTINATION_ADDRESS": "203.0.113.1",
                                    "MESH_GROUP": "G", "BIDIR": True}}},  # C derrière un NAT : les deux sens
    }
    from lib import st_addresses as sa
    paths = lm.flow_paths(generated, sa.internal_networks({}))
    assert paths[("A", "B", "G")] == {"address": "10.0.0.2", "via": "local"}
    assert paths[("B", "A", "G")] == {"address": "203.0.113.1", "via": "internet"}
    assert paths[("C", "A", "G")] == paths[("A", "C", "G")] == {"address": "203.0.113.1", "via": "internet"}


def test_the_map_carries_the_path_of_each_direction():
    paths = {("A", "B", "G"): {"address": "10.0.0.2", "via": "local"},
             ("B", "A", "G"): {"address": "203.0.113.1", "via": "internet"}}
    ab = [l for l in lm.build(FLOWS, CLIENTS, METRICS, paths=paths)["links"] if {l["a"], l["b"]} == {"A", "B"}][0]
    by = {(d["from"], d["to"]): d for d in ab["directions"]}
    assert (by[("A", "B")]["via"], by[("A", "B")]["address"]) == ("local", "10.0.0.2")
    assert (by[("B", "A")]["via"], by[("B", "A")]["address"]) == ("internet", "203.0.113.1")
    ac = [l for l in lm.build(FLOWS, CLIENTS, METRICS, paths=paths)["links"] if {l["a"], l["b"]} == {"A", "C"}][0]
    assert ac["directions"][0]["via"] == "unknown" and ac["directions"][0]["address"] is None


# --- VPN : sous-réseaux d'accès VPN (GLOBAL.VPN_NETWORKS) et tunnel partagé ou complet (GLOBAL.VPN_MODE)

def test_a_flow_through_the_vpn_split_or_full_tunnel():
    from lib import st_addresses as sa
    nets = sa.internal_networks({})
    vpn = sa.parse_networks("10.251.0.0/16")[0]
    c = lambda addr, on_vpn=False, full=False: sa.classify(addr, nets, vpn, on_vpn, full)  # noqa: E731
    assert c("10.251.243.248") == "vpn"                        # destination dans le VPN
    assert c("10.249.77.29", on_vpn=True) == "vpn"             # sonde au bout du VPN vers le réseau interne
    assert c("10.249.77.29") == "local"
    assert c("142.83.130.23", on_vpn=True) == "internet"       # tunnel partagé : le public sort par Internet
    assert c("142.83.130.23", on_vpn=True, full=True) == "vpn"  # tunnel complet : tout passe par le VPN
    assert c("142.83.130.23") == "internet"


def test_the_initiator_of_a_connection_decides_if_it_starts_from_the_vpn():
    from lib import st_addresses as sa
    generated = {"H": {"CONNECTORS": {
        "k1": {"UID_CLIENT": "H", "UID_SERVER": "S", "DESTINATION_ADDRESS": "142.83.130.23", "MESH_GROUP": "G", "BIDIR": True},
        "k2": {"UID_CLIENT": "H", "UID_SERVER": "P", "DESTINATION_ADDRESS": "10.249.77.29", "MESH_GROUP": "G", "BIDIR": True}}}}
    nets, vpn = sa.internal_networks({}), sa.parse_networks("10.251.0.0/16")[0]
    split = lm.flow_paths(generated, nets, vpn, vpn_clients={"H"}, full_tunnel=False)
    assert split[("H", "S", "G")]["via"] == split[("S", "H", "G")]["via"] == "internet"
    assert split[("H", "P", "G")]["via"] == split[("P", "H", "G")]["via"] == "vpn"
    full = lm.flow_paths(generated, nets, vpn, vpn_clients={"H"}, full_tunnel=True)
    assert full[("H", "S", "G")]["via"] == "vpn"


def test_a_probe_is_on_the_vpn_when_one_of_its_addresses_is_in_a_vpn_subnet():
    from lib import st_addresses as sa
    store = sa.Learned()
    store.record("H", [{"address": "10.251.243.248", "prefix": 32, "interface": "Ethernet 4"},
                       {"address": "192.168.3.41", "prefix": 24, "interface": "Ethernet 7"}], "10.251.243.248", now=1.0)
    store.record("P", [{"address": "10.249.77.29", "prefix": 22, "interface": "ens192"}], "10.249.77.29", now=1.0)
    clients = [{"UID": "H", "IP_ADDRESS": "0.0.0.0"}, {"UID": "P", "IP_ADDRESS": "10.249.77.29"}]
    assert sa.vpn_clients(clients, sa.parse_networks("10.251.0.0/16")[0], store) == {"H"}
    assert sa.vpn_clients(clients, [], store) == set()

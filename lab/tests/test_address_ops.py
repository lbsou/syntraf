"""Adresses des sondes côté serveur : choix par paire dans les flux générés, lecture et modification depuis la webui
(ajouter une adresse, forcer celle d'un pair), et propagation quand une sonde annonce d'autres adresses."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib import st_addresses, st_mesh_group_ops as ops
    from lib.st_conf_validation import validate_group, generate_client_config_mesh
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


class FakeClient:
    def __init__(self):
        self.status, self.capabilities = "CONNECTED", {"LIVE_CONFIG"}


def iface(address, prefix, name="eth0"):
    return {"address": address, "prefix": prefix, "interface": name}


@pytest.fixture
def state(tmp_path, monkeypatch):
    store = st_addresses.Learned()
    store.record("X", [iface("10.0.0.5", 24, "ens192"), iface("203.0.113.7", 28, "ens224")], "203.0.113.7", now=1.0)
    store.record("INTERNE", [iface("10.0.0.21", 24)], "10.0.0.21", now=1.0)
    store.record("DISTANT", [iface("192.168.1.10", 24)], "198.51.100.40", now=1.0)
    monkeypatch.setattr(st_addresses, "LEARNED", store)
    cfg = {"SERVER": {"BIND_ADDRESS": "0.0.0.0", "SERVER_PORT": "6531", "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                      "TOKEN": {"t": "secret-token"}},
           "GLOBAL": {},
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}],
           "SERVER_CLIENT": [{"UID": "X", "IP_ADDRESS": "203.0.113.7", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                             {"UID": "INTERNE", "IP_ADDRESS": "10.0.0.21", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                             {"UID": "DISTANT", "IP_ADDRESS": "198.51.100.40", "MESH_GROUP_UID_LIST": ["GROUP1"]}]}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {u: FakeClient() for u in ("X", "INTERNE", "DISTANT")},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def destination(state, src, dst):
    connectors = state["_dict_by_node_generated_config"][src].get("CONNECTORS") or {}
    found = [c["DESTINATION_ADDRESS"] for k, c in connectors.items() if k.endswith(f"_CONNECTING_TO_{dst}")]
    assert len(found) == 1, (src, dst, list(connectors))
    return found[0]


def test_each_peer_reaches_the_probe_by_the_best_address(state):
    assert destination(state, "INTERNE", "X") == "10.0.0.5"         # même réseau interne
    assert destination(state, "DISTANT", "X") == "203.0.113.7"      # par Internet
    assert destination(state, "X", "INTERNE") == "10.0.0.21"


def test_the_addresses_of_a_probe_and_how_each_peer_reaches_it(state):
    a = ops.client_addresses(state, "X")
    assert [(x["address"], x["source"], x.get("interface")) for x in a["learned"]] == [
        ("203.0.113.7", "observed", None), ("10.0.0.5", "interface", "ens192"), ("203.0.113.7", "interface", "ens224")]
    peers = {p["peer"]: (p["address"], p["reason"]) for p in a["peers"]}
    assert peers == {"INTERNE": ("10.0.0.5", "same_network"), "DISTANT": ("203.0.113.7", "declared")}
    assert a["manual"] == [] and a["declared"] == "203.0.113.7"


def test_an_address_can_be_added_and_forced_for_one_peer_live(state):
    r = ops.update_client_addresses(state, "X", {"EXTRA_ADDRESSES": ["198.51.100.9"],
                                                 "FORCED": {"DISTANT": "198.51.100.9"}}, "admin")
    assert r["reconnected_clients"] == [] and "DISTANT" in r["reconfigured_clients"]
    disk = toml.load(state["config_file_path"])
    by = {c["UID"]: c for c in disk["SERVER_CLIENT"]}
    assert by["X"]["EXTRA_ADDRESSES"] == ["198.51.100.9"]
    assert by["DISTANT"]["OVERRIDE_DST_NODE_IP"] == {"X": "198.51.100.9"}
    assert destination(state, "DISTANT", "X") == "198.51.100.9"
    assert destination(state, "INTERNE", "X") == "10.0.0.5"         # les autres pairs ne changent pas
    peers = {p["peer"]: p for p in ops.client_addresses(state, "X")["peers"]}
    assert peers["DISTANT"]["reason"] == "forced" and peers["DISTANT"]["forced"] == "198.51.100.9"

    ops.update_client_addresses(state, "X", {"EXTRA_ADDRESSES": [], "FORCED": {"DISTANT": ""}}, "admin")
    by = {c["UID"]: c for c in toml.load(state["config_file_path"])["SERVER_CLIENT"]}
    assert "OVERRIDE_DST_NODE_IP" not in by["DISTANT"] and "EXTRA_ADDRESSES" not in by["X"]
    assert destination(state, "DISTANT", "X") == "203.0.113.7"


def test_a_preview_changes_nothing(state):
    before = Path(state["config_file_path"]).read_text()
    r = ops.update_client_addresses(state, "X", {"EXTRA_ADDRESSES": ["10.9.0.5/24"], "FORCED": {}}, "admin",
                                    dry_run=True)
    assert r["dry_run"] is True and Path(state["config_file_path"]).read_text() == before


def test_invalid_addresses_are_field_errors(state):
    with pytest.raises(ops.OpError) as e:
        ops.update_client_addresses(state, "X", {"EXTRA_ADDRESSES": ["pas une adresse !"],
                                                 "FORCED": {"DISTANT": "x y"}}, "admin")
    assert e.value.status == 400 and set(e.value.fields) == {"EXTRA_ADDRESSES", "FORCED.DISTANT"}
    with pytest.raises(ops.OpError) as e:
        ops.update_client_addresses(state, "X", {"FORCED": {"INCONNU": "10.0.0.1"}}, "admin")
    assert e.value.status == 400


def test_new_addresses_announced_by_a_probe_reach_only_the_peers_concerned(state):
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur
    from lib import st_mesh
    st_addresses.LEARNED.record("X", [iface("10.0.0.99", 24, "ens192")], "203.0.113.7", now=2.0)
    pushed = st_mesh.server_push_address_change(state["config"], state["_dict_by_node_generated_config"],
                                                state["dict_of_clients"],
                                                state["dict_of_commands_for_network_clients"], "X")
    assert pushed == ["INTERNE"]
    assert state["dict_of_commands_for_network_clients"]["INTERNE"] == [{"ACTION": "NEWCONFIG"}]
    assert destination(state, "INTERNE", "X") == "10.0.0.99"

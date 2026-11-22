"""Clients derrière un NAT (BEHIND_NAT) : génération bidirectionnelle, réglage dans la webui, détection automatique,
maintien de la correspondance NAT. Les tests des opérations tournent dans l'image du lab (dépendances de SYNTRAF).
"""
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_nat  # noqa: E402  (sans dépendance)
from lib import st_flow_catalog  # noqa: E402

try:
    import toml
    from lib import st_mesh_group_ops as ops
    from lib.st_conf_validation import validate_group, generate_client_config_mesh
except (ImportError, SystemExit):
    ops = None

needs_syntraf = pytest.mark.skipif(ops is None, reason="dépendances de SYNTRAF absentes (image du lab)")


# ---------------------------------------------------------------------------------- détection et maintien

def test_nat_is_detected_when_the_server_sees_another_address():
    assert st_nat.nat_detected("203.0.113.7", ["10.99.0.34", "127.0.0.1"]) is True
    assert st_nat.nat_detected("172.30.0.31", ["172.30.0.31"]) is False
    assert st_nat.nat_detected("172.30.0.31", []) is None  # client trop ancien : on ne sait pas


def test_keepalive_is_an_empty_udp_datagram_from_the_return_stream_port():
    header = st_nat.udp_keepalive(40123, 15995)
    src, dst, length, checksum = struct.unpack("!HHHH", header)
    assert (src, dst, length, checksum) == (40123, 15995, 8, 0)  # somme de contrôle facultative en IPv4


# ---------------------------------------------------------------------------------- génération

def config(nat=(), topology="MESH", hubs=None, nodes=("NODE_A", "NODE_B", "NODE_C")):
    group = {"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1",
             "TOPOLOGY": topology}
    if hubs:
        group["HUBS"] = list(hubs)
    clients = []
    for i, u in enumerate(nodes):
        c = {"UID": u, "IP_ADDRESS": f"10.0.0.{i + 1}", "MESH_GROUP_UID_LIST": ["GROUP1"]}
        if u in nat:
            c["BEHIND_NAT"] = True
        clients.append(c)
    return {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100"}, "GLOBAL": {}, "MESH_GROUP": [group],
            "SERVER_CLIENT": clients}


def generate(cfg):
    assert validate_group(cfg, "MESH_GROUP")
    generated = {}
    generate_client_config_mesh(cfg, generated)
    return generated


@needs_syntraf
def test_a_client_behind_nat_opens_nothing_and_measures_both_directions_itself():
    cfg = config(nat=("NODE_A",))
    gen = generate(cfg)
    a = gen["NODE_A"]
    assert not a.get("LISTENERS")
    assert sorted(c["UID_SERVER"] for c in a["CONNECTORS"].values()) == ["NODE_B", "NODE_C"]
    assert all(c["BIDIR"] for c in a["CONNECTORS"].values())
    assert all(c["UID_SERVER"] != "NODE_A" for c in (gen["NODE_B"].get("CONNECTORS") or {}).values())
    flows = {(f["CLIENT"], f["SERVER"]) for f in st_flow_catalog.expected_flows(cfg, gen)}
    assert {("NODE_B", "NODE_A"), ("NODE_A", "NODE_B")} <= flows and len(flows) == 6  # rien ne manque


@needs_syntraf
def test_two_clients_behind_nat_cannot_measure_each_other():
    cfg = config(nat=("NODE_A", "NODE_B"))
    flows = {(f["CLIENT"], f["SERVER"]) for f in st_flow_catalog.expected_flows(cfg, generate(cfg))}
    assert ("NODE_A", "NODE_B") not in flows and ("NODE_B", "NODE_A") not in flows
    assert len(flows) == 4


@needs_syntraf
def test_hub_and_spoke_suits_spokes_behind_nat():
    cfg = config(nat=("NODE_B", "NODE_C"), topology="HUB_SPOKE", hubs=("NODE_A",))
    flows = {(f["CLIENT"], f["SERVER"]) for f in st_flow_catalog.expected_flows(cfg, generate(cfg))}
    assert flows == {("NODE_A", "NODE_B"), ("NODE_B", "NODE_A"), ("NODE_A", "NODE_C"), ("NODE_C", "NODE_A")}


# ---------------------------------------------------------------------------------- webui

@pytest.fixture
def state(tmp_path):
    cfg = config()
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    generated = generate(live)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": {}, "dict_of_clients": {},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def form(**over):
    return dict({"IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["GROUP1"]}, **over)


@needs_syntraf
def test_behind_nat_is_set_from_the_client_form(state):
    ops.update_client(state, "NODE_A", form(BEHIND_NAT=True), actor="x")
    assert toml.load(state["config_file_path"])["SERVER_CLIENT"][0]["BEHIND_NAT"] is True
    assert not state["_dict_by_node_generated_config"]["NODE_A"].get("LISTENERS")
    ops.update_client(state, "NODE_A", form(BEHIND_NAT=False), actor="x")
    assert "BEHIND_NAT" not in toml.load(state["config_file_path"])["SERVER_CLIENT"][0]
    ops.update_client(state, "NODE_A", form(), actor="x")  # un ancien appel sans la clé ne change rien
    assert "BEHIND_NAT" not in toml.load(state["config_file_path"])["SERVER_CLIENT"][0]


@needs_syntraf
def test_the_client_list_shows_a_detected_nat(state):
    class Seen:
        nat_detected = True
    state["dict_of_clients"]["NODE_B"] = Seen()
    rows = {r["UID"]: r for r in ops.list_clients(state)}
    assert rows["NODE_B"]["NAT_DETECTED"] is True and rows["NODE_A"]["NAT_DETECTED"] is None


@needs_syntraf
@pytest.mark.parametrize("nat", ["NODE_A", "NODE_D"])  # premier ou dernier déclaré
def test_generation_does_not_reuse_the_objects_of_the_previous_pair(nat):
    nodes = ("NODE_A", "NODE_B", "NODE_C", "NODE_D")
    gen = generate(config(nat=(nat,), nodes=nodes))
    for uid, node in gen.items():
        assert all(c["UID_SERVER"] != uid for c in (node.get("CONNECTORS") or {}).values()), uid  # jamais vers soi
        assert all(lst["UID_CLIENT"] != uid for lst in (node.get("LISTENERS") or {}).values()), uid
        assert all(c["UID_SERVER"] != nat for c in (node.get("CONNECTORS") or {}).values()), uid  # personne n'y entre
    assert not gen[nat].get("LISTENERS")
    assert sorted(c["UID_SERVER"] for c in gen[nat]["CONNECTORS"].values()) == sorted(set(nodes) - {nat})
    others = set(nodes) - {nat}
    for uid in others:
        assert sorted(lst["UID_CLIENT"] for lst in gen[uid]["LISTENERS"].values()) == sorted(set(nodes) - {uid})

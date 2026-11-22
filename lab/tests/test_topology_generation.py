"""Topologies dans la génération de la config des clients, la validation et les opérations de la webui.
Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib import st_mesh_group_ops as ops
    from lib.st_conf_validation import validate_group, generate_client_config_mesh
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)

NODES = ("NODE_A", "NODE_B", "NODE_C", "NODE_D")


class FakeClient:
    status = "CONNECTED"


def config(**group):
    return {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100"}, "GLOBAL": {},
            "MESH_GROUP": [dict({"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218",
                                 "INTERVAL": "1"}, **group)],
            "SERVER_CLIENT": [{"UID": u, "IP_ADDRESS": f"10.0.0.{i + 1}", "MESH_GROUP_UID_LIST": ["GROUP1"]}
                              for i, u in enumerate(NODES)]}


def connectors(cfg):
    assert validate_group(cfg, "MESH_GROUP")
    generated = {}
    generate_client_config_mesh(cfg, generated)
    return {u: len(c.get("CONNECTORS") or {}) for u, c in generated.items()}


def test_generation_follows_the_topology():
    assert connectors(config()) == {u: 3 for u in NODES}
    assert connectors(config(TOPOLOGY="HUB_SPOKE", HUBS=["NODE_A"])) == {"NODE_A": 3, "NODE_B": 1, "NODE_C": 1, "NODE_D": 1}
    assert connectors(config(TOPOLOGY="DUAL_HUB", HUBS=["NODE_A", "NODE_B"])) == \
        {"NODE_A": 3, "NODE_B": 3, "NODE_C": 2, "NODE_D": 2}


def test_validation_refuses_a_hub_outside_the_group():
    assert not validate_group(config(TOPOLOGY="HUB_SPOKE", HUBS=["STRANGER"]), "MESH_GROUP")
    assert not validate_group(config(TOPOLOGY="DUAL_HUB", HUBS=["NODE_A"]), "MESH_GROUP")
    assert not validate_group(config(TOPOLOGY="STAR"), "MESH_GROUP")


@pytest.fixture
def state(tmp_path):
    cfg = config()
    cfg["SERVER_CLIENT"].append({"UID": "NODE_E", "IP_ADDRESS": "10.0.0.9", "MESH_GROUP_UID_LIST": []})
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {u: FakeClient() for u in NODES}, "dict_of_commands_for_network_clients": {},
            "dynamic_uids": set()}


def form(**over):
    return dict({"BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}, **over)


def declared(state, uid):
    return next(c for c in toml.load(state["config_file_path"])["SERVER_CLIENT"] if c["UID"] == uid)


def test_switching_to_hub_and_spoke_applies_live(state):
    result = ops.update(state, "GROUP1", form(TOPOLOGY="HUB_SPOKE", HUBS=["NODE_A"]), actor="x")
    g = next(g for g in toml.load(state["config_file_path"])["MESH_GROUP"] if g["UID"] == "GROUP1")
    assert g["TOPOLOGY"] == "HUB_SPOKE" and g["HUBS"] == ["NODE_A"]
    assert len(state["_dict_by_node_generated_config"]["NODE_B"]["CONNECTORS"]) == 1
    # Le hub garde exactement ses flux (vers B, C, D) : seuls les spokes, qui perdent les leurs entre eux, sont touchés
    assert result["affected_clients"] == ["NODE_B", "NODE_C", "NODE_D"]


def test_a_hub_that_is_not_yet_a_member_joins_the_group(state):
    ops.update(state, "GROUP1", form(TOPOLOGY="HUB_SPOKE", HUBS=["NODE_E"]), actor="x")
    assert "GROUP1" in declared(state, "NODE_E")["MESH_GROUP_UID_LIST"]
    assert len(state["_dict_by_node_generated_config"]["NODE_E"]["CONNECTORS"]) == 4


def test_topology_fields_are_validated(state):
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "GROUP1", form(TOPOLOGY="DUAL_HUB", HUBS=["NODE_A"]), actor="x")
    assert list(err.value.fields) == ["HUBS"]
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "GROUP1", form(TOPOLOGY="HUB_SPOKE", HUBS=["NOBODY"]), actor="x")
    assert list(err.value.fields) == ["HUBS"]


def test_back_to_mesh_removes_the_hubs(state):
    ops.update(state, "GROUP1", form(TOPOLOGY="HUB_SPOKE", HUBS=["NODE_A"]), actor="x")
    ops.update(state, "GROUP1", form(TOPOLOGY="MESH"), actor="x")
    g = next(g for g in toml.load(state["config_file_path"])["MESH_GROUP"] if g["UID"] == "GROUP1")
    assert "TOPOLOGY" not in g and "HUBS" not in g


def test_a_hub_cannot_leave_its_group(state):
    ops.update(state, "GROUP1", form(TOPOLOGY="HUB_SPOKE", HUBS=["NODE_A"]), actor="x")
    with pytest.raises(ops.OpError) as err:
        ops.update_client(state, "NODE_A", {"IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": []}, actor="x")
    assert "hub" in err.value.message.lower() and "GROUP1" in err.value.message


def test_listing_reports_topology_members_flows_and_bandwidth_per_role(state):
    ops.update(state, "GROUP1", form(TOPOLOGY="HUB_SPOKE", HUBS=["NODE_A"]), actor="x")
    g = ops.get_group(state, "GROUP1")
    assert g["TOPOLOGY"] == "HUB_SPOKE" and g["HUBS"] == ["NODE_A"]
    assert g["MEMBER_UIDS"] == list(NODES) and g["FLOWS"] == 6
    assert g["KBPS_OUT"] == {"hub": 300, "spoke": 100}


def test_duplicating_a_hub_group_makes_its_hubs_join_the_copy(state):
    ops.update(state, "GROUP1", form(TOPOLOGY="HUB_SPOKE", HUBS=["NODE_A"]), actor="x")
    result = ops.duplicate(state, "GROUP1", actor="x")
    assert result["uid"] == "GROUP1_COPY"
    assert "GROUP1_COPY" in declared(state, "NODE_A")["MESH_GROUP_UID_LIST"]
    assert ops.get_group(state, "GROUP1_COPY")["MEMBER_UIDS"] == ["NODE_A"]

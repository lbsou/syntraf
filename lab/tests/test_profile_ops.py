"""Profils iperf3 (IPERF3_PROFILE) éditables depuis la webui (lib/st_mesh_group_ops.py).

Tourne dans l'image du lab (dépendances de SYNTRAF), comme test_mesh_group_ops.py.
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


class FakeClient:
    def __init__(self, status):
        self.status = status


@pytest.fixture
def state(tmp_path):
    cfg = {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100"}, "GLOBAL": {},
           "IPERF3_PROFILE": [{"UID": "VOICE", "DSCP": "46", "PACKET_SIZE": "160", "BANDWIDTH": "64K"}],
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"},
                          {"UID": "GROUP2", "BANDWIDTH": "10K", "DSCP": "0", "PACKET_SIZE": "100", "INTERVAL": "1",
                           "IPERF3_PROFILE": "VOICE"}],
           "SERVER_CLIENT": [{"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                             {"UID": "NODE_B", "IP_ADDRESS": "10.0.0.2", "MESH_GROUP_UID_LIST": ["GROUP1", "GROUP2"]},
                             {"UID": "NODE_C", "IP_ADDRESS": "10.0.0.3", "MESH_GROUP_UID_LIST": ["GROUP2"]}]}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {u: FakeClient("CONNECTED") for u in ("NODE_A", "NODE_B", "NODE_C")},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def live_group(state, uid):
    return next(g for g in state["config"]["MESH_GROUP"] if g["UID"] == uid)


def test_profiles_are_listed_with_the_groups_using_them(state):
    [voice] = ops.list_profiles(state)
    assert voice["UID"] == "VOICE" and voice["USED_BY"] == ["GROUP2"]


def test_editing_a_profile_applies_it_live_to_its_groups_only(state):
    result = ops.update_profile(state, "VOICE", {"DSCP": "34", "PACKET_SIZE": "160", "BANDWIDTH": "64K"}, actor="x")
    assert live_group(state, "GROUP2")["DSCP"] == "34"
    assert live_group(state, "GROUP1")["DSCP"] == "0"
    assert result["affected_clients"] == ["NODE_B", "NODE_C"]
    assert result["reconnected_clients"] == ["NODE_B", "NODE_C"]


def test_assigning_a_profile_to_a_group_overrides_its_values(state):
    ops.update(state, "GROUP1", {"BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1",
                                 "IPERF3_PROFILE": "VOICE"}, actor="x")
    assert live_group(state, "GROUP1")["DSCP"] == "46"
    assert live_group(state, "GROUP1")["BANDWIDTH"] == "64K"


def test_unknown_profile_on_a_group_is_a_field_error(state):
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "GROUP1", {"BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1",
                                     "IPERF3_PROFILE": "NOPE1"}, actor="x")
    assert list(err.value.fields) == ["IPERF3_PROFILE"]


def test_profile_fields_are_validated_and_at_least_one_is_needed(state):
    with pytest.raises(ops.OpError) as err:
        ops.create_profile(state, {"UID": "BULK1", "DSCP": "99", "BANDWIDTH": "x"}, actor="x")
    assert set(err.value.fields) == {"DSCP", "BANDWIDTH"}
    with pytest.raises(ops.OpError) as err:
        ops.create_profile(state, {"UID": "EMPTY1"}, actor="x")
    assert err.value.status == 400


def test_a_profile_in_use_cannot_be_deleted(state):
    with pytest.raises(ops.OpError) as err:
        ops.delete_profile(state, "VOICE", actor="x")
    assert err.value.status == 409 and "GROUP2" in err.value.message
    ops.create_profile(state, {"UID": "BULK1", "BANDWIDTH": "1M"}, actor="x")
    ops.delete_profile(state, "BULK1", actor="x")
    assert [p["UID"] for p in ops.list_profiles(state)] == ["VOICE"]


def test_a_group_defined_only_by_its_profile_is_listed_with_the_profile_values(state):
    cfg = toml.load(state["config_file_path"])
    cfg["MESH_GROUP"][1] = {"UID": "GROUP2", "IPERF3_PROFILE": "VOICE"}
    cfg["IPERF3_PROFILE"][0]["INTERVAL"] = "1"
    Path(state["config_file_path"]).write_text(toml.dumps(cfg))
    g2 = next(g for g in ops.list_groups(state) if g["UID"] == "GROUP2")
    assert g2["EFFECTIVE"] == {"BANDWIDTH": "64K", "DSCP": "46", "PACKET_SIZE": "160", "INTERVAL": "1"}
    assert g2["BW_PER_NODE_KBPS"] == 64


def test_with_a_profile_the_group_values_are_optional(state):
    ops.update(state, "GROUP1", {"IPERF3_PROFILE": "VOICE", "BANDWIDTH": "", "DSCP": "", "PACKET_SIZE": "",
                                 "INTERVAL": "1"}, actor="x")
    g1 = next(g for g in toml.load(state["config_file_path"])["MESH_GROUP"] if g["UID"] == "GROUP1")
    assert g1 == {"UID": "GROUP1", "IPERF3_PROFILE": "VOICE", "INTERVAL": "1"}
    assert live_group(state, "GROUP1")["DSCP"] == "46"

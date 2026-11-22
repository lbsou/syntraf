"""Opérations de la webui sur les mesh groups (lib/st_mesh_group_ops.py) : validation, aperçu, écriture, audit,
application aux clients connectés, restauration d'une version.

Tourne dans l'image du lab (dépendances de SYNTRAF), comme test_config_generation.py.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib import st_config_store as store
    from lib import st_mesh_group_ops as ops
    from lib.st_conf_validation import validate_group, generate_client_config_mesh
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


class FakeClient:
    def __init__(self, status):
        self.status = status


def disk_config(**client_extra):
    return {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100"}, "GLOBAL": {},
            "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"},
                           {"UID": "SPARE", "BANDWIDTH": "10K", "DSCP": "0", "PACKET_SIZE": "100", "INTERVAL": "1"}],
            "SERVER_CLIENT": [dict({"UID": u, "IP_ADDRESS": ip, "MESH_GROUP_UID_LIST": ["GROUP1"]}, **client_extra)
                              for u, ip in (("NODE_A", "10.0.0.1"), ("NODE_B", "10.0.0.2"))]}


@pytest.fixture
def state(tmp_path):
    return make_state(tmp_path, disk_config())


def make_state(tmp_path, disk):
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(disk))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {"NODE_A": FakeClient("CONNECTED"), "NODE_B": FakeClient("DISCONNECTED")},
            "dict_of_commands_for_network_clients": {}}


def values(**over):
    return dict({"BANDWIDTH": "120K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}, **over)


def disk(state):
    return toml.load(state["config_file_path"])


def group(cfg, uid):
    return next(g for g in cfg["MESH_GROUP"] if g["UID"] == uid)


def test_update_writes_disk_recomputes_live_and_reconnects_connected_members(state):
    result = ops.update(state, "GROUP1", values(), actor="10.0.0.9")
    assert group(disk(state), "GROUP1")["BANDWIDTH"] == "120K"
    assert group(state["config"], "GROUP1")["PACKET_PACING"] == int(1_000_000 / int(120_000 / 8 / 218))
    assert state["dict_of_commands_for_network_clients"] == {"NODE_A": [{"ACTION": "RECONNECT_CLIENT"}]}
    assert result["affected_clients"] == ["NODE_A", "NODE_B"]
    assert result["reconnected_clients"] == ["NODE_A"]
    [entry] = store.audit_entries(state["config_file_path"])
    assert (entry["actor"], entry["action"]) == ("10.0.0.9", "UPDATE_MESH_GROUP")


def test_dry_run_changes_nothing_but_reports_the_diff_and_affected_clients(state):
    before = Path(state["config_file_path"]).read_text()
    generated_before = repr(state["_dict_by_node_generated_config"])
    result = ops.update(state, "GROUP1", values(), actor="x", dry_run=True)
    assert Path(state["config_file_path"]).read_text() == before
    assert repr(state["_dict_by_node_generated_config"]) == generated_before
    assert state["dict_of_commands_for_network_clients"] == {}
    assert '+BANDWIDTH = "120K"' in result["diff"]
    assert result["affected_clients"] == ["NODE_A", "NODE_B"]
    assert result["dry_run"] is True


def test_invalid_fields_are_reported_one_by_one(state):
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "GROUP1", values(BANDWIDTH="lots", DSCP="99"), actor="x")
    assert err.value.status == 400
    assert set(err.value.fields) == {"BANDWIDTH", "DSCP"}


def test_create_refuses_an_existing_name_and_update_an_unknown_one(state):
    with pytest.raises(ops.OpError) as err:
        ops.create(state, dict(values(), UID="GROUP1"), actor="x")
    assert err.value.status == 409
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "NOPE1", values(), actor="x")
    assert err.value.status == 404


def test_change_exceeding_max_bandwidth_is_refused_and_nothing_is_written(tmp_path):
    state = make_state(tmp_path, disk_config(MAX_BANDWIDTH="150K"))
    before = Path(state["config_file_path"]).read_text()
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "GROUP1", values(BANDWIDTH="200K"), actor="x")
    assert err.value.status == 409
    assert Path(state["config_file_path"]).read_text() == before
    assert group(state["config"], "GROUP1")["BANDWIDTH"] == "100K"


def test_disable_empties_the_members_config(state):
    ops.set_disabled(state, "GROUP1", True, actor="x")
    assert group(disk(state), "GROUP1")["DISABLED"] is True
    assert all(not c["LISTENERS"] and not c["CONNECTORS"] for c in state["_dict_by_node_generated_config"].values())
    ops.set_disabled(state, "GROUP1", False, actor="x")
    assert "DISABLED" not in group(disk(state), "GROUP1")


def test_delete_refuses_a_group_in_use_and_removes_an_unused_one(state):
    with pytest.raises(ops.OpError) as err:
        ops.delete(state, "GROUP1", actor="x")
    assert err.value.status == 409
    ops.delete(state, "SPARE", actor="x")
    assert [g["UID"] for g in disk(state)["MESH_GROUP"]] == ["GROUP1"]
    assert [g["UID"] for g in state["config"]["MESH_GROUP"]] == ["GROUP1"]


def test_duplicate_picks_a_free_name_and_affects_no_client(state):
    first = ops.duplicate(state, "GROUP1", actor="x")
    second = ops.duplicate(state, "GROUP1", actor="x")
    assert (first["uid"], second["uid"]) == ("GROUP1_COPY", "GROUP1_COPY1")
    assert first["affected_clients"] == []
    assert group(disk(state), "GROUP1_COPY")["BANDWIDTH"] == "100K"


def test_restore_brings_back_a_previous_version(state):
    ops.update(state, "GROUP1", values(), actor="x")
    original = store.versions(state["config_file_path"])[-1]["version"]
    result = ops.restore(state, original, actor="y")
    assert group(disk(state), "GROUP1")["BANDWIDTH"] == "100K"
    assert group(state["config"], "GROUP1")["BANDWIDTH"] == "100K"
    assert result["restart_required"] == []
    assert store.audit_entries(state["config_file_path"])[0]["action"] == "RESTORE_CONFIG"


def test_restore_flags_sections_that_need_a_restart(state):
    path = state["config_file_path"]
    store.save(path, dict(disk(state), GLOBAL={"LOGDIR": "/elsewhere"}), "x", "TEST", "global changed")
    original = store.versions(path)[-1]["version"]
    assert ops.restore(state, original, actor="y", dry_run=True)["restart_required"] == ["GLOBAL"]


def test_list_groups_counts_members_and_bandwidth_per_node(state):
    groups = {g["UID"]: g for g in ops.list_groups(state)}
    assert groups["GROUP1"]["MEMBERS"] == 2
    assert groups["GROUP1"]["BW_PER_NODE_KBPS"] == 100
    assert groups["SPARE"]["MEMBERS"] == 0


def test_keys_added_when_a_client_connects_do_not_count_as_a_change(state):
    # send_config ajoute CLIENT et GLOBAL à la config générée d'un client quand il se connecte.
    state["_dict_by_node_generated_config"]["NODE_A"]["CLIENT"] = {"IPERF3_USERNAME": "u"}
    state["_dict_by_node_generated_config"]["NODE_A"]["GLOBAL"] = {"IPERF3_TIME_SKEW_THRESHOLD": 5}
    assert ops.duplicate(state, "GROUP1", actor="x", dry_run=True)["affected_clients"] == []

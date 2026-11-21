"""Édition des clients (SERVER_CLIENT) et des bases de données (DATABASE) depuis la webui (lib/st_mesh_group_ops.py).

Tourne dans l'image du lab (dépendances de SYNTRAF), comme test_mesh_group_ops.py.
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


class FakeDb:
    def __init__(self, config, uid):
        self.DB_UID = uid
        self.server = next(d for d in config["DATABASE"] if d["DB_UID"] == uid)["DB_SERVER"]
        self.status = "ONLINE"


def disk_config():
    return {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100"}, "GLOBAL": {},
            "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"},
                           {"UID": "GROUP2", "BANDWIDTH": "10K", "DSCP": "0", "PACKET_SIZE": "100", "INTERVAL": "1"}],
            "SERVER_CLIENT": [{"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                              {"UID": "NODE_B", "IP_ADDRESS": "10.0.0.2", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                              {"UID": "NODE_D", "IP_ADDRESS": "0.0.0.0", "MESH_GROUP_UID_LIST": ["GROUP1"]}],
            "DATABASE": [{"DB_UID": "VM_ONE", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "10.0.0.10",
                          "DB_PORT": "8428", "DB_SERVER_USE_SSL": False, "DB_TOKEN": "s3cret"}]}


@pytest.fixture
def state(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(disk_config()))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    # NODE_D est dynamique et connecté : le serveur a rempli son IP en mémoire.
    next(c for c in live["SERVER_CLIENT"] if c["UID"] == "NODE_D")["IP_ADDRESS"] = "192.168.9.9"
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {"NODE_A": FakeClient("CONNECTED"), "NODE_B": FakeClient("CONNECTED"),
                                "NODE_D": FakeClient("CONNECTED")},
            "dict_of_commands_for_network_clients": {},
            "conn_db": [FakeDb(live, "VM_ONE")], "db_factory": FakeDb, "dynamic_uids": {"NODE_D"}}


def disk(state):
    return toml.load(state["config_file_path"])


def find(items, key, uid):
    return next((i for i in items if i[key] == uid), None)


def client_values(**over):
    return dict({"IP_ADDRESS": "10.0.0.3", "MESH_GROUP_UID_LIST": ["GROUP1"], "MAX_BANDWIDTH": "",
                 "MESH_LISTENERS_PORT_RANGE": ""}, **over)


# ------------------------------------------------------------------------------------------------------ clients

def test_new_client_is_written_and_its_peers_reconnect(state):
    result = ops.create_client(state, client_values(UID="NODE_C"), actor="x")
    assert find(disk(state)["SERVER_CLIENT"], "UID", "NODE_C")["IP_ADDRESS"] == "10.0.0.3"
    assert find(state["config"]["SERVER_CLIENT"], "UID", "NODE_C") is not None
    assert "NODE_C" in state["_dict_by_node_generated_config"]
    assert result["affected_clients"] == ["NODE_A", "NODE_B", "NODE_C", "NODE_D"]
    assert result["reconnected_clients"] == ["NODE_A", "NODE_B", "NODE_D"]


def test_client_fields_are_validated_one_by_one(state):
    with pytest.raises(ops.OpError) as err:
        ops.create_client(state, client_values(UID="x", IP_ADDRESS="not an ip!", MESH_GROUP_UID_LIST=["NOPE1"],
                                               MAX_BANDWIDTH="lots", MESH_LISTENERS_PORT_RANGE="9-2"), actor="x")
    assert err.value.status == 400
    assert set(err.value.fields) == {"UID", "IP_ADDRESS", "MESH_GROUP_UID_LIST", "MAX_BANDWIDTH",
                                     "MESH_LISTENERS_PORT_RANGE"}


def test_moving_a_client_to_another_group_affects_only_the_groups_members(state):
    result = ops.update_client(state, "NODE_B", client_values(IP_ADDRESS="10.0.0.2", MESH_GROUP_UID_LIST=["GROUP2"]),
                               actor="x")
    assert find(disk(state)["SERVER_CLIENT"], "UID", "NODE_B")["MESH_GROUP_UID_LIST"] == ["GROUP2"]
    assert result["affected_clients"] == ["NODE_A", "NODE_B", "NODE_D"]


def test_editing_keeps_the_ip_learned_for_a_connected_dynamic_client(state):
    ops.update_client(state, "NODE_A", client_values(IP_ADDRESS="10.0.0.1", MAX_BANDWIDTH="10M"), actor="x")
    assert find(state["config"]["SERVER_CLIENT"], "UID", "NODE_D")["IP_ADDRESS"] == "192.168.9.9"
    assert find(disk(state)["SERVER_CLIENT"], "UID", "NODE_D")["IP_ADDRESS"] == "0.0.0.0"
    assert find(disk(state)["SERVER_CLIENT"], "UID", "NODE_A")["MAX_BANDWIDTH"] == "10M"


def test_switching_a_client_to_dynamic_registers_it_and_reconnects_it(state):
    result = ops.update_client(state, "NODE_A", client_values(IP_ADDRESS="0.0.0.0"), actor="x")
    assert state["dynamic_uids"] == {"NODE_A", "NODE_D"}
    assert "NODE_A" in result["reconnected_clients"]


def test_editing_preserves_advanced_keys_not_in_the_form(state):
    cfg = disk(state)
    find(cfg["SERVER_CLIENT"], "UID", "NODE_A")["OVERRIDE_DST_NODE_IP"] = {"NODE_B": "10.9.9.2"}
    store.save(state["config_file_path"], cfg, "x", "TEST", "advanced key")
    ops.update_client(state, "NODE_A", client_values(IP_ADDRESS="10.0.0.1", MAX_BANDWIDTH="5M"), actor="x")
    assert find(disk(state)["SERVER_CLIENT"], "UID", "NODE_A")["OVERRIDE_DST_NODE_IP"] == {"NODE_B": "10.9.9.2"}


def test_deleted_client_is_told_to_reconnect_so_that_it_gets_rejected(state):
    result = ops.delete_client(state, "NODE_B", actor="x")
    assert find(disk(state)["SERVER_CLIENT"], "UID", "NODE_B") is None
    assert find(state["config"]["SERVER_CLIENT"], "UID", "NODE_B") is None
    assert "NODE_B" in result["reconnected_clients"]
    assert state["dict_of_commands_for_network_clients"]["NODE_B"] == [{"ACTION": "RECONNECT_CLIENT"}]


def test_client_name_conflicts(state):
    with pytest.raises(ops.OpError) as err:
        ops.create_client(state, client_values(UID="NODE_A"), actor="x")
    assert err.value.status == 409
    with pytest.raises(ops.OpError) as err:
        ops.update_client(state, "NOPE1", client_values(), actor="x")
    assert err.value.status == 404


def test_list_clients_reports_the_declaration(state):
    rows = {c["UID"]: c for c in ops.list_clients(state)}
    assert rows["NODE_D"]["IP_ADDRESS"] == "0.0.0.0" and rows["NODE_D"]["DYNAMIC"] is True
    assert rows["NODE_A"]["MESH_GROUP_UID_LIST"] == ["GROUP1"]


# ---------------------------------------------------------------------------------------------------- databases

def db_values(**over):
    return dict({"DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "10.0.0.11", "DB_PORT": "8428",
                 "DB_SERVER_USE_SSL": False, "DB_TOKEN": ""}, **over)


def test_listing_databases_never_returns_the_token(state):
    [db] = ops.list_databases(state)
    assert "DB_TOKEN" not in db and db["DB_TOKEN_SET"] is True


def test_editing_a_database_keeps_an_unchanged_token_and_recreates_its_connection(state):
    old = state["conn_db"][0]
    result = ops.update_database(state, "VM_ONE", db_values(), actor="x")
    assert find(disk(state)["DATABASE"], "DB_UID", "VM_ONE")["DB_TOKEN"] == "s3cret"
    assert find(disk(state)["DATABASE"], "DB_UID", "VM_ONE")["DB_SERVER"] == "10.0.0.11"
    assert state["conn_db"][0] is not old and state["conn_db"][0].server == "10.0.0.11"
    assert result["recreated_databases"] == ["VM_ONE"]
    assert result["affected_clients"] == []


def test_database_fields_are_validated(state):
    with pytest.raises(ops.OpError) as err:
        ops.create_database(state, db_values(DB_UID="DB2_X", DB_ENGINE="Oracle", DB_SERVER="", DB_PORT="99999"),
                            actor="x")
    assert set(err.value.fields) == {"DB_ENGINE", "DB_SERVER", "DB_PORT"}
    with pytest.raises(ops.OpError) as err:
        ops.create_database(state, db_values(DB_UID="INFLUX1", DB_ENGINE="InfluxDB2"), actor="x")
    assert set(err.value.fields) == {"DB_TOKEN", "DB_ORG", "DB_BUCKET"}


def test_new_and_deleted_databases_update_the_connections(state):
    ops.create_database(state, db_values(DB_UID="VM_TWO"), actor="x")
    assert [d.DB_UID for d in state["conn_db"]] == ["VM_ONE", "VM_TWO"]
    unchanged = state["conn_db"][0]
    ops.delete_database(state, "VM_TWO", actor="x")
    assert [d.DB_UID for d in state["conn_db"]] == ["VM_ONE"]
    assert state["conn_db"][0] is unchanged


def test_database_dry_run_touches_nothing(state):
    old = state["conn_db"][0]
    result = ops.update_database(state, "VM_ONE", db_values(), actor="x", dry_run=True)
    assert state["conn_db"][0] is old
    assert result["recreated_databases"] == ["VM_ONE"]
    assert "s3cret" not in result["diff"]


def test_test_database_reports_the_status_without_saving(state):
    before = Path(state["config_file_path"]).read_text()
    assert ops.test_database(state, db_values(DB_UID="VM_ONE"))["status"] == "ONLINE"
    assert Path(state["config_file_path"]).read_text() == before


def test_restore_applies_clients_and_databases_live(state):
    ops.update_database(state, "VM_ONE", db_values(), actor="x")
    ops.delete_client(state, "NODE_B", actor="x")
    original = store.versions(state["config_file_path"])[-1]["version"]
    result = ops.restore(state, original, actor="y")
    assert result["restart_required"] is False
    assert find(state["config"]["SERVER_CLIENT"], "UID", "NODE_B") is not None
    assert state["conn_db"][0].server == "10.0.0.10"

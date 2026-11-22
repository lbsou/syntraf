"""Renommer un client (lib/st_mesh_group_ops.rename_client) : configuration, ancien nom reconnu, nouveau nom remis
au client, historique déplacé dans VictoriaMetrics. Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib import st_mesh_group_ops as ops
    from lib.st_conf_validation import generate_client_config_mesh, validate_group
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


class FakeAdmin:
    calls = []

    def __init__(self, db):
        self.db = db

    def rename_node(self, old, new, since_s=None):
        FakeAdmin.calls.append((self.db["DB_UID"], old, new, since_s))
        return {"points": 42, "series": 3}


@pytest.fixture
def state(tmp_path):
    cfg = {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100", "TOKEN": {"site": "shared"}}, "GLOBAL": {},
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1",
                           "TOPOLOGY": "HUB_SPOKE", "HUBS": ["NODE_A"]}],
           "SERVER_CLIENT": [{"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                             {"UID": "NODE_B", "IP_ADDRESS": "10.0.0.2", "MESH_GROUP_UID_LIST": ["GROUP1"],
                              "OVERRIDE_DST_NODE_IP": {"NODE_A": "192.0.2.1"}}],
           "DATABASE": [{"DB_UID": "VM", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "vm", "DB_PORT": "8428"}]}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    FakeAdmin.calls = []
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples, "dict_of_clients": {},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set(),
            "vm_admin_factory": FakeAdmin, "history_rename_delay_s": None, "history_sweep_delay_s": 0}  # None : synchrone (tests)


def disk(state):
    return toml.load(state["config_file_path"])


def audit(state):
    path = Path(state["config_file_path"] + ".audit.jsonl")
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_rename_updates_every_reference(state):
    result = ops.rename_client(state, "NODE_A", {"NEW_UID": "STARLINK"}, actor="admin")
    cfg = disk(state)
    a = next(c for c in cfg["SERVER_CLIENT"] if c["UID"] == "STARLINK")
    assert a["PREVIOUS_UIDS"] == ["NODE_A"]
    assert cfg["MESH_GROUP"][0]["HUBS"] == ["STARLINK"]
    assert cfg["SERVER_CLIENT"][1]["OVERRIDE_DST_NODE_IP"] == {"STARLINK": "192.0.2.1"}
    assert result["uid"] == "STARLINK"
    assert {"ACTION": "SET_UID", "UID": "STARLINK"} in state["dict_of_commands_for_network_clients"]["NODE_A"]
    assert "STARLINK" in state["_dict_by_node_generated_config"]


def test_rename_moves_the_history_and_audits_it(state):
    result = ops.rename_client(state, "NODE_A", {"NEW_UID": "STARLINK"}, actor="admin")
    # une passe complète, puis une seconde sur les deux dernières heures (mesures arrivées en retard)
    assert FakeAdmin.calls == [("VM", "NODE_A", "STARLINK", None), ("VM", "NODE_A", "STARLINK", 7200)]
    assert result["history"] == ["VM"]
    actions = [e["action"] for e in audit(state)]
    assert "RENAME_CLIENT" in actions and "RENAME_HISTORY" in actions


def test_rename_back_drops_the_name_from_the_previous_ones(state):
    ops.rename_client(state, "NODE_A", {"NEW_UID": "STARLINK"}, actor="admin")
    ops.rename_client(state, "STARLINK", {"NEW_UID": "NODE_A"}, actor="admin")
    a = next(c for c in disk(state)["SERVER_CLIENT"] if c["UID"] == "NODE_A")
    assert a["PREVIOUS_UIDS"] == ["STARLINK"]


@pytest.mark.parametrize("new, status", [("bad name!", 400), ("NODE_B", 409), ("NODE_A", 400)])
def test_invalid_renames_are_refused(state, new, status):
    with pytest.raises(ops.OpError) as err:
        ops.rename_client(state, "NODE_A", {"NEW_UID": new}, actor="admin")
    assert err.value.status == status and "NEW_UID" in err.value.fields


def test_unknown_client_cannot_be_renamed(state):
    with pytest.raises(ops.OpError) as err:
        ops.rename_client(state, "NOPE", {"NEW_UID": "X_NODE"}, actor="admin")
    assert err.value.status == 404


def test_dry_run_changes_nothing(state):
    ops.rename_client(state, "NODE_A", {"NEW_UID": "STARLINK"}, actor="admin", dry_run=True)
    assert [c["UID"] for c in disk(state)["SERVER_CLIENT"]] == ["NODE_A", "NODE_B"]
    assert FakeAdmin.calls == [] and state["dict_of_commands_for_network_clients"] == {}


def test_a_name_still_known_as_a_previous_one_cannot_be_given_to_another_client(state):
    ops.rename_client(state, "NODE_A", {"NEW_UID": "STARLINK"}, actor="admin")
    with pytest.raises(ops.OpError) as err:
        ops.rename_client(state, "NODE_B", {"NEW_UID": "NODE_A"}, actor="admin")
    assert err.value.status == 409


# ---------------------------------------------------------------------------------- côté client

def test_client_keeps_the_name_given_by_the_server(tmp_path):
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_mesh
    cfg = {"CLIENT": {"CLIENT_UID": "NODE_A", "_UID_FILE": str(tmp_path / "syntraf_client_uid")}}
    assert st_mesh.client_command_set_uid(cfg, {"PAYLOAD": {"UID": "STARLINK"}}) is True
    assert cfg["CLIENT"]["CLIENT_UID"] == "STARLINK"
    restarted = {"CLIENT": {"CLIENT_UID": "NODE_A", "_UID_FILE": str(tmp_path / "syntraf_client_uid")}}
    st_mesh.client_apply_uid_file(restarted)  # au redémarrage : le nom remis par le serveur l'emporte
    assert restarted["CLIENT"]["CLIENT_UID"] == "STARLINK"


def test_client_refuses_an_invalid_name(tmp_path):
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_mesh
    cfg = {"CLIENT": {"CLIENT_UID": "NODE_A", "_UID_FILE": str(tmp_path / "syntraf_client_uid")}}
    assert st_mesh.client_command_set_uid(cfg, {"PAYLOAD": {"UID": "../../etc"}}) is False
    assert cfg["CLIENT"]["CLIENT_UID"] == "NODE_A" and not (tmp_path / "syntraf_client_uid").exists()


def test_the_connection_state_follows_the_rename(state):
    class Obj:
        client_uid, status, public_key_sha256, public_key = "NODE_A", "CONNECTED", None, None
    state["dict_of_clients"]["NODE_A"] = Obj()
    ops.rename_client(state, "NODE_A", {"NEW_UID": "STARLINK"}, actor="admin")
    assert "NODE_A" not in state["dict_of_clients"] and state["dict_of_clients"]["STARLINK"].client_uid == "STARLINK"

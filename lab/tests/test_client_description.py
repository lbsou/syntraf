"""Description d'un client (DESCRIPTION) : documentation libre pour l'admin, sans effet sur les mesures.
Tourne dans l'image du lab (dépendances de SYNTRAF)."""
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
        self.status, self.release_id, self.update_status, self.update_failed = status, "0.45", None, None


@pytest.fixture
def state(tmp_path):
    cfg = {"SERVER": {"BIND_ADDRESS": "0.0.0.0", "SERVER_PORT": "6531", "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                      "TOKEN": {"t": "secret-token"}},
           "GLOBAL": {},
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}],
           "SERVER_CLIENT": [{"UID": "SITE_A", "IP_ADDRESS": "10.0.0.4", "MESH_GROUP_UID_LIST": ["GROUP1"]}]}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {"SITE_A": FakeClient("CONNECTED")},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def form(**over):
    return dict({"IP_ADDRESS": "10.0.0.4", "MESH_GROUP_UID_LIST": ["GROUP1"]}, **over)


def disk(state):
    return toml.load(state["config_file_path"])["SERVER_CLIENT"][0]


def test_description_is_saved_listed_and_does_not_reconnect(state):
    text = "Bureau de Québec\r\nRouteur Bell, contact : NOC 🛰️"
    preview = ops.update_client(state, "SITE_A", form(DESCRIPTION=text), actor="admin", dry_run=True)
    assert preview["affected_clients"] == []
    ops.update_client(state, "SITE_A", form(DESCRIPTION=text), actor="admin")
    assert disk(state)["DESCRIPTION"] == text
    assert ops.list_clients(state)[0]["DESCRIPTION"] == text


def test_description_is_stripped_and_500_chars_is_the_limit(state):
    ops.update_client(state, "SITE_A", form(DESCRIPTION="  " + "é" * 500 + "  "), actor="admin")
    assert disk(state)["DESCRIPTION"] == "é" * 500
    with pytest.raises(ops.OpError) as err:
        ops.update_client(state, "SITE_A", form(DESCRIPTION="x" * 501), actor="admin")
    assert err.value.status == 400 and "DESCRIPTION" in err.value.fields
    assert disk(state)["DESCRIPTION"] == "é" * 500


def test_empty_description_removes_the_key(state):
    ops.update_client(state, "SITE_A", form(DESCRIPTION="note"), actor="admin")
    ops.update_client(state, "SITE_A", form(DESCRIPTION="   "), actor="admin")
    assert "DESCRIPTION" not in disk(state)


def test_a_form_without_description_keeps_it(state):
    ops.update_client(state, "SITE_A", form(DESCRIPTION="note"), actor="admin")
    ops.update_client(state, "SITE_A", form(), actor="admin")
    assert disk(state)["DESCRIPTION"] == "note"


def test_a_new_client_can_have_a_description(state):
    ops.create_client(state, form(UID="SITE_B", IP_ADDRESS="10.0.0.5", DESCRIPTION="neuf"), actor="admin")
    assert toml.load(state["config_file_path"])["SERVER_CLIENT"][1]["DESCRIPTION"] == "neuf"

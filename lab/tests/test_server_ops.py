"""Section SERVER et jetons éditables depuis la webui (lib/st_mesh_group_ops.py).

Tourne dans l'image du lab (dépendances de SYNTRAF).
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


@pytest.fixture
def state(tmp_path):
    cfg = {"SERVER": {"BIND_ADDRESS": "0.0.0.0", "SERVER_PORT": "6531", "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                      "TOKEN": {"site_a": "secret-a"}},
           "GLOBAL": {},
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}],
           "SERVER_CLIENT": [{"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                             {"UID": "NODE_B", "IP_ADDRESS": "10.0.0.2", "MESH_GROUP_UID_LIST": ["GROUP1"]}]}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    live["SERVER"]["RSA_KEY_LISTENERS"] = b"runtime only"
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {"NODE_A": FakeClient("CONNECTED"), "NODE_B": FakeClient("CONNECTED")},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def server_values(**over):
    return dict({"BIND_ADDRESS": "0.0.0.0", "SERVER_PORT": "6531", "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                 "SERVER_X509_CERTIFICATE": "", "SERVER_X509_PRIVATE_KEY": ""}, **over)


def disk(state):
    return toml.load(state["config_file_path"])


def test_server_settings_never_include_the_tokens(state):
    server = ops.get_server(state)
    assert server["SERVER_PORT"] == "6531" and "TOKEN" not in server
    assert server["RUNNING"]["SERVER_PORT"] == "6531"


def test_port_range_change_applies_live_and_reconnects_clients(state):
    result = ops.update_server(state, server_values(MESH_LISTENERS_PORT_RANGE="20000-20100"), actor="x")
    assert state["config"]["SERVER"]["MESH_LISTENERS_PORT_RANGE"] == "20000-20100"
    assert result["restart_required"] == []
    assert result["reconnected_clients"] == ["NODE_A", "NODE_B"]
    ports = [int(l["PORT"]) for c in state["_dict_by_node_generated_config"].values()
             for l in (c.get("LISTENERS") or {}).values()]
    assert ports and all(20000 <= p <= 20100 for p in ports)


def test_listening_port_change_is_written_but_needs_a_restart(state):
    result = ops.update_server(state, server_values(SERVER_PORT="7000"), actor="x")
    assert disk(state)["SERVER"]["SERVER_PORT"] == "7000"
    assert state["config"]["SERVER"]["SERVER_PORT"] == "6531"
    assert result["restart_required"] == ["SERVER.SERVER_PORT"]
    assert ops.get_server(state)["RUNNING"]["SERVER_PORT"] == "6531"


def test_server_fields_are_validated(state):
    with pytest.raises(ops.OpError) as err:
        ops.update_server(state, server_values(BIND_ADDRESS="nope!", SERVER_PORT="99999",
                                               MESH_LISTENERS_PORT_RANGE="9-2",
                                               SERVER_X509_CERTIFICATE="/does/not/exist.pem"), actor="x")
    assert set(err.value.fields) == {"BIND_ADDRESS", "SERVER_PORT", "MESH_LISTENERS_PORT_RANGE",
                                     "SERVER_X509_CERTIFICATE", "SERVER_X509_PRIVATE_KEY"}


def test_runtime_keys_are_never_written_to_disk(state):
    ops.update_server(state, server_values(SERVER_PORT="7000"), actor="x")
    assert "RSA_KEY_LISTENERS" not in disk(state)["SERVER"]
    assert state["config"]["SERVER"]["RSA_KEY_LISTENERS"] == b"runtime only"


def test_a_new_token_is_shown_once_and_accepted_live(state):
    result = ops.create_token(state, {"NAME": "site_b"}, actor="x")
    assert len(result["token"]) >= 24
    assert disk(state)["SERVER"]["TOKEN"]["site_b"] == result["token"]
    assert state["config"]["SERVER"]["TOKEN"]["site_b"] == result["token"]
    assert [t["NAME"] for t in ops.list_tokens(state)] == ["site_a", "site_b"]
    assert all("token" not in t and "VALUE" not in t for t in ops.list_tokens(state))
    assert "secret-a" not in store.audit_entries(state["config_file_path"])[0]["diff"]


def test_revoking_a_token_applies_live_but_the_last_one_stays(state):
    ops.create_token(state, {"NAME": "site_b"}, actor="x")
    ops.delete_token(state, "site_a", actor="x")
    assert "site_a" not in state["config"]["SERVER"]["TOKEN"]
    with pytest.raises(ops.OpError) as err:
        ops.delete_token(state, "site_b", actor="x")
    assert err.value.status == 409


def test_revealing_a_token_is_audited(state):
    assert ops.reveal_token(state, "site_a", actor="10.0.0.9") == "secret-a"
    entry = store.audit_entries(state["config_file_path"])[0]
    assert (entry["action"], entry["actor"]) == ("REVEAL_TOKEN", "10.0.0.9")


def test_token_names_are_validated(state):
    with pytest.raises(ops.OpError) as err:
        ops.create_token(state, {"NAME": "bad name!"}, actor="x")
    assert list(err.value.fields) == ["NAME"]
    with pytest.raises(ops.OpError) as err:
        ops.create_token(state, {"NAME": "site_a"}, actor="x")
    assert err.value.status == 409


def test_restore_reports_restart_only_for_settings_that_need_it(state):
    ops.create_token(state, {"NAME": "site_b"}, actor="x")
    original = store.versions(state["config_file_path"])[-1]["version"]
    result = ops.restore(state, original, actor="y")
    assert result["restart_required"] == []
    assert "site_b" not in state["config"]["SERVER"]["TOKEN"]
    ops.update_server(state, server_values(SERVER_PORT="7000"), actor="x")
    original = store.versions(state["config_file_path"])[-1]["version"]
    assert ops.restore(state, original, actor="y", dry_run=True)["restart_required"] == ["SERVER.SERVER_PORT"]


# ------------------------------------------------------------------------------------------- journalisation

def logging_values(**over):
    return dict({"LOG_LEVEL": "INFO", "LOG_FORWARD_LEVEL": "INFO", "LOG_MAX_SIZE_PER_FILE_MB": "10",
                 "LOG_FILE_TO_KEEP": "5", "LOG_RETENTION_DAYS": ""}, **over)


def test_logging_settings_have_defaults(state):
    settings = ops.get_logging(state)
    assert settings["LOG_FORWARD_LEVEL"] == "INFO" and settings["LOG_RETENTION_DAYS"] == ""


def test_forward_level_change_applies_live_and_reconnects_clients(state):
    result = ops.update_logging(state, logging_values(LOG_FORWARD_LEVEL="WARNING", LOG_RETENTION_DAYS="30"), actor="x")
    assert state["config"]["GLOBAL"]["LOG_FORWARD_LEVEL"] == "WARNING"
    assert state["config"]["GLOBAL"]["LOG_RETENTION_DAYS"] == "30"
    assert result["restart_required"] == [] and result["reconnected_clients"] == ["NODE_A", "NODE_B"]


def test_server_log_file_size_needs_a_restart(state):
    result = ops.update_logging(state, logging_values(LOG_MAX_SIZE_PER_FILE_MB="50"), actor="x")
    assert result["restart_required"] == ["GLOBAL.LOG_MAX_SIZE_PER_FILE_MB"]
    assert result["reconnected_clients"] == []


def test_logging_settings_are_validated(state):
    with pytest.raises(ops.OpError) as err:
        ops.update_logging(state, logging_values(LOG_LEVEL="LOUD", LOG_FORWARD_LEVEL="x", LOG_MAX_SIZE_PER_FILE_MB="0",
                                                 LOG_FILE_TO_KEEP="abc", LOG_RETENTION_DAYS="-3"), actor="x")
    assert set(err.value.fields) == {"LOG_LEVEL", "LOG_FORWARD_LEVEL", "LOG_MAX_SIZE_PER_FILE_MB", "LOG_FILE_TO_KEEP",
                                     "LOG_RETENTION_DAYS"}


# ------------------------------------------------------------------------------------------- redémarrage

def test_restart_asks_the_supervisor_and_is_audited(state, tmp_path, monkeypatch):
    from lib import st_updater
    from lib.st_global import DefaultValues
    monkeypatch.setattr(DefaultValues, "SYNTRAF_DATA_DIR", tmp_path)
    monkeypatch.setenv(st_updater.ENV_CHILD, "1")
    ops.restart_server(state, actor="10.0.0.9")
    assert st_updater.read_state(str(tmp_path))["restart"] is True
    entry = store.audit_entries(state["config_file_path"])[0]
    assert (entry["action"], entry["actor"]) == ("RESTART_SERVER", "10.0.0.9")


def test_restart_is_refused_clearly_without_supervisor(state, monkeypatch):
    from lib import st_updater
    monkeypatch.delenv(st_updater.ENV_CHILD, raising=False)
    with pytest.raises(ops.OpError) as err:
        ops.restart_server(state, actor="x")
    assert err.value.status == 409 and "service" in err.value.message

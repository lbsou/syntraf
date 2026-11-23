"""Groupes de déploiement des clients (DEPLOYMENT_GROUP) : mises à jour par étapes (pilote, vagues).
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

RELEASE = {"id": "0.45+new", "version": "0.45", "sha256": "ab" * 32, "size": 1000, "has_wheelhouse": False}


class FakeClient:
    def __init__(self, status, release="0.45+old"):
        self.status, self.release_id, self.update_status, self.update_failed = status, release, None, None


@pytest.fixture
def state(tmp_path, monkeypatch):
    cfg = {"SERVER": {"BIND_ADDRESS": "0.0.0.0", "SERVER_PORT": "6531", "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                      "TOKEN": {"t": "secret-token"}},
           "GLOBAL": {},
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}],
           "SERVER_CLIENT": [{"UID": "PILOT_1", "IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["GROUP1"],
                              "DEPLOYMENT_GROUP": "pilot"},
                             {"UID": "WAVE_1", "IP_ADDRESS": "10.0.0.2", "MESH_GROUP_UID_LIST": ["GROUP1"],
                              "DEPLOYMENT_GROUP": "wave-1"},
                             {"UID": "WAVE_2", "IP_ADDRESS": "10.0.0.3", "MESH_GROUP_UID_LIST": ["GROUP1"],
                              "DEPLOYMENT_GROUP": "wave-1"},
                             {"UID": "LOOSE", "IP_ADDRESS": "10.0.0.4", "MESH_GROUP_UID_LIST": ["GROUP1"]}]}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    monkeypatch.setattr(ops, "builtin_release", lambda: dict(RELEASE))
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {"PILOT_1": FakeClient("CONNECTED"), "WAVE_1": FakeClient("CONNECTED"),
                                "WAVE_2": FakeClient("CONNECTED", release="0.45+new"),
                                "LOOSE": FakeClient("CONNECTED")},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def form(**over):
    return dict({"IP_ADDRESS": "10.0.0.4", "MESH_GROUP_UID_LIST": ["GROUP1"]}, **over)


def test_the_group_is_listed_and_editable_without_restarting_measurements(state):
    assert {c["UID"]: c.get("DEPLOYMENT_GROUP", "") for c in ops.list_clients(state)}["PILOT_1"] == "pilot"
    preview = ops.update_client(state, "LOOSE", form(DEPLOYMENT_GROUP="wave-2"), actor="admin", dry_run=True)
    assert preview["affected_clients"] == []
    ops.update_client(state, "LOOSE", form(DEPLOYMENT_GROUP="wave-2"), actor="admin")
    assert toml.load(state["config_file_path"])["SERVER_CLIENT"][3]["DEPLOYMENT_GROUP"] == "wave-2"
    ops.update_client(state, "LOOSE", form(DEPLOYMENT_GROUP=""), actor="admin")
    assert "DEPLOYMENT_GROUP" not in toml.load(state["config_file_path"])["SERVER_CLIENT"][3]


def test_an_older_form_without_the_group_keeps_it(state):
    ops.update_client(state, "PILOT_1", form(IP_ADDRESS="10.0.0.1"), actor="admin")
    assert toml.load(state["config_file_path"])["SERVER_CLIENT"][0]["DEPLOYMENT_GROUP"] == "pilot"


def test_an_invalid_group_name_is_a_field_error(state):
    with pytest.raises(ops.OpError) as err:
        ops.update_client(state, "LOOSE", form(DEPLOYMENT_GROUP="bad group!"), actor="admin")
    assert err.value.status == 400 and "DEPLOYMENT_GROUP" in err.value.fields


def test_the_updates_overview_shows_each_group(state):
    view = ops.updates_overview(state)
    assert {r["uid"]: r["group"] for r in view["clients"]} == {"PILOT_1": "pilot", "WAVE_1": "wave-1",
                                                                "WAVE_2": "wave-1", "LOOSE": ""}
    assert view["groups"] == [{"group": "pilot", "clients": 1, "up_to_date": 0},
                              {"group": "wave-1", "clients": 2, "up_to_date": 1},
                              {"group": "", "clients": 1, "up_to_date": 0}]


def test_a_group_can_be_updated_at_once(state):
    r = ops.request_updates(state, [], actor="admin", groups=["wave-1"])
    assert r["queued"] == ["WAVE_1"] and r["skipped"] == {"WAVE_2": "up to date"}
    assert list(state["dict_of_commands_for_network_clients"]) == ["WAVE_1"]


def test_an_unknown_group_is_refused(state):
    with pytest.raises(ops.OpError) as err:
        ops.request_updates(state, [], actor="admin", groups=["nope"])
    assert err.value.status == 400


def test_the_iperf3_connect_timeout_is_a_global_setting_sent_to_clients(state):
    preview = ops.update_global(state, {"IPERF3_CONNECT_TIMEOUT": "8"}, actor="admin", dry_run=True)
    assert set(preview["affected_clients"]) == {"PILOT_1", "WAVE_1", "WAVE_2", "LOOSE"}
    ops.update_global(state, {"IPERF3_CONNECT_TIMEOUT": "8"}, actor="admin")
    assert toml.load(state["config_file_path"])["GLOBAL"]["IPERF3_CONNECT_TIMEOUT"] == "8"
    assert ops.get_global(state)["IPERF3_CONNECT_TIMEOUT"] == "8"
    with pytest.raises(ops.OpError) as err:
        ops.update_global(state, {"IPERF3_CONNECT_TIMEOUT": "0"}, actor="admin")
    assert "IPERF3_CONNECT_TIMEOUT" in err.value.fields


# ---------------------------------------------------------------------------------- oublier un client

def test_a_deleted_client_disappears_from_the_server_memory_when_offline(state):
    state["dict_of_clients"]["LOOSE"].status = "DISCONNECTED"
    ops.delete_client(state, "LOOSE", actor="admin")
    assert "LOOSE" not in state["dict_of_clients"]


def test_a_client_no_longer_declared_can_be_forgotten(state):
    from lib.st_enrollment import Enrollment
    e = Enrollment(state["config_file_path"] + ".pending.json")
    e.record("GHOST", "10.0.0.9", "key", "0.45")
    e.reject("GHOST", "admin")
    state["dict_of_clients"]["GHOST"] = FakeClient("DISCONNECTED")
    ops.forget_client(state, "GHOST", actor="admin")
    assert "GHOST" not in state["dict_of_clients"] and not e.is_rejected("GHOST")
    with pytest.raises(ops.OpError) as err:
        ops.forget_client(state, "GHOST", actor="admin")
    assert err.value.status == 404


def test_a_declared_client_is_deleted_not_forgotten(state):
    with pytest.raises(ops.OpError) as err:
        ops.forget_client(state, "LOOSE", actor="admin")
    assert err.value.status == 409


def test_a_profile_can_name_its_voice_codec_without_restarting_measurements(state):
    ops.create_profile(state, {"UID": "VOICE_PROF", "BANDWIDTH": "87.2K", "PACKET_SIZE": "218", "CODEC": "g729"},
                       actor="admin")
    assert [p for p in ops.list_profiles(state) if p["UID"] == "VOICE_PROF"][0]["CODEC"] == "G729"
    with pytest.raises(ops.OpError) as err:
        ops.create_profile(state, {"UID": "BAD_PROF", "BANDWIDTH": "1M", "CODEC": "MP3"}, actor="admin")
    assert "CODEC" in err.value.fields


def test_latency_measurement_is_a_global_setting_sent_to_clients(state):
    preview = ops.update_global(state, {"LATENCY_PORT": "8700"}, actor="admin", dry_run=True)
    assert set(preview["affected_clients"]) == {"PILOT_1", "WAVE_1", "WAVE_2", "LOOSE"}
    ops.update_global(state, {"LATENCY_PORT": "8700", "LATENCY": False}, actor="admin")
    g = toml.load(state["config_file_path"])["GLOBAL"]
    assert g["LATENCY_PORT"] == "8700" and g["LATENCY"] is False
    with pytest.raises(ops.OpError) as err:
        ops.update_global(state, {"LATENCY_PORT": "99999"}, actor="admin")
    assert "LATENCY_PORT" in err.value.fields


def test_unticking_a_global_switch_really_turns_it_off(state):
    ops.update_global(state, {"IPERF3_AUTH": False}, actor="admin")
    assert toml.load(state["config_file_path"])["GLOBAL"]["IPERF3_AUTH"] is False


def test_the_live_map_shows_declared_probes_and_expected_links(state, monkeypatch):
    from lib import st_live_map
    monkeypatch.setattr(st_live_map, "read_metrics", lambda vm: {"loss": {}, "jitter": {}, "mos": {}, "rtt": {}})
    m = ops.live_topology(state)
    assert {n["id"] for n in m["nodes"]} == {"PILOT_1", "WAVE_1", "WAVE_2", "LOOSE"}
    assert len(m["links"]) == 6 and m["mesh_groups"] == ["GROUP1"] and m["metrics_available"] is False
    assert all(l["grade"]["loss"] == "nodata" for l in m["links"])


def test_the_live_map_names_the_hubs_for_its_layout(state, monkeypatch):
    from lib import st_live_map
    monkeypatch.setattr(st_live_map, "read_metrics", lambda vm: {"loss": {}, "jitter": {}, "mos": {}, "rtt": {}})
    assert ops.live_topology(state)["hubs"] == []

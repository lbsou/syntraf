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


# ------------------------------------------------------------------------------------------- tests TCP

TCP = {"UID": "WAN_TCP", "MESH_GROUP": "GROUP1", "EVERY": "1h", "DURATION": "5", "DIRECTION": "upload",
       "PARALLEL": "2", "MODE": "fixed", "ENABLED": True}


def test_tcp_tests_can_be_created_listed_and_deleted_without_restarting_measurements(state):
    preview = ops.create_tcp_test(state, TCP, actor="admin", dry_run=True)
    assert preview["affected_clients"] == [] and preview["restart_required"] == []  # relu à chaque passage
    ops.create_tcp_test(state, TCP, actor="admin")
    assert [t["UID"] for t in ops.list_tcp_tests(state)] == ["WAN_TCP"]
    assert toml.load(state["config_file_path"])["TCP_TEST"][0]["PARALLEL"] == "2"
    ops.update_tcp_test(state, "WAN_TCP", dict(TCP, PARALLEL="8"), actor="admin")
    assert ops.list_tcp_tests(state)[0]["PARALLEL"] == "8"
    with pytest.raises(ops.OpError) as err:
        ops.create_tcp_test(state, dict(TCP, UID="BAD_TCP", EVERY="5s"), actor="admin")
    assert "EVERY" in err.value.fields
    ops.delete_tcp_test(state, "WAN_TCP", actor="admin")
    assert ops.list_tcp_tests(state) == []


def test_the_server_turns_a_due_tcp_test_into_commands_for_both_probes(state, monkeypatch):
    from lib import st_tcp_tests as tt
    monkeypatch.setattr(tt, "SCHEDULER", tt.Scheduler(start_delay_s=10))
    ops.create_tcp_test(state, TCP, actor="admin")
    ops.run_tcp_test_now(state, "WAN_TCP", actor="admin")
    jobs = ops.tcp_tests_tick(state, now=1000.0)
    assert len(jobs) == 1
    cmds = state["dict_of_commands_for_network_clients"]
    roles = sorted(c["ROLE"] for u in cmds for c in cmds[u] if c["ACTION"] == "TCP_TEST")
    assert roles == ["client", "server"]


def test_auto_mode_uses_the_measured_round_trip_and_declared_capacity(state, monkeypatch):
    from lib import st_tcp_tests as tt, st_quality
    monkeypatch.setattr(tt, "SCHEDULER", tt.Scheduler(start_delay_s=10))
    monkeypatch.setattr(st_quality, "latest_rtt", lambda tags, now=None: 40.0)
    ops.create_tcp_test(state, dict(TCP, MODE="auto", BANDWIDTH="100M"), actor="admin")
    ops.run_tcp_test_now(state, "WAN_TCP", actor="admin")
    ops.tcp_tests_tick(state, now=1000.0)
    client = [c for u in state["dict_of_commands_for_network_clients"].values() for c in u if c.get("ROLE") == "client"][0]
    assert client["TEST"]["WINDOW"] == "950000" and client["TEST"]["BANDWIDTH"] == "95M"


def test_the_live_map_replays_a_past_instant_from_victoriametrics(state, monkeypatch):
    from lib import st_live_map
    state["config"]["DATABASE"] = [{"DB_UID": "VM", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "h", "DB_PORT": "1"}]
    seen = {}

    def read_metrics(vm, at=None):
        seen["at"] = at
        return {"loss": {}, "jitter": {}, "mos": {}, "rtt": {}}
    monkeypatch.setattr(st_live_map, "read_metrics", read_metrics)
    monkeypatch.setattr(st_live_map, "read_status", lambda vm, at: {"PILOT_1": "DISCONNECTED"})
    monkeypatch.setattr(st_live_map, "read_alerts", lambda vm, at: [])
    m = ops.live_topology(state, at="1000")
    assert seen["at"] == 1000 and m["at"] == 1000
    status = {n["id"]: n["status"] for n in m["nodes"]}
    assert status["PILOT_1"] == "DISCONNECTED" and status["WAVE_1"] == "UNKNOWN"  # pas collecté : inconnu
    with pytest.raises(ops.OpError):
        ops.live_topology(state, at="demain")


def test_the_timeline_window_is_checked(state, monkeypatch):
    from lib import st_live_map
    state["config"]["DATABASE"] = [{"DB_UID": "VM", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "h", "DB_PORT": "1"}]
    monkeypatch.setattr(st_live_map, "timeline", lambda vm, s, e, step, g: {"t": [s], "step_seen": step})
    t = ops.topology_timeline(state, "1000000", str(1000000 + 6 * 3600))
    assert t["step"] == 60 and t["t"][0] % 60 == 0
    assert ops.topology_timeline(state, "1000000", str(1000000 + 7 * 86400))["step"] == 1680
    with pytest.raises(ops.OpError):
        ops.topology_timeline(state, "2000", "1000")


# ------------------------------------------------------------------------------------------- pause d'une sonde

def _peers(generated, uid):
    """Sondes avec lesquelles uid a un flux (listeners ou connectors), d'après la configuration générée."""
    edges = {**(generated.get(uid) or {}).get("LISTENERS", {}), **(generated.get(uid) or {}).get("CONNECTORS", {})}
    return {v.get(k) for v in edges.values() for k in ("UID_CLIENT", "UID_SERVER") if v.get(k) and v.get(k) != uid}


def test_a_paused_probe_measures_nothing_and_nobody_measures_it(state):
    gen = state["_dict_by_node_generated_config"]
    assert "WAVE_1" in _peers(gen, "PILOT_1")
    r = ops.set_client_paused(state, "WAVE_1", True, "tester")
    assert "WAVE_1" in r["reconnected_clients"] and "PILOT_1" in r["reconnected_clients"]
    assert gen["WAVE_1"] == {"LISTENERS": {}, "CONNECTORS": {}} or not _peers(gen, "WAVE_1")
    assert all("WAVE_1" not in _peers(gen, u) for u in ("PILOT_1", "WAVE_2", "LOOSE"))
    assert ops.list_clients(state)[1]["PAUSED"] is True  # gardé dans la configuration : survit à un redémarrage
    assert ops.list_clients(state)[0]["PAUSED"] is False


def test_resuming_a_probe_gives_its_flows_back(state):
    ops.set_client_paused(state, "WAVE_1", True, "tester")
    ops.set_client_paused(state, "WAVE_1", False, "tester")
    assert "WAVE_1" in _peers(state["_dict_by_node_generated_config"], "PILOT_1")
    assert "PAUSED" not in toml.loads(Path(state["config_file_path"]).read_text())["SERVER_CLIENT"][1]


def test_pausing_an_unknown_probe_is_refused(state):
    with pytest.raises(ops.OpError) as e:
        ops.set_client_paused(state, "NOPE", True, "tester")
    assert e.value.status == 404


def test_the_paused_probe_still_shows_connected_with_its_pause(state):
    try:
        from lib.web_ui_kindafixed2 import st_status
    except ImportError:
        pytest.skip("interface web absente (paquets du serveur)")
    ops.set_client_paused(state, "WAVE_1", True, "tester")
    rows = {r["uid"]: r for r in st_status.clients(state)}
    assert rows["WAVE_1"]["status"] == "CONNECTED" and rows["WAVE_1"]["paused"] is True
    assert rows["WAVE_1"]["status_label"] == "CONNECTED - PAUSED"
    assert rows["PILOT_1"]["status_label"] == "CONNECTED" and rows["PILOT_1"]["paused"] is False


def test_pausing_reconfigures_the_peers_live_instead_of_reconnecting_them(state):
    """Les sondes qui savent recevoir leur configuration en direct ne sont pas déconnectées ; les plus anciennes,
    si."""
    for uid in ("PILOT_1", "WAVE_1", "WAVE_2"):
        state["dict_of_clients"][uid].capabilities = {"LIVE_CONFIG"}
    r = ops.set_client_paused(state, "WAVE_1", True, "tester")
    cmds = state["dict_of_commands_for_network_clients"]
    assert cmds["PILOT_1"] == [{"ACTION": "NEWCONFIG"}] and cmds["WAVE_1"] == [{"ACTION": "NEWCONFIG"}]
    assert cmds["LOOSE"] == [{"ACTION": "RECONNECT_CLIENT"}]  # sans la capacité : reconnectée comme avant
    assert set(r["reconfigured_clients"]) >= {"PILOT_1", "WAVE_1", "WAVE_2"} and r["reconnected_clients"] == ["LOOSE"]
    ops.set_client_paused(state, "WAVE_1", False, "tester")
    assert cmds["PILOT_1"] == [{"ACTION": "NEWCONFIG"}]  # une seule configuration en attente : la dernière


def _ports(generated):
    """{(groupe, sonde qui écoute, sonde qui envoie): port}."""
    return {(v["MESH_GROUP"], v["UID_SERVER"], v["UID_CLIENT"]): v["PORT"]
            for g in generated.values() for v in (g.get("LISTENERS") or {}).values()}


def test_a_flow_keeps_its_listener_port_when_another_probe_is_paused_or_resumed(state):
    """Ports attribués dans l'ordre : retirer une sonde décalait ceux des autres flux, relancés sans raison."""
    before = _ports(state["_dict_by_node_generated_config"])
    ops.set_client_paused(state, "WAVE_1", True, "tester")
    during = _ports(state["_dict_by_node_generated_config"])
    assert during == {k: p for k, p in before.items() if "WAVE_1" not in k[1:]}
    ops.set_client_paused(state, "WAVE_1", False, "tester")
    after = _ports(state["_dict_by_node_generated_config"])
    assert after == before  # les ports des flux rendus ne prennent celui de personne
    for node in {k[1] for k in after}:
        mine = [p for k, p in after.items() if k[1] == node]
        assert len(mine) == len(set(mine))  # jamais deux flux sur le même port d'une sonde


# ------------------------------------------------------------------------- serveur neuf (aucun groupe, aucun client)

@pytest.fixture
def fresh(tmp_path):
    """Serveur tout juste installé par le package : ni [[MESH_GROUP]] ni [[SERVER_CLIENT]] dans le fichier."""
    cfg = {"SERVER": {"BIND_ADDRESS": "0.0.0.0", "SERVER_PORT": "6531", "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                      "TOKEN": {"t": "secret-token"}}, "GLOBAL": {}}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    return {"config": toml.loads(path.read_text()), "config_file_path": str(path), "_dict_by_node_generated_config": {},
            "_dict_by_group_of_generated_tuple_for_map": {}, "dict_of_clients": {},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def test_a_fresh_server_approves_its_first_probe_and_knows_it_at_once(fresh):
    """L'approbation écrivait le fichier puis plantait (KeyError 'MESH_GROUP') : le serveur en marche ne connaissait
    pas le client et la sonde restait « PENDING APPROVAL »."""
    from lib.st_enrollment import Enrollment, authorize
    key = "-----BEGIN PUBLIC KEY-----probe-----END PUBLIC KEY-----"
    Enrollment(fresh["config_file_path"] + ".pending.json").record("tcn00qubc03351", "10.120.130.27", key, "0.45.9")
    r = ops.approve_client(fresh, "tcn00qubc03351", {"IP_MODE": "static", "MESH_GROUP_UID_LIST": []}, "tester")
    assert r["uid"] == "tcn00qubc03351"
    assert [c["UID"] for c in fresh["config"]["SERVER_CLIENT"]] == ["tcn00qubc03351"]  # en mémoire, tout de suite
    assert Enrollment(fresh["config_file_path"] + ".pending.json").pending() == []
    d = authorize(fresh["config"], {"CLIENT_UID": "tcn00qubc03351", "TOKEN": "secret-token", "PUBLIC_KEY": key},
                  "10.120.130.27", None)
    assert d.accepted and d.deliver_token  # accepté, avec son jeton propre


def test_a_fresh_server_creates_its_first_mesh_group(fresh):
    r = ops.create(fresh, {"UID": "FIRST_GROUP", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218",
                           "INTERVAL": "1"}, "tester")
    assert [g["UID"] for g in fresh["config"]["MESH_GROUP"]] == ["FIRST_GROUP"] and r["uid"] == "FIRST_GROUP"

"""Garde-fous de capacité dans les opérations de la webui : limites strictes, alerte avec confirmation, ports.
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

NODES = [f"NODE_{i:02d}" for i in range(12)]


class FakeClient:
    status = "CONNECTED"


def make_state(tmp_path, server_extra=None, port_range="15000-15999", narrow_client=None):
    """12 clients dans GROUP1 en hub & spoke autour de NODE_00 (22 flux)."""
    cfg = {"SERVER": dict({"MESH_LISTENERS_PORT_RANGE": port_range}, **(server_extra or {})), "GLOBAL": {},
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1",
                           "TOPOLOGY": "HUB_SPOKE", "HUBS": ["NODE_00"]}],
           "SERVER_CLIENT": [{"UID": u, "IP_ADDRESS": f"10.0.0.{i + 1}", "MESH_GROUP_UID_LIST": ["GROUP1"]}
                             for i, u in enumerate(NODES)]}
    if narrow_client:  # plage de ports propre à un client : assez pour un spoke, pas pour un maillage
        next(c for c in cfg["SERVER_CLIENT"] if c["UID"] == narrow_client)["MESH_LISTENERS_PORT_RANGE"] = "16000-16003"
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples, "dict_of_clients": {u: FakeClient() for u in NODES},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


TO_MESH = {"BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1", "TOPOLOGY": "MESH"}


def test_preview_reports_the_impact(tmp_path):
    result = ops.update(make_state(tmp_path), "GROUP1", TO_MESH, actor="x", dry_run=True)
    impact = result["impact"]
    assert (impact["flows_before"], impact["flows_after"]) == (22, 132)
    assert impact["busiest"]["processes"] == 22 and impact["points_per_s_after"] == 132
    assert impact["alert"] is True and "added" in impact["alert_reason"]


def test_a_large_change_needs_an_explicit_confirmation(tmp_path):
    state = make_state(tmp_path)
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "GROUP1", TO_MESH, actor="x")
    assert err.value.status == 428
    token = ops.CONFIRMED.set(True)
    try:
        ops.update(state, "GROUP1", TO_MESH, actor="x")
    finally:
        ops.CONFIRMED.reset(token)
    assert len(state["_dict_by_node_generated_config"]["NODE_05"]["CONNECTORS"]) == 11


def test_a_hard_limit_blocks_even_when_confirmed_and_suggests_hubs(tmp_path):
    state = make_state(tmp_path, {"MAX_TOTAL_FLOWS": "100"})
    token = ops.CONFIRMED.set(True)
    try:
        with pytest.raises(ops.OpError) as err:
            ops.update(state, "GROUP1", TO_MESH, actor="x", dry_run=True)
    finally:
        ops.CONFIRMED.reset(token)
    assert err.value.status == 409
    assert "132 flows in total" in err.value.message and "dual hub" in err.value.message.lower()


def test_running_out_of_listener_ports_is_refused_clearly(tmp_path):
    state = make_state(tmp_path, {"FLOW_ALERT_ADDED": "1000", "FLOW_ALERT_RATIO": "100"}, narrow_client="NODE_05")
    with pytest.raises(ops.OpError) as err:
        ops.update(state, "GROUP1", TO_MESH, actor="x", dry_run=True)
    assert err.value.status == 409 and "port" in err.value.message.lower() and "MESH_LISTENERS_PORT_RANGE" in err.value.message


def test_limits_are_server_settings_applied_live(tmp_path):
    state = make_state(tmp_path)
    values = {"BIND_ADDRESS": "", "SERVER_PORT": "", "MESH_LISTENERS_PORT_RANGE": "15000-15999",
              "MAX_FLOWS_PER_CLIENT": "30", "MAX_TOTAL_FLOWS": "800", "FLOW_ALERT_ADDED": "50", "FLOW_ALERT_RATIO": "1.5"}
    result = ops.update_server(state, values, actor="x")
    assert result["restart_required"] == []
    server = ops.get_server(state)
    assert (server["MAX_TOTAL_FLOWS"], server["FLOW_ALERT_RATIO"]) == ("800", "1.5")
    with pytest.raises(ops.OpError) as err:
        ops.update_server(state, dict(values, MAX_TOTAL_FLOWS="0", FLOW_ALERT_RATIO="x"), actor="x")
    assert set(err.value.fields) == {"MAX_TOTAL_FLOWS", "FLOW_ALERT_RATIO"}


def test_unrelated_changes_are_not_blocked_on_an_installation_over_its_limits(tmp_path):
    state = make_state(tmp_path, {"MAX_TOTAL_FLOWS": "10"})  # 22 flux déjà en place
    ops.update(state, "GROUP1", {"BANDWIDTH": "120K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1",
                                 "TOPOLOGY": "HUB_SPOKE", "HUBS": ["NODE_00"]}, actor="x")

"""Approbation des clients depuis la webui (lib/st_mesh_group_ops.py) : approuver, refuser, sécuriser un client
existant, faire tourner son jeton. Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib import st_config_store as store
    from lib import st_enrollment
    from lib import st_mesh_group_ops as ops
    from lib.st_conf_validation import validate_group, generate_client_config_mesh
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)

KEY = "-----BEGIN PUBLIC KEY-----NEW"


class FakeClient:
    def __init__(self, status, key=None):
        self.status = status
        self.public_key_sha256 = st_enrollment.fingerprint(key) if key else None


@pytest.fixture
def state(tmp_path):
    cfg = {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100", "TOKEN": {"site": "shared"}}, "GLOBAL": {},
           "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}],
           "SERVER_CLIENT": [{"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["GROUP1"]}]}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    enrollment = st_enrollment.Enrollment(str(path) + ".pending.json")
    st_enrollment.authorize(live, {"CLIENT_UID": "NEW_NODE", "TOKEN": "shared", "PUBLIC_KEY": KEY,
                                   "SYNTRAF_CLIENT_VERSION": "0.46"}, "10.0.0.9", enrollment)
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": generated,
            "_dict_by_group_of_generated_tuple_for_map": tuples,
            "dict_of_clients": {"NODE_A": FakeClient("CONNECTED", key="-----BEGIN PUBLIC KEY-----A")},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set()}


def declared(state, uid):
    return next((c for c in toml.load(state["config_file_path"])["SERVER_CLIENT"] if c["UID"] == uid), None)


def test_pending_requests_are_listed_without_the_full_key(state):
    [p] = ops.list_pending(state)["pending"]
    assert p["UID"] == "NEW_NODE" and p["IP_ADDRESS"] == "10.0.0.9" and "PUBLIC_KEY" not in p
    assert p["PUBLIC_KEY_SHA256"] == st_enrollment.fingerprint(KEY)


def test_approval_declares_the_client_with_its_pinned_key_and_own_token(state):
    ops.approve_client(state, "NEW_NODE", {"MESH_GROUP_UID_LIST": ["GROUP1"], "IP_MODE": "static"}, actor="admin")
    c = declared(state, "NEW_NODE")
    assert c["IP_ADDRESS"] == "10.0.0.9" and c["MESH_GROUP_UID_LIST"] == ["GROUP1"]
    assert c["PUBLIC_KEY_SHA256"] == st_enrollment.fingerprint(KEY) and len(c["TOKEN"]) >= 24
    assert ops.list_pending(state)["pending"] == []
    # La prochaine tentative du client (jeton partagé, même clé) est acceptée et reçoit son jeton
    d = st_enrollment.authorize(state["config"], {"CLIENT_UID": "NEW_NODE", "TOKEN": "shared", "PUBLIC_KEY": KEY},
                                "10.0.0.9", None)
    assert d.accepted and d.deliver_token == c["TOKEN"]
    assert store.audit_entries(state["config_file_path"])[0]["action"] == "APPROVE_CLIENT"


def test_dry_run_approval_keeps_the_request(state):
    result = ops.approve_client(state, "NEW_NODE", {"MESH_GROUP_UID_LIST": ["GROUP1"], "IP_MODE": "dynamic"},
                                actor="admin", dry_run=True)
    assert result["affected_clients"] == ["NEW_NODE", "NODE_A"]
    assert [p["UID"] for p in ops.list_pending(state)["pending"]] == ["NEW_NODE"]


def test_rejection_is_audited_and_can_be_forgiven(state):
    ops.reject_client(state, "NEW_NODE", actor="admin")
    assert ops.list_pending(state)["pending"] == []
    assert [r["UID"] for r in ops.list_pending(state)["rejected"]] == ["NEW_NODE"]
    ops.forgive_client(state, "NEW_NODE", actor="admin")
    assert ops.list_pending(state)["rejected"] == []
    actions = [e["action"] for e in store.audit_entries(state["config_file_path"])]
    assert actions[:2] == ["FORGIVE_CLIENT", "REJECT_CLIENT"]


def test_unknown_request_cannot_be_approved(state):
    with pytest.raises(ops.OpError) as err:
        ops.approve_client(state, "NOPE_NODE", {"MESH_GROUP_UID_LIST": []}, actor="admin")
    assert err.value.status == 404


def test_securing_an_existing_client_pins_its_current_key_and_hands_over_a_token(state):
    ops.secure_client(state, "NODE_A", actor="admin")
    c = declared(state, "NODE_A")
    assert c["PUBLIC_KEY_SHA256"] == st_enrollment.fingerprint("-----BEGIN PUBLIC KEY-----A") and c["TOKEN"]
    assert state["dict_of_commands_for_network_clients"]["NODE_A"][-1] == {"ACTION": "SET_TOKEN", "TOKEN": c["TOKEN"]}


def test_securing_needs_a_key_seen_on_a_connection(state):
    state["dict_of_clients"]["NODE_A"] = FakeClient("DISCONNECTED")
    with pytest.raises(ops.OpError) as err:
        ops.secure_client(state, "NODE_A", actor="admin")
    assert err.value.status == 409


def test_token_rotation_needs_a_pinned_key_and_sends_the_new_token(state):
    with pytest.raises(ops.OpError):
        ops.rotate_client_token(state, "NODE_A", actor="admin")
    ops.secure_client(state, "NODE_A", actor="admin")
    old = declared(state, "NODE_A")["TOKEN"]
    ops.rotate_client_token(state, "NODE_A", actor="admin")
    new = declared(state, "NODE_A")["TOKEN"]
    assert new != old
    assert state["dict_of_commands_for_network_clients"]["NODE_A"][-1]["TOKEN"] == new


def test_client_listing_shows_the_security_state_but_never_the_token(state):
    ops.secure_client(state, "NODE_A", actor="admin")
    [row] = ops.list_clients(state)
    assert row["PINNED"] is True and row["OWN_TOKEN"] is True and "TOKEN" not in row


def test_approving_a_key_change_repins_and_keeps_the_declaration(state):
    ops.secure_client(state, "NODE_A", actor="admin")
    before = declared(state, "NODE_A")
    new_key = "-----BEGIN PUBLIC KEY-----REINSTALLED"
    enrollment = st_enrollment.Enrollment(state["config_file_path"] + ".pending.json")
    d = st_enrollment.authorize(state["config"], {"CLIENT_UID": "NODE_A", "TOKEN": before["TOKEN"],
                                                  "PUBLIC_KEY": new_key}, "10.0.0.1", enrollment)
    assert d.reason == "KEY MISMATCH"
    assert next(p for p in ops.list_pending(state)["pending"] if p["UID"] == "NODE_A")["KEY_CHANGE"] is True
    ops.approve_client(state, "NODE_A", {}, actor="admin")
    after = declared(state, "NODE_A")
    assert after["PUBLIC_KEY_SHA256"] == st_enrollment.fingerprint(new_key) and after["TOKEN"] != before["TOKEN"]
    assert after["MESH_GROUP_UID_LIST"] == before["MESH_GROUP_UID_LIST"] and after["IP_ADDRESS"] == before["IP_ADDRESS"]
    assert store.audit_entries(state["config_file_path"])[0]["action"] == "APPROVE_KEY_CHANGE"


def test_a_request_from_a_client_declared_since_is_dropped(state):
    # Le client s'est présenté avant d'être déclaré (fichier modifié, ajout dans la page Clients) : sa demande est
    # caduque ; elle ne doit plus apparaître ni pouvoir être « approuvée » (erreur « already declared »).
    ops.create_client(state, {"UID": "NEW_NODE", "IP_ADDRESS": "10.0.0.9", "MESH_GROUP_UID_LIST": ["GROUP1"]},
                      actor="admin")
    assert ops.list_pending(state)["pending"] == []
    with pytest.raises(ops.OpError) as err:
        ops.approve_client(state, "NEW_NODE", {"MESH_GROUP_UID_LIST": ["GROUP1"]}, actor="admin")
    assert err.value.status == 404

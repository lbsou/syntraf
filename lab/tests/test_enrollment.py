"""Admission des clients (lib/st_enrollment.py) : clé épinglée, jeton propre à chaque client, demandes en attente.
Module sans dépendance : tourne dans lab/.venv.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_enrollment as enr  # noqa: E402

KEY_A, KEY_B = "-----BEGIN PUBLIC KEY-----AAA", "-----BEGIN PUBLIC KEY-----BBB"
SHARED = "shared-enrollment-token"


def config(*none, **client):
    """config(...) : NODE_A déclaré, avec les clés données ; config(None) : aucun client déclaré."""
    clients = [] if none == (None,) else [dict({"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1"}, **client)]
    return {"SERVER": {"TOKEN": {"site": SHARED}}, "SERVER_CLIENT": clients}


@pytest.fixture
def store(tmp_path):
    return enr.Enrollment(str(tmp_path / "config.toml.pending.json"))


def auth(cfg, store, uid="NODE_A", token=SHARED, key=KEY_A, ip="10.0.0.1"):
    return enr.authorize(cfg, {"CLIENT_UID": uid, "TOKEN": token, "PUBLIC_KEY": key,
                               "SYNTRAF_CLIENT_VERSION": "0.46"}, ip, store)


def test_legacy_client_with_the_shared_token_is_accepted(store):
    assert auth(config(), store) == enr.Decision(True, "", None)


def test_client_with_its_own_token_must_present_it(store):
    cfg = config(TOKEN="own-a", PUBLIC_KEY_SHA256=enr.fingerprint(KEY_A))
    assert auth(cfg, store, token="own-a").accepted
    assert auth(cfg, store, token="someone-else").reason == "INVALID TOKEN"


def test_pinned_key_with_the_shared_token_gets_its_own_token_handed_over(store):
    cfg = config(TOKEN="own-a", PUBLIC_KEY_SHA256=enr.fingerprint(KEY_A))
    d = auth(cfg, store, token=SHARED)
    assert d.accepted and d.deliver_token == "own-a"


def test_another_device_cannot_use_a_pinned_name_even_with_a_valid_token(store):
    cfg = config(TOKEN="own-a", PUBLIC_KEY_SHA256=enr.fingerprint(KEY_A))
    assert auth(cfg, store, token="own-a", key=KEY_B).reason == "KEY MISMATCH"
    assert auth(cfg, store, token=SHARED, key=KEY_B).reason == "KEY MISMATCH"


def test_own_token_without_pinned_key_does_not_accept_the_shared_token(store):
    cfg = config(TOKEN="own-a")
    assert auth(cfg, store, token=SHARED).reason == "INVALID TOKEN"


def test_unknown_client_with_a_shared_token_waits_for_approval(store):
    d = auth(config(None), store, uid="NEW_NODE", key=KEY_B, ip="10.9.9.9")
    assert d.reason == "PENDING APPROVAL"
    [p] = store.pending()
    assert (p["UID"], p["IP_ADDRESS"], p["PUBLIC_KEY_SHA256"], p["VERSION"]) == \
           ("NEW_NODE", "10.9.9.9", enr.fingerprint(KEY_B), "0.46")
    assert p["PUBLIC_KEY"] == KEY_B and p["ATTEMPTS"] == 1
    auth(config(None), store, uid="NEW_NODE", key=KEY_B, ip="10.9.9.9")
    assert store.pending()[0]["ATTEMPTS"] == 2


def test_unknown_client_without_a_valid_token_is_not_recorded(store):
    assert auth(config(None), store, uid="NEW_NODE", token="guess").reason == "UNKNOWN CLIENT"
    assert store.pending() == []


def test_invalid_names_are_not_recorded(store):
    assert auth(config(None), store, uid="../x").reason == "UNKNOWN CLIENT"
    assert store.pending() == []


def test_a_pending_request_changing_its_key_is_flagged(store):
    auth(config(None), store, uid="NEW_NODE", key=KEY_A)
    auth(config(None), store, uid="NEW_NODE", key=KEY_B)
    p = store.pending()[0]
    assert p["PUBLIC_KEY_SHA256"] == enr.fingerprint(KEY_B) and p["KEY_CHANGED"] is True


def test_rejected_client_stays_rejected_until_forgiven(store):
    auth(config(None), store, uid="NEW_NODE")
    store.reject("NEW_NODE", actor="admin")
    assert store.pending() == [] and [r["UID"] for r in store.rejected()] == ["NEW_NODE"]
    assert auth(config(None), store, uid="NEW_NODE").reason == "REJECTED"
    store.forgive("NEW_NODE")
    assert auth(config(None), store, uid="NEW_NODE").reason == "PENDING APPROVAL"


def test_pending_list_is_bounded(store, monkeypatch):
    monkeypatch.setattr(enr, "MAX_PENDING", 3)
    for i in range(5):
        auth(config(None), store, uid=f"NODE_{i:02d}")
    assert len(store.pending()) == 3


def test_take_removes_and_returns_the_request(store):
    auth(config(None), store, uid="NEW_NODE", key=KEY_B)
    assert store.take("NEW_NODE")["PUBLIC_KEY"] == KEY_B
    assert store.pending() == [] and store.take("NEW_NODE") is None


def test_fingerprint_format():
    assert enr.fingerprint(KEY_A).startswith("sha256:") and len(enr.fingerprint(KEY_A)) == 7 + 64


def test_new_key_with_a_valid_token_is_recorded_as_a_key_change(store):
    cfg = config(TOKEN="own-a", PUBLIC_KEY_SHA256=enr.fingerprint(KEY_A))
    assert auth(cfg, store, token="own-a", key=KEY_B).reason == "KEY MISMATCH"
    [p] = store.pending()
    assert p["UID"] == "NODE_A" and p["KEY_CHANGE"] is True and p["PUBLIC_KEY_SHA256"] == enr.fingerprint(KEY_B)


def test_new_key_without_a_valid_token_is_not_recorded(store):
    cfg = config(TOKEN="own-a", PUBLIC_KEY_SHA256=enr.fingerprint(KEY_A))
    assert auth(cfg, store, token="guess", key=KEY_B).reason == "KEY MISMATCH"
    assert store.pending() == []

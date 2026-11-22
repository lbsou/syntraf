"""Admission sur le canal de contrôle : décision du serveur, remise du jeton propre (SET_TOKEN), conservation par le
client et repli sur le jeton partagé quand son jeton propre est refusé.

Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_enrollment, st_mesh
    from lib.st_obj_cc_client import cc_client
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)

KEY = "-----BEGIN PUBLIC KEY-----AAA"


class FakeSocket:
    def getpeername(self):
        return ("10.0.0.1", 40000)


def server_config(**client):
    return {"SERVER": {"TOKEN": {"site": "shared"}},
            "SERVER_CLIENT": [dict({"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1"}, **client)]}


def payload(token, uid="NODE_A", key=KEY):
    return {"PAYLOAD": {"CLIENT_UID": uid, "TOKEN": token, "PUBLIC_KEY": key, "SYNTRAF_CLIENT_VERSION": "0.46"}}


def test_server_hands_over_the_own_token_to_a_pinned_client(tmp_path):
    cfg = server_config(TOKEN="own-a", PUBLIC_KEY_SHA256=st_enrollment.fingerprint(KEY))
    commands = {}
    client = cc_client("UNKNOWN", None, "", False, "NODE_A")
    ok, reason = st_mesh.authenticate_server_client(cfg, payload("shared"), client, FakeSocket(),
                                                    st_enrollment.Enrollment(str(tmp_path / "p.json")), commands)
    assert ok and commands["NODE_A"] == [{"ACTION": "SET_TOKEN", "TOKEN": "own-a"}]
    assert client.public_key_sha256 == st_enrollment.fingerprint(KEY)


def test_server_records_an_unknown_client_as_pending(tmp_path):
    enrollment = st_enrollment.Enrollment(str(tmp_path / "p.json"))
    ok, reason = st_mesh.authenticate_server_client(server_config(), payload("shared", uid="NEW_NODE"),
                                                    cc_client("UNKNOWN", None, "", False, "NEW_NODE"), FakeSocket(),
                                                    enrollment, {})
    assert (ok, reason) == (False, "PENDING APPROVAL")
    assert [p["UID"] for p in enrollment.pending()] == ["NEW_NODE"]


def test_set_token_command_is_sent_without_logging_the_token(monkeypatch, caplog):
    sent = []
    monkeypatch.setattr(st_mesh, "sock_send", lambda s, p, c: sent.append((c, p)))
    st_mesh.server_awaiting_commands("NODE_A", {"NODE_A": [{"ACTION": "SET_TOKEN", "TOKEN": "own-a"}]}, None)
    assert sent == [("SET_TOKEN", {"TOKEN": "own-a"})]
    assert "own-a" not in caplog.text


def test_client_saves_its_token_privately(tmp_path):
    cfg = {"CLIENT": {"TOKEN": "shared", "_TOKEN_FILE": str(tmp_path / "syntraf_client_token")}}
    st_mesh.client_command_set_token(cfg, {"PAYLOAD": {"TOKEN": "own-a"}})
    path = tmp_path / "syntraf_client_token"
    assert path.read_text() == "own-a"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert st_mesh.client_token(cfg) == "own-a"


def test_client_falls_back_to_the_shared_token_after_a_refusal(tmp_path, monkeypatch):
    token_file = tmp_path / "syntraf_client_token"
    token_file.write_text("old-own")
    cfg = {"CLIENT": {"TOKEN": "shared", "CLIENT_UID": "NODE_A", "PUBLIC_KEY": KEY, "_TOKEN_FILE": str(token_file)}}
    sent = []
    monkeypatch.setattr(st_mesh, "sock_send", lambda s, p, c: sent.append(p["TOKEN"]))
    answers = iter([{"COMMAND": "AUTH_FAILED", "PAYLOAD": "INVALID TOKEN"}, {"COMMAND": "AUTHENTICATION SUCCESSFUL"}])
    monkeypatch.setattr(st_mesh, "sock_rcv", lambda s: next(answers))
    assert st_mesh.client_send_auth(cfg, 0, None) is False
    assert st_mesh.client_send_auth(cfg, 0, None) is True
    assert sent == ["old-own", "shared"]


# ---------------------------------------------------------------------------------- preuve de la clé du client

@pytest.fixture
def identity(tmp_path, monkeypatch):
    from lib import st_identity
    from lib.st_crypto import ensure_self_signed
    scert, skey = ensure_self_signed(str(tmp_path / "srv"), "server")
    fp = st_identity.spki_sha256(st_identity.pem_to_der(open(scert, "rb").read()))
    monkeypatch.setattr(st_mesh, "_SERVER_IDENTITY", {"fp": fp, "key": open(skey).read()})
    ccert, ckey = ensure_self_signed(str(tmp_path / "cli"), "client")
    return fp, open(ckey).read(), st_identity.public_key_pem_of_cert(open(ccert, "rb").read())


def proved(identity, uid="NODE_A", token="shared"):
    from lib import st_identity
    fp, key, pub = identity
    p = payload(token, uid=uid, key=pub)
    p["PAYLOAD"]["PROOF"] = st_identity.auth_proof(key, uid, fp)
    return p


def test_a_client_that_proves_its_key_is_admitted(tmp_path, identity):
    cfg = server_config()
    ok, reason = st_mesh.authenticate_server_client(cfg, proved(identity), cc_client("UNKNOWN", None, "", False, "NODE_A"),
                                                    FakeSocket(), st_enrollment.Enrollment(str(tmp_path / "p.json")), {})
    assert ok, reason


def test_a_proof_made_with_another_key_is_refused(tmp_path, identity):
    from lib import st_identity
    from lib.st_crypto import ensure_self_signed
    fp, _, pub = identity
    _, other_key = ensure_self_signed(str(tmp_path / "other"), "client")
    p = payload("shared", key=pub)
    p["PAYLOAD"]["PROOF"] = st_identity.auth_proof(open(other_key).read(), "NODE_A", fp)
    ok, reason = st_mesh.authenticate_server_client(server_config(), p, cc_client("UNKNOWN", None, "", False, "NODE_A"),
                                                    FakeSocket(), st_enrollment.Enrollment(str(tmp_path / "p.json")), {})
    assert (ok, reason) == (False, "INVALID KEY PROOF")


def test_an_older_client_without_proof_is_accepted_unless_required(tmp_path, identity):
    cfg = server_config()
    ok, _ = st_mesh.authenticate_server_client(cfg, payload("shared"), cc_client("UNKNOWN", None, "", False, "NODE_A"),
                                               FakeSocket(), st_enrollment.Enrollment(str(tmp_path / "p.json")), {})
    assert ok
    cfg["SERVER"]["REQUIRE_KEY_PROOF"] = True
    ok, reason = st_mesh.authenticate_server_client(cfg, payload("shared"), cc_client("UNKNOWN", None, "", False, "NODE_A"),
                                                    FakeSocket(), st_enrollment.Enrollment(str(tmp_path / "p.json")), {})
    assert not ok and "KEY PROOF REQUIRED" in reason

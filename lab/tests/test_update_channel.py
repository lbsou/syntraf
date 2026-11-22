"""Mise à jour sur le canal de contrôle : commande UPDATE, téléchargement de la release intégrée du serveur par
morceaux, installation et demande de bascule. Les messages client → serveur sont relayés en mémoire.

Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_mesh, st_release, st_updater
    from lib.st_global import DefaultValues
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


@pytest.fixture
def server_release(tmp_path, monkeypatch):
    """Le « serveur » distribue le code de tmp/server_src ; le client a son installation en place dans tmp/client."""
    src = tmp_path / "server_src"
    (src / "lib").mkdir(parents=True)
    (src / "syntraf.py").write_text("print('new')\n")
    (src / "lib" / "st_x.py").write_text("X = 2\n" * 50000)  # assez gros pour plusieurs morceaux
    (src / "requirements_client.txt").write_text("toml==0.10.2\n")
    client = tmp_path / "client"
    client.mkdir()
    (client / "requirements_client.txt").write_text("toml==0.10.2\n")
    monkeypatch.setattr(DefaultValues, "SYNTRAF_ROOT_DIR", src)
    monkeypatch.setattr(DefaultValues, "SYNTRAF_DATA_DIR", client)
    monkeypatch.setattr(st_mesh, "RELEASE_CHUNK_BYTES", 64 * 1024)
    info = st_release.builtin(src, tmp_path / "server_data", DefaultValues.SYNTRAF_VERSION)
    return info, client


def relay(monkeypatch):
    """sock_send du client → gestionnaire du serveur ; sa réponse est rendue par sock_rcv."""
    answers, statuses = [], []

    def send(sock, payload, command):
        if command == "GET_RELEASE_CHUNK":
            st_mesh.server_send_release_chunk("server-side", payload)
        elif command == "UPDATE_STATUS":
            statuses.append(payload)
        elif sock == "server-side":
            answers.append({"COMMAND": command, "PAYLOAD": payload})

    monkeypatch.setattr(st_mesh, "sock_send", send)
    monkeypatch.setattr(st_mesh, "sock_rcv", lambda sock: answers.pop(0))
    return statuses


@pytest.fixture
def keys(tmp_path, monkeypatch):
    """Clé du serveur (signature des releases) ; le client la connaît (épinglée à la connexion)."""
    from lib import st_identity
    from lib.st_crypto import ensure_self_signed
    cert, key = ensure_self_signed(str(tmp_path / "srv_crypto"), "server")
    key_pem, cert_pem = open(key).read(), open(cert, "rb").read()
    monkeypatch.setattr(st_mesh, "_SERVER_IDENTITY", {"fp": st_identity.spki_sha256(st_identity.pem_to_der(cert_pem)),
                                                      "key": key_pem})
    return key_pem, {"CLIENT": {"_SERVER_PUBLIC_PEM": st_identity.public_key_pem_of_cert(cert_pem)}}


def update_command(info, key_pem=None, **extra):
    from lib import st_identity
    payload = dict({"RELEASE": info["id"], "SHA256": info["sha256"], "SIZE": info["size"]}, **extra)
    if key_pem:
        payload["SIGNATURE"] = st_identity.sign_release(key_pem, payload["RELEASE"], payload["SHA256"],
                                                        payload["SIZE"])
    return {"PAYLOAD": payload}


def test_client_downloads_installs_and_asks_to_switch(server_release, keys, monkeypatch):
    info, client = server_release
    monkeypatch.setenv(st_updater.ENV_CHILD, "1")
    statuses = relay(monkeypatch)
    st_mesh.client_command_update(keys[1], "client-side", update_command(info, keys[0]))
    state = st_updater.read_state(str(client))
    assert state["current"] == info["id"] and state["restart"] is True
    assert (client / "releases" / info["id"] / "lib" / "st_x.py").read_text() == "X = 2\n" * 50000
    assert statuses == [{"RELEASE": info["id"], "STATE": "STAGED", "MESSAGE": "installed, switching"}]
    assert not list((client / "releases").glob("download-*"))  # l'archive téléchargée est supprimée


def test_unsupervised_client_reports_that_it_cannot_switch(server_release, keys, monkeypatch):
    info, client = server_release
    monkeypatch.delenv(st_updater.ENV_CHILD, raising=False)
    statuses = relay(monkeypatch)
    st_mesh.client_command_update(keys[1], "client-side", update_command(info, keys[0]))
    assert statuses[0]["STATE"] == "FAILED" and "supervisor" in statuses[0]["MESSAGE"]
    assert st_updater.read_state(str(client))["current"] is None


def test_server_only_distributes_its_own_release(server_release, keys, monkeypatch):
    info, client = server_release
    monkeypatch.setenv(st_updater.ENV_CHILD, "1")
    statuses = relay(monkeypatch)
    st_mesh.client_command_update(keys[1], "client-side", update_command(info, keys[0], RELEASE="0.1+0000000000"))
    assert statuses[0]["STATE"] == "FAILED" and "distributes release" in statuses[0]["MESSAGE"]


def test_an_unsigned_release_is_never_installed(server_release, keys, monkeypatch):
    info, client = server_release
    monkeypatch.setenv(st_updater.ENV_CHILD, "1")
    statuses = relay(monkeypatch)
    st_mesh.client_command_update(keys[1], "client-side", update_command(info))  # sans signature
    assert statuses[0]["STATE"] == "FAILED" and "not signed" in statuses[0]["MESSAGE"]
    assert st_updater.read_state(str(client))["current"] is None


def test_a_release_signed_for_another_archive_is_refused(server_release, keys, monkeypatch):
    from lib import st_identity
    info, client = server_release
    monkeypatch.setenv(st_updater.ENV_CHILD, "1")
    statuses = relay(monkeypatch)
    command = update_command(info)
    command["PAYLOAD"]["SIGNATURE"] = st_identity.sign_release(keys[0], info["id"], "0" * 64, info["size"])
    st_mesh.client_command_update(keys[1], "client-side", command)
    assert statuses[0]["STATE"] == "FAILED" and st_updater.read_state(str(client))["current"] is None


def test_an_invalid_release_name_is_refused(server_release, keys, monkeypatch):
    info, client = server_release
    statuses = relay(monkeypatch)
    st_mesh.client_command_update(keys[1], "client-side", update_command(info, keys[0], RELEASE="../../etc"))
    assert statuses == [] and not (client / "releases").exists()


def test_update_command_is_sent_signed_to_the_client(keys, monkeypatch):
    from lib import st_identity
    sent = []
    monkeypatch.setattr(st_mesh, "sock_send", lambda s, p, c: sent.append((c, p)))
    st_mesh.server_awaiting_commands("NODE_A", {"NODE_A": [{"ACTION": "UPDATE", "RELEASE": "r", "SHA256": "s",
                                                            "SIZE": 3}]}, None)
    [(command, payload)] = sent
    assert command == "UPDATE" and {k: payload[k] for k in ("RELEASE", "SHA256", "SIZE")} == {"RELEASE": "r",
                                                                                              "SHA256": "s", "SIZE": 3}
    assert st_identity.verify_release(keys[1]["CLIENT"]["_SERVER_PUBLIC_PEM"], "r", "s", 3, payload["SIGNATURE"])


def test_server_records_the_update_status():
    from lib.st_obj_cc_client import cc_client
    client = cc_client("CONNECTED", None, "", False, "NODE_A")
    st_mesh.server_save_update_status(client, {"RELEASE": "r", "STATE": "FAILED", "MESSAGE": "no space left"})
    assert client.update_status["STATE"] == "FAILED" and client.update_status["AT"]

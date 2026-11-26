"""Fin d'une session de contrôle quand la sonde en a déjà ouvert une autre.

Cas vu en production (W34650, portable qui change de réseau) : la sonde se reconnecte depuis une autre adresse avant
que le serveur ne voie mourir l'ancienne session. Quand celle-ci expirait (SOCKET TIMEOUT), elle marquait la sonde
déconnectée et programmait l'oubli de son adresse, alors que la nouvelle session mesurait : état « déconnectée » avec
des données qui arrivent, et pairs privés de destination (100 % de pertes vers elle).

Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_enrollment, st_mesh
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)

from test_enrollment_channel import _self_signed, payload  # noqa: E402

UID = "LAPTOP"


@pytest.fixture
def control_server(tmp_path, monkeypatch):
    certfile, keyfile = _self_signed(tmp_path)
    monkeypatch.setattr(st_mesh, "DYNAMIC_UIDS", {UID}, raising=False)
    monkeypatch.setattr(st_mesh, "DYNAMIC_IP_FORGET", st_mesh.ForgetScheduler())
    srv = st_mesh.SSLnThreadingTCPServer(("127.0.0.1", 0), st_mesh.Handler, certfile=certfile, keyfile=keyfile)
    srv._config = {"SERVER": {"TOKEN": {"site": "shared"}, "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                              "RSA_KEY_LISTENERS": b"l", "RSA_KEY_CONNECTORS": b"c", "IPERF3_USERNAME": "u",
                              "IPERF3_PASSWORD": "p", "IPERF3_PASSWORD_HASH": "h"},
                   "GLOBAL": {"IPERF3_TIME_SKEW_THRESHOLD": 10}, "MESH_GROUP": [],
                   "SERVER_CLIENT": [{"UID": UID, "IP_ADDRESS": "0.0.0.0", "MESH_GROUP_UID_LIST": []}]}
    srv.dict_of_clients, srv.dict_of_commands_for_network_clients = {}, {}
    srv.dict_by_node_generated_config, srv.conn_db, srv.threads_n_processes = {}, [], []
    srv.dict_of_client_pending_acceptance = st_enrollment.Enrollment(str(tmp_path / "p.json"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def connect(srv):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    s = ctx.wrap_socket(socket.create_connection(srv.server_address, timeout=5))
    s.settimeout(5)
    auth = dict(payload("shared", uid=UID)["PAYLOAD"], TIMESTAMP=time.time())
    st_mesh.sock_send(s, auth, "AUTH")
    assert st_mesh.sock_rcv(s)["COMMAND"] == "AUTHENTICATION SUCCESSFUL"
    # la fiche de la sonde n'est rattachée à son nom qu'après la réponse : attendre la fin de l'authentification
    assert wait_until(lambda: UID in srv.dict_of_clients and "127.0.0.1" not in srv.dict_of_clients)
    return s


def session_thread(s):
    """Le fil du serveur qui sert cette connexion (nommé d'après l'adresse de la sonde)."""
    name = f"CONTROL CHANNEL CLIENT:{s.getsockname()}"
    return lambda: any(t.name == name for t in threading.enumerate())


def wait_until(condition, seconds=3.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.05)
    return condition()


def test_an_old_session_that_ends_after_a_reconnection_leaves_the_probe_connected(control_server):
    old = connect(control_server)
    new = connect(control_server)
    try:
        probe = control_server.dict_of_clients[UID]
        status, reason = probe.status, probe.status_explanation
        assert "CONNECTED" in status and status != "DISCONNECTED"
        alive = session_thread(old)
        assert alive()
        old.close()  # l'ancienne session meurt après l'authentification de la nouvelle
        assert wait_until(lambda: not alive()), "la session fermée n'a pas pris fin"
        time.sleep(0.2)
        assert (probe.status, probe.status_explanation) == (status, reason)
        assert not st_mesh.DYNAMIC_IP_FORGET.should_forget(UID, st_mesh.DYNAMIC_IP_FORGET._next), \
            "l'oubli de l'adresse a été programmé par l'ancienne session"
    finally:
        new.close()


def test_the_current_session_that_ends_marks_the_probe_disconnected(control_server):
    s = connect(control_server)
    probe = control_server.dict_of_clients[UID]
    s.close()
    assert wait_until(lambda: probe.status == "DISCONNECTED")
    assert st_mesh.DYNAMIC_IP_FORGET.should_forget(UID, st_mesh.DYNAMIC_IP_FORGET._next)

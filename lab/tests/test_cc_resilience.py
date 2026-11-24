"""Tests du canal de contrôle : lecture d'un message complet et application sélective de la config.

- recv_exact : une connexion fermée au milieu d'un message ne doit pas faire tourner sock_rcv à vide.
- edges_to_restart : à la reconnexion, seuls les iperf3 dont la config a changé sont relancés.
"""
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib.st_config_diff import edges_to_restart  # noqa: E402
from lib.st_sockutil import recv_exact  # noqa: E402


def pair():
    a, b = socket.socketpair()
    a.settimeout(2)
    return a, b


def test_recv_exact_reassembles_fragments():
    a, b = pair()
    def send():
        for chunk in (b"ab", b"c", b"def"):
            b.sendall(chunk)
    threading.Thread(target=send).start()
    assert recv_exact(a, 6) == b"abcdef"


def test_recv_exact_returns_none_when_peer_closes_mid_message():
    a, b = pair()
    b.sendall(b"abc")
    b.close()
    assert recv_exact(a, 6) is None


def test_recv_exact_returns_none_on_immediate_close():
    a, b = pair()
    b.close()
    assert recv_exact(a, 4) is None


def cfg(listeners=None, connectors=None, password="pw"):
    return {"LISTENERS": listeners or {}, "CONNECTORS": connectors or {},
            "CLIENT": {"IPERF3_PASSWORD": password}, "GLOBAL": {"IPERF3_AUTH": False}}


L1 = {"UID_CLIENT": "LAB_C2", "UID_SERVER": "LAB_C1", "PORT": 15999}
C1 = {"UID_CLIENT": "LAB_C1", "UID_SERVER": "LAB_C3", "DESTINATION_ADDRESS": "172.30.0.33", "PORT": 15997}


def test_identical_config_restarts_nothing():
    old = cfg({"l1": L1}, {"c1": C1})
    assert edges_to_restart(old, cfg({"l1": dict(L1)}, {"c1": dict(C1)})) == ([], [])


def test_removed_or_changed_edges_are_restarted():
    old = cfg({"l1": L1, "l2": L1}, {"c1": C1, "c2": C1})
    new = cfg({"l1": L1}, {"c1": dict(C1, PORT=16000), "c2": C1})
    assert edges_to_restart(old, new) == (["l2"], ["c1"])


def test_renamed_connector_key_is_restarted():
    # La clé d'un connecteur contient un hash de l'IP : une IP dynamique mise à jour change la clé.
    old = cfg(connectors={"old_key": C1})
    assert edges_to_restart(old, cfg(connectors={"new_key": C1})) == ([], ["old_key"])


def test_new_iperf3_credentials_with_auth_restart_everything():
    old = cfg({"l1": L1}, {"c1": C1})
    old["GLOBAL"]["IPERF3_AUTH"] = True
    new = cfg({"l1": L1}, {"c1": C1}, password="new")
    new["GLOBAL"]["IPERF3_AUTH"] = True
    assert edges_to_restart(old, new) == (["l1"], ["c1"])


def test_new_iperf3_credentials_without_auth_restart_nothing():
    assert edges_to_restart(cfg({"l1": L1}), cfg({"l1": L1}, password="new")) == ([], [])


def test_first_config_has_nothing_to_restart():
    assert edges_to_restart({"CLIENT": {}, "GLOBAL": {}}, cfg({"l1": L1})) == ([], [])


def test_reuse_keys_keeps_old_key_for_identical_content():
    from lib.st_config_diff import reuse_keys
    # Connecteur vers une IP dynamique : l'ancienne clé (hash de 0.0.0.0) a reçu l'IP par DIFFCONFIG.
    old = {"old_key": C1, "other": dict(C1, UID_SERVER="LAB_C4")}
    new = {"new_key": dict(C1), "other": dict(C1, UID_SERVER="LAB_C4"), "brand_new": dict(C1, PORT=1)}
    assert reuse_keys(old, new) == {"old_key": C1, "other": dict(C1, UID_SERVER="LAB_C4"), "brand_new": dict(C1, PORT=1)}


def test_reuse_keys_then_nothing_to_restart():
    from lib.st_config_diff import reuse_keys
    old = cfg(connectors={"old_key": C1})
    new = cfg(connectors=reuse_keys(old["CONNECTORS"], {"new_key": dict(C1)}))
    assert edges_to_restart(old, new) == ([], [])


def test_a_message_leaves_in_one_write_so_nagle_does_not_hold_it():
    """Taille puis contenu en deux écritures : Nagle retient la seconde jusqu'à l'accusé différé du pair (~40 ms), ce
    qui ralentissait chaque échange du canal de contrôle et faussait la mesure de l'horloge des sondes."""
    pytest.importorskip("toml")
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur
    from lib import st_mesh

    class Recorder:
        def __init__(self):
            self.writes = []

        def sendall(self, data):
            self.writes.append(bytes(data))
    r = Recorder()
    st_mesh.sock_send(r, {"T1": 1.5}, "AWAITING_COMMAND")
    assert len(r.writes) == 1
    size = int.from_bytes(r.writes[0][:4], "big", signed=True)
    assert size == len(r.writes[0]) - 4 and b'"AWAITING_COMMAND"' in r.writes[0]

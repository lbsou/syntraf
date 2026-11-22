"""Envoi des mesures du client (lib/st_mesh.client_send_metrics) : une réponse vide du serveur (connexion fermée,
redémarrage) est une déconnexion, pas une erreur avec trace. Tourne dans l'image du lab."""
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_mesh
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)

CONFIG = {"CLIENT": {"SERVER": "10.0.0.1", "SERVER_PORT": "6531"}}


def test_a_closed_connection_ends_the_session_quietly(monkeypatch, caplog):
    monkeypatch.setattr(st_mesh, "sock_send", lambda *a, **k: None)
    monkeypatch.setattr(st_mesh, "sock_rcv", lambda *a, **k: None)
    queue = {"h1": {"x": 1}}
    with caplog.at_level(logging.DEBUG):
        assert st_mesh.client_send_metrics(CONFIG, object(), queue) is False
    assert queue == {"h1": {"x": 1}}  # rien n'est perdu : renvoyé à la reconnexion
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("CONNECTION" in r.getMessage() and r.levelno == logging.WARNING for r in caplog.records)


def test_an_acknowledged_batch_leaves_the_queue(monkeypatch):
    monkeypatch.setattr(st_mesh, "sock_send", lambda *a, **k: None)
    monkeypatch.setattr(st_mesh, "sock_rcv", lambda *a, **k: {"COMMAND": "ACK", "PAYLOAD": "OK"})
    queue = {"h1": {"x": 1}}
    assert st_mesh.client_send_metrics(CONFIG, object(), queue) is True and queue == {}

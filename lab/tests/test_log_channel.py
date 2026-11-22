"""Transmission des journaux sur le canal de contrôle : envoi par le client (SAVE_LOGS), écriture par le serveur,
niveau transmis par le serveur dans la config du client.

Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_log_forward, st_mesh
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


@pytest.fixture
def handler(monkeypatch):
    h = st_log_forward.ForwardHandler(capacity=10, level=logging.INFO)
    monkeypatch.setattr(st_log_forward, "HANDLER", h)
    return h


def emit(h, message, level=logging.WARNING):
    h.emit(logging.LogRecord("syntraf.x", level, __file__, 1, message, None, None))


def test_client_sends_its_buffered_lines(monkeypatch, handler):
    sent = []
    monkeypatch.setattr(st_mesh, "sock_send", lambda conn, payload, command: sent.append((command, payload)))
    emit(handler, "disk almost full")
    st_mesh.client_send_logs(None)
    [(command, payload)] = sent
    assert command == "SAVE_LOGS" and payload["DROPPED"] == 0 and "disk almost full" in payload["LINES"][0]
    st_mesh.client_send_logs(None)
    assert len(sent) == 1  # rien de neuf : rien d'envoyé


def test_server_writes_the_lines_of_the_authenticated_client(tmp_path):
    config = {"GLOBAL": {"LOGDIR": str(tmp_path), "LOG_MAX_SIZE_PER_FILE_MB": "1", "LOG_FILE_TO_KEEP": "2"}}
    st_mesh.server_save_logs(config, "LAB_C2", {"PAYLOAD": {"LINES": [" 2026-11-21 23:45:00+0000 - INFO - x (y,1) - hi"],
                                                            "DROPPED": 0}})
    assert "hi" in (tmp_path / "clients" / "LAB_C2" / "syntraf.log").read_text()


def test_server_sends_the_forward_level_and_the_client_applies_it(handler):
    config = {"CLIENT": {}, "GLOBAL": {}}
    payload = {"LISTENERS": {}, "CONNECTORS": {}, "GLOBAL": {"IPERF3_TIME_SKEW_THRESHOLD": "10",
                                                            "LOG_FORWARD_LEVEL": "ERROR"},
               "CLIENT": {"IPERF3_USERNAME": "u", "IPERF3_PASSWORD": "p", "IPERF3_PASSWORD_HASH": "h"}}
    st_mesh.update_config({"PAYLOAD": payload}, config)
    assert handler.level == logging.ERROR

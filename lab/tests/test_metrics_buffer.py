"""Tampon de mesures des clients : chaque client rapporte combien de mesures attendent d'être envoyées au serveur
(arriéré quand le serveur est injoignable) ; le serveur l'affiche par client.

Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import lib.st_process_and_thread  # noqa: F401 - charge st_mesh dans l'ordre du serveur (import circulaire sinon)
    from lib import st_mesh
    from lib.st_obj_cc_client import cc_client
    from lib.web_ui_kindafixed2 import st_status
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


class FakeStats:
    hasdata = True

    def as_dict(self):
        return {"timestamp": 1, "if_pct_usage_rx": 1, "if_pct_usage_tx": 2, "mem_pct_free": 3, "cpu_pct_usage": 4}


def test_client_reports_its_buffer_with_the_system_stats(monkeypatch):
    sent = []
    monkeypatch.setattr(st_mesh, "sock_send", lambda conn, payload, command: sent.append((command, payload)))
    st_mesh.client_send_system_stats(None, FakeStats(), {"a": 1, "b": 2, "c": 3})
    assert sent == [("SAVE_STATS_METRIC", dict(FakeStats().as_dict(), metrics_buffer=3))]


def test_server_keeps_the_last_reported_buffer():
    client = cc_client("CONNECTED", None, "", False, "NODE_A")
    st_mesh.server_save_stats_metric(client, {"PAYLOAD": dict(FakeStats().as_dict(), metrics_buffer=42)})
    assert client.metrics_buffer == 42


def test_an_old_client_without_the_field_reports_nothing():
    client = cc_client("CONNECTED", None, "", False, "NODE_A")
    st_mesh.server_save_stats_metric(client, {"PAYLOAD": FakeStats().as_dict()})
    assert client.metrics_buffer is None


def test_status_and_metrics_show_the_buffer_per_client():
    client = cc_client("CONNECTED", None, "", False, "NODE_A")
    client.metrics_buffer = 7
    state = {"config": {"SERVER_CLIENT": [{"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1"}]},
             "dict_of_clients": {"NODE_A": client}, "_dict_by_node_generated_config": {}}
    assert st_status.clients(state)[0]["metrics_buffer"] == 7
    assert 'syntraf_client_buffered_points{client="NODE_A"} 7' in st_status.metrics(state)


def test_pre_authentication_placeholders_are_not_listed_as_clients():
    placeholder = cc_client("KEY MISMATCH", None, "", False, "172.30.0.31")
    state = {"config": {"SERVER_CLIENT": [{"UID": "NODE_A", "IP_ADDRESS": "10.0.0.1"}]},
             "dict_of_clients": {"172.30.0.31": placeholder}, "_dict_by_node_generated_config": {}}
    assert [c["uid"] for c in st_status.clients(state)] == ["NODE_A"]

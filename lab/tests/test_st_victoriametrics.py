"""Tests du moteur VictoriaMetrics de SYNTRAF (lib/st_victoriametrics.py), sans Docker."""
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib import st_victoriametrics as vm  # noqa: E402

POINT = {
    "measurement": "SYNTRAF",
    "tags": {"MESH_GROUP": "LAB_MESH", "CLIENT": "LAB_C1", "SERVER": "LAB_C2",
             "UID": "LAB_C1__TO__LAB_C2__ON__DSCP0"},
    "time": "2026-11-20 12:00:01+00:00",
    "fields": {"RX_BITRATE": 99.5, "RX_JITTER": 0.12, "RX_PCT_LOSS": 0.0,
               "RX_PACKET_TOTAL": 57, "RX_PACKET_LOSS": 0},
}
NS = int(datetime(2026, 11, 20, 12, 0, 1, tzinfo=timezone.utc).timestamp()) * 1_000_000_000


class Recorder(BaseHTTPRequestHandler):
    status = 204
    requests: list = []

    def _reply(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode() if length else ""
        type(self).requests.append((self.command, self.path, dict(self.headers), body))
        # Comme VictoriaMetrics : GET /health → 200 ; POST /api/v2/write → 204 (ou l'erreur simulée)
        code = type(self).status if self.command == "POST" or type(self).status >= 400 else 200
        self.send_response(code)
        self.end_headers()

    do_GET = do_POST = _reply

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Recorder.status, Recorder.requests = 204, []
    httpd = HTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()


def config(port, **extra):
    db = {"DB_UID": "VM_LAB", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "127.0.0.1",
          "DB_PORT": str(port), "DB_SERVER_USE_SSL": False, **extra}
    return {"DATABASE": [db]}


def test_line_protocol_escapes_and_types():
    p = dict(POINT, tags=dict(POINT["tags"], MESH_GROUP="A B,C=D"))
    line = vm.to_line_protocol([p])
    assert line.startswith("SYNTRAF,")
    assert "MESH_GROUP=A\\ B\\,C\\=D" in line
    assert "RX_PACKET_TOTAL=57i" in line and "RX_PACKET_LOSS=0i" in line
    assert "RX_BITRATE=99.5" in line
    assert line.endswith(f" {NS}")


def test_line_protocol_parses_str_datetime_with_space():
    assert vm.to_line_protocol([POINT]).rsplit(" ", 1)[1] == str(NS)


def test_line_protocol_accepts_datetime_and_int():
    dt = datetime(2026, 11, 20, 12, 0, 1, tzinfo=timezone.utc)
    assert vm.to_line_protocol([dict(POINT, time=dt)]).endswith(f" {NS}")
    assert vm.to_line_protocol([dict(POINT, time=NS)]).endswith(f" {NS}")


def test_health_check_sets_online(server):
    obj = vm.VictoriaMetricsObj(config(server.server_port), "VM_LAB")
    assert obj.status == "ONLINE"
    assert ("GET", "/health") == Recorder.requests[0][:2]


def test_save_returns_ok_on_204_and_posts_to_api_v2_write(server):
    obj = vm.VictoriaMetricsObj(config(server.server_port), "VM_LAB")
    assert obj.save_metrics_to_database_with_buffer([POINT, POINT], ("1.2.3.4", 1), "LAB_C1") == "OK"
    method, path, _headers, body = Recorder.requests[-1]
    assert method == "POST" and path.startswith("/api/v2/write")
    assert len(body.strip().splitlines()) == 2


def test_save_returns_error_on_500_and_sets_offline(server):
    obj = vm.VictoriaMetricsObj(config(server.server_port), "VM_LAB")
    Recorder.status = 500
    assert obj.save_metrics_to_database_with_buffer([POINT], ("1.2.3.4", 1), "LAB_C1") == "ERROR"
    assert obj.status == "OFFLINE"


def test_save_returns_error_when_unreachable():
    obj = vm.VictoriaMetricsObj(config(1), "VM_LAB")
    assert obj.status == "OFFLINE"
    assert obj.save_metrics_to_database_with_buffer([POINT], ("1.2.3.4", 1), "LAB_C1") == "ERROR"


def test_bearer_token_sent_when_configured(server):
    obj = vm.VictoriaMetricsObj(config(server.server_port, DB_TOKEN="secret-lab"), "VM_LAB")
    obj.save_metrics_to_database_with_buffer([POINT], ("1.2.3.4", 1), "LAB_C1")
    assert Recorder.requests[-1][2].get("Authorization") == "Bearer secret-lab"


def test_force_status_check_recovers(server):
    obj = vm.VictoriaMetricsObj(config(server.server_port), "VM_LAB")
    obj.status = "OFFLINE"
    obj.force_status_check()
    assert obj.status == "ONLINE"
    assert obj.get_Database_UID() == "VM_LAB"


def test_write_queue_exists_for_webui(server):
    # La page d'accueil lit database.write_queue.queue (GET_LIST_OF_DATABASES_INFOS).
    obj = vm.VictoriaMetricsObj(config(server.server_port), "VM_LAB")
    assert len(obj.write_queue.queue) == 0


def test_non_finite_values_are_dropped_not_sent():
    p = dict(POINT, fields=dict(POINT["fields"], RX_JITTER=float("nan"), RX_BITRATE=float("inf")))
    line = vm.to_line_protocol([p])
    assert "nan" not in line.lower() and "inf" not in line.lower()
    assert "RX_PCT_LOSS=0.0" in line


def test_point_without_finite_field_is_skipped():
    p = dict(POINT, fields={"RX_JITTER": float("nan")})
    assert vm.to_line_protocol([p, POINT]).count("\n") == 0  # une seule ligne : le point valide


def test_health_check_on_non_http_service_is_offline():
    import socket
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def garbage():
        conn, _ = srv.accept()
        conn.recv(1024)
        conn.sendall(b"PAS DU HTTP\r\n\r\n")
        conn.close()

    threading.Thread(target=garbage, daemon=True).start()
    obj = vm.VictoriaMetricsObj(config(srv.getsockname()[1]), "VM_LAB")
    assert obj.status == "OFFLINE"
    srv.close()

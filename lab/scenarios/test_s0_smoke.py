"""S0 — fumée : le lab démarre, tous les flux écrivent, la webui répond, aucun traceback."""
import urllib.error
import urllib.request

from lablib import docker, topology


def urlopen_status(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_s0_all_flows_write(lab_up, metrics):
    for flow in topology.expected_flows():
        assert metrics.last_point_time(flow) is not None, flow


def test_s0_webui_answers(lab_up):
    assert urlopen_status("http://127.0.0.1:18080/") in (200, 302)


def test_s0_no_traceback_in_logs(lab_up):
    for svc in topology.SYNTRAF_NODES:
        assert "Traceback" not in docker.compose(["logs", "--no-color", svc]).stdout, svc


def test_s0_client_status_api(lab_up):
    """L'API qui rafraîchit la page de statut des clients répond, avec les 4 clients connectés."""
    import json
    req = urllib.request.Request("http://127.0.0.1:18080/api", data=b"ACTION=GET_SYSTEM_STATS",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        clients = {uid: json.loads(v) for uid, v in json.loads(resp.read().decode()).items()}
    for uid in topology.CLIENT_UID.values():
        assert "CONNECTED" in clients[uid]["status"], (uid, clients[uid]["status"])

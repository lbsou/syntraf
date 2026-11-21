"""S0 (Grafana) — Grafana répond, la source VictoriaMetrics est saine, le tableau de bord existe."""
import base64
import json
import urllib.request

from lablib import health

GRAFANA = "http://127.0.0.1:18300"


def get_json(path: str):
    """Requête authentifiée avec le compte admin factice du lab (lab.env)."""
    pwd = health.read_env()["GRAFANA_ADMIN_PASSWORD"]
    auth = base64.b64encode(f"admin:{pwd}".encode()).decode()
    req = urllib.request.Request(GRAFANA + path, headers={"Authorization": f"Basic {auth}"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, json.loads(resp.read().decode() or "null")


def test_grafana_answers(lab_up):
    status, body = get_json("/api/health")
    assert status == 200 and body["database"] == "ok"


def test_grafana_datasource_healthy(lab_up):
    status, body = get_json("/api/datasources/uid/syntraf-vm/health")
    assert status == 200 and body["status"] == "OK"


def test_matrix_dashboard_provisioned(lab_up):
    status, body = get_json("/api/dashboards/uid/syntraf-matrix")
    assert status == 200
    tables = [p for p in body["dashboard"]["panels"] if p["type"] == "table"]
    assert len(tables) >= 4
    for p in tables:
        matrix = p["transformations"][-1]
        assert matrix["id"] == "groupingToMatrix", p["title"]
        assert (matrix["options"]["rowField"], matrix["options"]["columnField"]) == ("CLIENT", "SERVER")


def test_dashboard_provisioned(lab_up):
    status, body = get_json("/api/dashboards/uid/syntraf-lab")
    assert status == 200
    titles = [p.get("title") for p in body["dashboard"]["panels"]]
    assert any("Pertes" in (t or "") for t in titles)

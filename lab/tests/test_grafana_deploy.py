"""Déploiement des tableaux de bord et de la source VictoriaMetrics dans un Grafana (lib/st_grafana_deploy.py)."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_grafana_deploy as gd  # noqa: E402


class FakeGrafana:
    """API HTTP de Grafana réduite : sources de données, dossiers, tableaux de bord."""

    def __init__(self, token="tok", existing_ds=False, existing_folder=False):
        self.token, self.calls = token, []
        self.ds = {"syntraf-vm": {"uid": "syntraf-vm"}} if existing_ds else {}
        self.folders = {"syntraf": {"uid": "syntraf"}} if existing_folder else {}
        self.dashboards = {}

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        if headers.get("Authorization") != f"Bearer {self.token}":
            return 401, {"message": "Unauthorized"}
        path = url.split("://", 1)[1].split("/", 1)[1]
        data = json.loads(body) if body else None
        if path == "api/health":
            return 200, {"version": "13.0.2", "database": "ok"}
        if path == "api/search?limit=1":
            return 200, []
        if path.startswith("api/datasources/uid/"):
            uid = path.rsplit("/", 1)[1]
            if method == "GET":
                return (200, self.ds[uid]) if uid in self.ds else (404, {"message": "not found"})
            self.ds[uid] = data
            return 200, {"message": "updated"}
        if path == "api/datasources" and method == "POST":
            self.ds[data["uid"]] = data
            return 200, {"message": "added"}
        if path.startswith("api/folders/"):
            uid = path.rsplit("/", 1)[1]
            return (200, self.folders[uid]) if uid in self.folders else (404, {"message": "not found"})
        if path == "api/folders" and method == "POST":
            self.folders[data["uid"]] = data
            return 200, data
        if path == "api/dashboards/db" and method == "POST":
            d = data["dashboard"]
            status = "updated" if d["uid"] in self.dashboards else "created"
            self.dashboards[d["uid"]] = data
            return 200, {"status": "success", "uid": d["uid"], "url": f"/d/{d['uid']}", "_s": status}
        return 404, {"message": f"unknown {method} {path}"}


SETTINGS = {"URL": "https://grafana.example.com", "TOKEN": "tok", "FOLDER": "SYNTRAF",
            "DATASOURCE_URL": "http://vm.example.com:8428", "VERIFY_TLS": True}


def test_a_first_deployment_creates_the_datasource_the_folder_and_every_dashboard():
    g = FakeGrafana()
    r = gd.deploy(SETTINGS, http=g)
    assert r["datasource"] == "created" and r["folder"] == "created"
    assert g.ds["syntraf-vm"]["url"] == "http://vm.example.com:8428" and g.ds["syntraf-vm"]["type"] == "prometheus"
    assert len(r["dashboards"]) == 7 and all(d["status"] == "deployed" for d in r["dashboards"])
    sample = next(iter(g.dashboards.values()))
    assert sample["folderUid"] == "syntraf" and sample["overwrite"] is True and sample["dashboard"].get("id") is None


def test_a_second_deployment_updates_in_place():
    g = FakeGrafana(existing_ds=True, existing_folder=True)
    r = gd.deploy(SETTINGS, http=g)
    assert r["datasource"] == "updated" and r["folder"] == "exists"
    assert ("PUT", "https://grafana.example.com/api/datasources/uid/syntraf-vm") in g.calls


def test_a_dry_run_only_reads():
    g = FakeGrafana()
    r = gd.deploy(SETTINGS, http=g, dry_run=True)
    assert r["datasource"] == "would be created" and all(d["status"] == "would be deployed" for d in r["dashboards"])
    assert all(m == "GET" for m, _ in g.calls)


def test_a_wrong_token_is_reported_without_deploying_anything():
    with pytest.raises(gd.GrafanaError) as err:
        gd.deploy(dict(SETTINGS, TOKEN="bad"), http=FakeGrafana())
    assert "token" in str(err.value).lower()


def test_the_connection_test_gives_the_grafana_version():
    assert gd.test(SETTINGS, http=FakeGrafana())["version"] == "13.0.2"


def test_the_datasource_url_defaults_to_the_first_victoriametrics_database():
    config = {"DATABASE": [{"DB_UID": "INFLUX", "DB_ENGINE": "InfluxDB"},
                           {"DB_UID": "VM", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "10.1.2.3", "DB_PORT": "8428",
                            "DB_SERVER_USE_SSL": False}]}
    assert gd.default_datasource_url(config) == "http://10.1.2.3:8428"
    assert gd.default_datasource_url({}) == ""

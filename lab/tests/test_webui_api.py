"""Webui : API REST v1, /healthz, /metrics, flux d'événements, journaux et rendu de chaque page.

Client de test Flask sur la vraie application (create_app), avec des objets serveur simulés.
Tourne dans l'image du lab (dépendances de SYNTRAF), comme test_config_generation.py.
"""
import datetime as dt
import queue
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib.st_conf_validation import validate_group, generate_client_config_mesh
    from lib.web_ui_kindafixed2 import create_app
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


class FakeClient:
    def __init__(self, status):
        self.status = status
        self.status_since = dt.datetime(2026, 11, 21, 10, 0, 0)
        self.status_explanation = "test"
        self.ip_address = "10.0.0.1"
        self.syntraf_version = "test"
        self.clock_skew_in_seconds = 0
        self.system_infos = {}
        self.thread_status = {}

    def asjson(self):
        return "{}"


class FakeDb:
    DB_UID = "VM1"
    status = "ONLINE"
    status_time = dt.datetime(2026, 11, 21, 10, 0, 0)

    def __init__(self):
        self.write_queue = queue.Queue()

    def force_status_check(self):
        pass


class FakeThread:
    def __init__(self, name, kind, alive=True):
        self.name, self.syntraf_instance_type, self.alive = name, kind, alive

    def getstatus(self):
        return self.alive


DISK = {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100", "TOKEN": {"T1": "tok"}}, "GLOBAL": {},
        "MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"},
                       {"UID": "SPARE", "BANDWIDTH": "10K", "DSCP": "0", "PACKET_SIZE": "100", "INTERVAL": "1"}],
        "SERVER_CLIENT": [{"UID": u, "IP_ADDRESS": ip, "MESH_GROUP_UID_LIST": ["GROUP1"]}
                          for u, ip in (("NODE_A", "10.0.0.1"), ("NODE_B", "0.0.0.0"))],
        "DATABASE": []}


@pytest.fixture
def env(tmp_path):
    logdir = tmp_path / "logs"
    logdir.mkdir()
    (logdir / "syntraf.log").write_text(" 2026-11-21 10:00:00 - INFO - a (f,1) - hello\n"
                                        " 2026-11-21 10:00:01 - ERROR - a (f,2) - broken pipe\n")
    disk = dict(DISK, GLOBAL={"LOGDIR": str(logdir)})
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(disk))
    live = toml.loads(path.read_text())
    assert validate_group(live, "MESH_GROUP")
    generated = {}
    _, tuples = generate_client_config_mesh(live, generated)
    threads = [FakeThread("SERVER", "SERVER"), FakeThread("WEBUI", "WEBUI")]
    clients = {"NODE_A": FakeClient("CONNECTED"), "NODE_B": FakeClient("DISCONNECTED")}
    app = create_app(threads, {}, generated, tuples, {}, live, str(path), [FakeDb()], {}, clients)
    app.config["TESTING"] = True
    return {"client": app.test_client(), "app": app, "path": path, "threads": threads}


def test_list_mesh_groups(env):
    r = env["client"].get("/api/v1/mesh-groups")
    assert r.status_code == 200
    assert [g["UID"] for g in r.json] == ["GROUP1", "SPARE"]


def test_invalid_update_returns_field_errors(env):
    r = env["client"].put("/api/v1/mesh-groups/GROUP1", json={"BANDWIDTH": "x", "DSCP": "0", "PACKET_SIZE": "218",
                                                                "INTERVAL": "1"})
    assert r.status_code == 400
    assert list(r.json["error"]["fields"]) == ["BANDWIDTH"]


def test_dry_run_update_previews_without_writing(env):
    before = env["path"].read_text()
    r = env["client"].put("/api/v1/mesh-groups/GROUP1?dry_run=1",
                          json={"BANDWIDTH": "120K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"})
    assert r.status_code == 200
    assert '+BANDWIDTH = "120K"' in r.json["diff"]
    assert env["path"].read_text() == before


def test_update_is_audited_with_the_caller_address(env):
    c = env["client"]
    r = c.put("/api/v1/mesh-groups/GROUP1", json={"BANDWIDTH": "120K", "DSCP": "0", "PACKET_SIZE": "218",
                                                  "INTERVAL": "1"})
    assert r.status_code == 200
    assert r.json["reconnected_clients"] == ["NODE_A"]
    [entry] = c.get("/api/v1/audit").json
    assert (entry["actor"], entry["action"]) == ("127.0.0.1", "UPDATE_MESH_GROUP")


def test_patch_disables_and_delete_in_use_conflicts(env):
    c = env["client"]
    assert c.patch("/api/v1/mesh-groups/GROUP1", json={"DISABLED": True}).status_code == 200
    assert c.get("/api/v1/mesh-groups/GROUP1").json["DISABLED"] is True
    assert c.patch("/api/v1/mesh-groups/GROUP1", json={"DISABLED": "maybe"}).status_code == 400
    r = c.delete("/api/v1/mesh-groups/GROUP1")
    assert r.status_code == 409
    assert "NODE_A" in r.json["error"]["message"]
    assert c.delete("/api/v1/mesh-groups/SPARE").status_code == 200
    assert c.get("/api/v1/mesh-groups/SPARE").status_code == 404


def test_create_and_duplicate_return_201(env):
    c = env["client"]
    r = c.post("/api/v1/mesh-groups", json={"UID": "NEWGRP", "BANDWIDTH": "50K", "DSCP": "0", "PACKET_SIZE": "100",
                                            "INTERVAL": "1"})
    assert r.status_code == 201
    assert c.post("/api/v1/mesh-groups/NEWGRP/duplicate").json["uid"] == "NEWGRP_COPY"


def test_versions_diff_and_restore(env):
    c = env["client"]
    c.patch("/api/v1/mesh-groups/GROUP1", json={"DISABLED": True})
    versions = c.get("/api/v1/config/versions").json
    original = versions[-1]["version"]
    assert "DISABLED = true" in c.get(f"/api/v1/config/versions/{original}/diff").get_data(as_text=True)
    r = c.post(f"/api/v1/config/versions/{original}/restore")
    assert r.status_code == 200
    assert c.get("/api/v1/mesh-groups/GROUP1").json["DISABLED"] is False
    assert c.get("/api/v1/config/versions/nope.toml").status_code == 404


def test_healthz_reports_dead_core_threads(env):
    assert env["client"].get("/healthz").status_code == 200
    env["threads"][0].alive = False
    r = env["client"].get("/healthz")
    assert r.status_code == 503
    assert r.json["checks"]["threads"]["dead"] == ["SERVER"]


def test_metrics_exposes_clients_and_databases(env):
    text = env["client"].get("/metrics").get_data(as_text=True)
    assert 'syntraf_client_connected{client="NODE_A"} 1' in text
    assert 'syntraf_client_connected{client="NODE_B"} 0' in text
    assert 'syntraf_database_up{database="VM1"} 1' in text


def test_status_and_events_stream(env):
    snap = env["client"].get("/api/v1/status").json
    assert snap["clients_summary"] == {"total": 2, "connected": 1, "disconnected": 1}
    assert [c["dynamic_ip"] for c in snap["clients"]] == [False, True]
    r = env["client"].get("/api/v1/events?max=1")
    assert r.mimetype == "text/event-stream"
    assert "event: status" in r.get_data(as_text=True)


def test_logs_filter_by_level_and_refuse_unknown_files(env):
    c = env["client"]
    assert [f["name"] for f in c.get("/api/v1/logs").json] == ["syntraf.log"]
    text = c.get("/api/v1/logs/syntraf.log?level=ERROR").get_data(as_text=True)
    assert "broken pipe" in text and "hello" not in text
    assert "hello" in c.get("/api/v1/logs/syntraf.log?q=HELLO").get_data(as_text=True)
    assert c.get("/api/v1/logs/..%2Fconfig.toml").status_code == 404


def test_openapi_lists_the_mesh_group_routes(env):
    assert "/api/v1/mesh-groups/{uid}" in env["client"].get("/api/v1/openapi.json").json["paths"]


@pytest.mark.parametrize("page", ["/home.html", "/stats.html", "/mesh_group_config.html", "/token_config.html",
                                  "/log_viewer.html", "/server.html", "/client_config.html",
                                  "/database_config.html", "/audit.html", "/profile_config.html", "/data.html",
                                  "/updates.html"])
def test_every_page_renders(env, page):
    assert env["client"].get(page).status_code == 200


def test_server_page_never_contains_secrets(env):
    server = env["app"].config["config"]["SERVER"]
    server["RSA_KEY_LISTENERS"] = b"-----BEGIN PRIVATE KEY-----secret"
    server["IPERF3_PASSWORD"] = "hunter2"
    html = env["client"].get("/server.html").get_data(as_text=True)
    assert "BEGIN PRIVATE KEY" not in html and "hunter2" not in html
    assert "hunter2" not in env["client"].get("/api/v1/config/global").get_data(as_text=True)


def test_global_settings_api(env):
    c = env["client"]
    assert "WATCHDOG_CHECK_RATE" in c.get("/api/v1/config/global").json
    r = c.put("/api/v1/config/global", json={"WATCHDOG_CHECK_RATE": "0"})
    assert r.status_code == 400 and "WATCHDOG_CHECK_RATE" in r.json["error"]["fields"]


def test_version_view_and_diffs_hide_tokens(env):
    c = env["client"]
    c.patch("/api/v1/mesh-groups/GROUP1?dry_run=1", json={"DISABLED": True})
    c.patch("/api/v1/mesh-groups/GROUP1", json={"DISABLED": True})
    original = c.get("/api/v1/config/versions").json[-1]["version"]
    assert 'T1 = "tok"' not in c.get(f"/api/v1/config/versions/{original}").get_data(as_text=True)
    assert "T1 = " in c.get(f"/api/v1/config/versions/{original}").get_data(as_text=True)


def test_client_declarations_can_be_created_edited_and_removed(env):
    c = env["client"]
    body = {"UID": "NODE_C", "IP_ADDRESS": "10.0.0.3", "MESH_GROUP_UID_LIST": ["GROUP1"]}
    assert c.post("/api/v1/config/clients?dry_run=1", json=body).json["affected_clients"] == ["NODE_A", "NODE_B", "NODE_C"]
    assert c.post("/api/v1/config/clients", json=body).status_code == 201
    r = c.put("/api/v1/config/clients/NODE_C", json=dict(body, IP_ADDRESS="bad ip!"))
    assert r.status_code == 400 and list(r.json["error"]["fields"]) == ["IP_ADDRESS"]
    assert c.put("/api/v1/config/clients/NODE_C", json=dict(body, MAX_BANDWIDTH="5M")).status_code == 200
    assert c.get("/api/v1/config/clients/NODE_C").json["MAX_BANDWIDTH"] == "5M"
    assert c.delete("/api/v1/config/clients/NODE_C").status_code == 200
    assert c.get("/api/v1/config/clients/NODE_C").status_code == 404


def test_database_declarations_never_expose_the_token(env):
    class Conn:
        def __init__(self, config, uid):
            self.DB_UID, self.status, self.status_time = uid, "ONLINE", dt.datetime(2026, 11, 21)
            self.write_queue = queue.Queue()
    env["app"].config["db_factory"] = Conn
    c = env["client"]
    body = {"DB_UID": "VM_TWO", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "10.0.0.20", "DB_PORT": "8428",
            "DB_TOKEN": "t0psecret"}
    assert c.post("/api/v1/config/databases/test", json=body).json["status"] == "ONLINE"
    r = c.post("/api/v1/config/databases", json=body)
    assert r.status_code == 201 and "t0psecret" not in r.get_data(as_text=True)
    listed = c.get("/api/v1/config/databases").get_data(as_text=True)
    assert "t0psecret" not in listed and '"DB_TOKEN_SET":true' in listed.replace(" ", "")
    assert "VM_TWO" in [d["uid"] for d in c.get("/api/v1/databases").json]


def test_data_page_api_status_snapshots_and_audited_purge(env):
    calls = []

    class FakeAdmin:
        def __init__(self, db):
            self.db = db

        def status(self):
            return {"uid": self.db["DB_UID"], "retention": "30d", "retention_target": None, "retention_matches": None}

        def snapshots(self):
            return ["s1"]

        def orphans(self, clients, groups):
            return {"clients": sorted({"OLD_C9"} - clients), "mesh_groups": []}

        def purge(self, kind, value, dry_run=False):
            calls.append((kind, value, dry_run))
            return {"kind": kind, "value": value, "series": 3, "dry_run": dry_run}

        def create_snapshot(self):
            return "s2"

    app, c = env["app"], env["client"]
    app.config["vm_admin_factory"] = FakeAdmin
    cfg = toml.load(env["path"])
    cfg["DATABASE"] = [{"DB_UID": "VM1", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "10.0.0.10", "DB_PORT": "8428"},
                       {"DB_UID": "INFLUX1", "DB_ENGINE": "InfluxDB2", "DB_SERVER": "10.0.0.11", "DB_PORT": "8086"}]
    env["path"].write_text(toml.dumps(cfg))
    rows = {r["uid"]: r for r in c.get("/api/v1/data").json}
    assert rows["VM1"]["orphans"]["clients"] == ["OLD_C9"] and rows["INFLUX1"]["supported"] is False
    assert c.post("/api/v1/data/VM1/purge?dry_run=1", json={"kind": "client", "value": "OLD_C9"}).json["series"] == 3
    assert c.post("/api/v1/data/VM1/purge", json={"kind": "client", "value": "OLD_C9"}).status_code == 200
    assert calls == [("client", "OLD_C9", True), ("client", "OLD_C9", False)]
    assert c.post("/api/v1/data/VM1/snapshots").json["snapshot"] == "s2"
    assert c.post("/api/v1/data/INFLUX1/snapshots").status_code == 409
    actions = [e["action"] for e in c.get("/api/v1/audit").json]
    assert actions[:2] == ["CREATE_SNAPSHOT", "PURGE_DATA"]


def test_server_settings_and_tokens_api(env):
    c = env["client"]
    server = c.get("/api/v1/config/server").json
    assert "TOKEN" not in server and "tok" not in c.get("/api/v1/config/server").get_data(as_text=True)
    r = c.put("/api/v1/config/server", json={"SERVER_PORT": "7000", "MESH_LISTENERS_PORT_RANGE": "15000-15100"})
    assert r.status_code == 200 and r.json["restart_required"] == ["SERVER.SERVER_PORT"]
    created = c.post("/api/v1/config/tokens", json={"NAME": "site_b"})
    assert created.status_code == 201 and created.json["token"]
    assert created.json["token"] not in c.get("/api/v1/config/tokens").get_data(as_text=True)
    assert c.post("/api/v1/config/tokens/site_b/reveal").json["token"] == created.json["token"]
    assert c.get("/api/v1/audit").json[0]["action"] == "REVEAL_TOKEN"
    assert c.delete("/api/v1/config/tokens/site_b").status_code == 200


def test_log_search_and_logging_settings_api(env):
    c = env["client"]
    logdir = Path(env["app"].config["config"]["GLOBAL"]["LOGDIR"])
    client_dir = logdir / "clients" / "NODE_A"
    client_dir.mkdir(parents=True)
    (client_dir / "syntraf.log").write_text(" 2026-11-21 18:50:00-0500 - WARNING - st_outage (record,1) - OUTAGE A\n")
    assert c.get("/api/v1/logs/nodes").json["nodes"] == ["server", "NODE_A"]
    found = c.get("/api/v1/logs/search?nodes=NODE_A&level=WARNING&q=outage").json
    assert [(e["node"], e["type"], e["time"]) for e in found] == [("NODE_A", "measurement", "2026-11-21T23:50:00+00:00")]
    assert len(c.get("/api/v1/logs/search?types=control").json) == 0
    text = c.get("/api/v1/logs/search?format=text&nodes=NODE_A").get_data(as_text=True)
    assert "[NODE_A] WARNING st_outage" in text
    assert c.get("/api/v1/logs/search?since=yesterday").status_code == 400
    r = c.put("/api/v1/config/logging", json={"LOG_LEVEL": "INFO", "LOG_FORWARD_LEVEL": "WARNING",
                                              "LOG_MAX_SIZE_PER_FILE_MB": "10", "LOG_FILE_TO_KEEP": "5",
                                              "LOG_RETENTION_DAYS": "30"})
    assert r.status_code == 200 and r.json["restart_required"] == []
    assert c.get("/api/v1/config/logging").json["LOG_RETENTION_DAYS"] == "30"


def test_pending_clients_api(env):
    from lib import st_enrollment
    c = env["client"]
    live = env["app"].config["config"]
    live["SERVER"]["TOKEN"] = {"T1": "tok"}
    enrollment = st_enrollment.Enrollment(str(env["path"]) + ".pending.json")
    st_enrollment.authorize(live, {"CLIENT_UID": "NEW_NODE", "TOKEN": "tok", "PUBLIC_KEY": "K"}, "10.0.0.9", enrollment)
    assert c.get("/api/v1/status").json["pending_clients"] == 1
    assert [p["UID"] for p in c.get("/api/v1/clients/pending").json["pending"]] == ["NEW_NODE"]
    r = c.post("/api/v1/clients/pending/NEW_NODE/approve", json={"MESH_GROUP_UID_LIST": ["GROUP1"], "IP_MODE": "dynamic"})
    assert r.status_code == 201
    row = c.get("/api/v1/config/clients/NEW_NODE").json
    assert row["PINNED"] and row["OWN_TOKEN"] and "TOKEN" not in row and row["DYNAMIC"]
    assert c.post("/api/v1/clients/pending/NEW_NODE/reject").status_code == 200
    assert c.delete("/api/v1/clients/rejected/NEW_NODE").status_code == 200


def test_updates_api_lists_the_release_and_sends_it_to_eligible_clients(env, monkeypatch):
    from lib import st_mesh_group_ops as ops
    release = {"id": "0.46+abc", "version": "0.46", "sha256": "f" * 64, "size": 10, "has_wheelhouse": False,
               "path": "x"}
    monkeypatch.setattr(ops, "builtin_release", lambda: release)
    clients = env["app"].config["dict_of_clients"]
    clients["NODE_A"].release_id = "0.45+old"
    c = env["client"]
    overview = c.get("/api/v1/updates").json
    assert overview["release"]["id"] == "0.46+abc"
    assert {r["uid"]: r["stage"] for r in overview["clients"]} == {"NODE_A": "OUTDATED", "NODE_B": "OFFLINE"}
    r = c.post("/api/v1/updates", json={"CLIENTS": ["NODE_A", "NODE_B"]})
    assert r.json["queued"] == ["NODE_A"] and r.json["skipped"] == {"NODE_B": "offline"}
    command = env["app"].config["dict_of_commands_for_network_clients"]["NODE_A"][-1]
    assert command["ACTION"] == "UPDATE" and command["RELEASE"] == "0.46+abc"
    assert c.get("/api/v1/audit").json[0]["action"] == "REQUEST_UPDATE"
    assert c.post("/api/v1/updates", json={}).status_code == 400


def test_large_changes_need_confirm_through_the_api(env):
    c = env["client"]
    c.put("/api/v1/config/server", json={"MESH_LISTENERS_PORT_RANGE": "15000-15100", "FLOW_ALERT_ADDED": "1"})
    body = {"UID": "NODE_C", "IP_ADDRESS": "10.0.0.3", "MESH_GROUP_UID_LIST": ["GROUP1"]}  # 2 -> 6 flux
    preview = c.post("/api/v1/config/clients?dry_run=1", json=body).json
    assert preview["impact"]["alert"] is True and preview["impact"]["flows_after"] == 6
    assert c.post("/api/v1/config/clients", json=body).status_code == 428
    assert c.post("/api/v1/config/clients?confirm=1", json=body).status_code == 201


def test_syslog_api(env):
    c = env["client"]
    assert "STATUS" in c.get("/api/v1/config/syslog").json
    assert c.put("/api/v1/config/syslog", json={"SYSLOG_HOST": "bad host!"}).status_code == 400
    assert c.post("/api/v1/logging/syslog/test").status_code == 409

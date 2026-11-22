"""Administration des données dans VictoriaMetrics (lib/st_vm_admin.py) : état, rétention, instantanés, purge.

Transport HTTP simulé : aucun VictoriaMetrics nécessaire.
"""
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from lib import st_vm_admin as vm  # noqa: E402
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)

METRICS = """vm_free_disk_space_bytes{path="/storage"} 1000
vm_data_size_bytes{type="storage/small"} 300
vm_data_size_bytes{type="indexdb/file"} 20
vm_rows{type="storage/small"} 5000
"""
NOW = 1_800_000_000


class FakeVm:
    def __init__(self, retention="30d", days_with_data=(3, 2, 1), series=None):
        self.retention, self.days, self.calls = retention, days_with_data, []
        self.series = series or [{"CLIENT": "LAB_C1", "SERVER": "LAB_C2", "MESH_GROUP": "LAB_MESH"},
                                 {"CLIENT": "OLD_C9", "SERVER": "LAB_C1", "MESH_GROUP": "OLD_GROUP"}]
        self.snapshots = ["20261120-snap"]

    def __call__(self, method, path, params=None):
        self.calls.append((method, path, params))
        if path == "/flags":
            return 200, f'-retentionPeriod="{self.retention}"\n-storageDataPath="/storage"\n'
        if path == "/metrics":
            return 200, METRICS
        if path == "/api/v1/query_range":
            values = [[NOW - d * 86400, "4"] for d in sorted(self.days, reverse=True)]
            return 200, json.dumps({"status": "success", "data": {"result": [{"values": values}] if values else []}})
        if path.startswith("/api/v1/label/"):
            label = path.split("/")[4]
            return 200, json.dumps({"status": "success", "data": sorted({s[label] for s in self.series})})
        if path == "/api/v1/series":
            selectors = [dict(re.findall(r'(\w+)="([^"]*)"', m)) for m in params["match[]"]]
            matched = [s for s in self.series
                       if any(all(s.get(k) == v for k, v in sel.items() if k != "__name__") for sel in selectors)]
            return 200, json.dumps({"status": "success", "data": matched})
        if path == "/api/v1/admin/tsdb/delete_series":
            return 204, ""
        if path == "/snapshot/list":
            return 200, json.dumps({"status": "ok", "snapshots": self.snapshots})
        if path == "/snapshot/create":
            self.snapshots.append("20261121-new")
            return 200, json.dumps({"status": "ok", "snapshot": "20261121-new"})
        if path == "/snapshot/delete":
            self.snapshots.remove(params["snapshot"])
            return 200, json.dumps({"status": "ok"})
        return 404, ""


def admin(fake, target=None):
    db = {"DB_UID": "VM1", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "10.0.0.10", "DB_PORT": "8428"}
    if target:
        db["DB_RETENTION"] = target
    return vm.VmAdmin(db, http=fake, now=lambda: NOW)


def test_status_reports_retention_disk_and_oldest_data():
    st = admin(FakeVm(), target="30d").status()
    assert st["retention"] == "30d" and st["retention_target"] == "30d" and st["retention_matches"] is True
    assert st["data_size_bytes"] == 320 and st["free_disk_bytes"] == 1000 and st["rows"] == 5000
    assert st["oldest_day"] == NOW - 3 * 86400


def test_retention_mismatch_explains_how_to_fix_it():
    st = admin(FakeVm(retention="30d"), target="1y").status()
    assert st["retention_matches"] is False
    assert "-retentionPeriod=1y" in st["retention_advice"]


def test_no_target_means_nothing_to_compare():
    st = admin(FakeVm()).status()
    assert st["retention_target"] is None and st["retention_matches"] is None


def test_orphans_are_label_values_no_longer_declared():
    orphans = admin(FakeVm()).orphans(clients={"LAB_C1", "LAB_C2"}, mesh_groups={"LAB_MESH"})
    assert orphans == {"clients": ["OLD_C9"], "mesh_groups": ["OLD_GROUP"]}


def test_purge_of_a_client_matches_it_as_sender_and_receiver():
    fake = FakeVm()
    dry = admin(fake).purge("client", "LAB_C1", dry_run=True)
    assert dry["series"] == 2 and not any(c[1].endswith("delete_series") for c in fake.calls)
    done = admin(fake).purge("client", "LAB_C1")
    assert done["series"] == 2
    [delete] = [c for c in fake.calls if c[1].endswith("delete_series")]
    assert delete[0] == "POST" and delete[2]["match[]"] == ['{__name__=~"SYNTRAF_.*",CLIENT="LAB_C1"}',
                                                            '{__name__=~"SYNTRAF_.*",SERVER="LAB_C1"}']


def test_purge_refuses_unsafe_values():
    with pytest.raises(ValueError):
        admin(FakeVm()).purge("client", 'x"}or{a="b')
    with pytest.raises(ValueError):
        admin(FakeVm()).purge("everything", "LAB_C1")


def test_snapshots_are_listed_created_and_deleted():
    fake = FakeVm()
    a = admin(fake)
    assert a.snapshots() == ["20261120-snap"]
    assert a.create_snapshot() == "20261121-new"
    a.delete_snapshot("20261120-snap")
    assert a.snapshots() == ["20261121-new"]
    with pytest.raises(ValueError):
        a.delete_snapshot("../../etc")


# ---------------------------------------------------------------------------------- renommage d'un client

class FakeVmData:
    """Export / import / delete_series sur quelques séries en mémoire."""

    def __init__(self):
        self.series = [
            {"metric": {"__name__": "SYNTRAF_RX_PCT_LOSS", "CLIENT": "LAB_C4", "SERVER": "LAB_C1",
                        "UID": "LAB_C4__TO__LAB_C1__ON__DSCP0", "MESH_GROUP": "M"},
             "values": [0, 2], "timestamps": [(NOW - 100) * 1000, (NOW - 50) * 1000]},
            {"metric": {"__name__": "SYNTRAF_GROUP_INFO", "MESH_GROUP": "M", "HUBS": "LAB_C1, LAB_C4"},
             "values": [1], "timestamps": [(NOW - 3 * 86400) * 1000]},
        ]
        self.imported, self.deleted, self.exports = [], [], 0

    def __call__(self, method, path, params=None, body=None):
        if path == "/flags":
            return 200, '-retentionPeriod="7d"\n'
        if path == "/api/v1/export":
            self.exports += 1
            start, end = float(params["start"]) * 1000, float(params["end"]) * 1000
            out = []
            for s in self.series:
                keep = [(v, t) for v, t in zip(s["values"], s["timestamps"]) if start <= t <= end]
                if keep:
                    out.append(json.dumps({"metric": s["metric"], "values": [v for v, _ in keep],
                                           "timestamps": [t for _, t in keep]}))
            return 200, "\n".join(out)
        if path == "/api/v1/import":
            self.imported += [json.loads(line) for line in body.splitlines() if line.strip()]
            return 204, ""
        if path == "/api/v1/admin/tsdb/delete_series":
            self.deleted.append(params["match[]"])
            return 204, ""
        raise AssertionError(path)


def test_renaming_a_node_rewrites_its_history_then_deletes_the_old_series():
    fake = FakeVmData()
    admin = vm.VmAdmin({"DB_UID": "VM", "DB_SERVER": "vm", "DB_PORT": "8428"}, http=fake, now=lambda: NOW)
    result = admin.rename_node("LAB_C4", "STARLINK")
    assert fake.exports == 8 * 24  # rétention de 7 jours (+ un jour), une heure par requête : mémoire bornée
    by_name = {s["metric"]["__name__"]: s for s in fake.imported}
    loss = by_name["SYNTRAF_RX_PCT_LOSS"]["metric"]
    assert (loss["CLIENT"], loss["SERVER"], loss["UID"]) == ("STARLINK", "LAB_C1", "STARLINK__TO__LAB_C1__ON__DSCP0")
    assert by_name["SYNTRAF_RX_PCT_LOSS"]["values"] == [0, 2]
    assert by_name["SYNTRAF_GROUP_INFO"]["metric"]["HUBS"] == "LAB_C1, STARLINK"
    assert len(fake.deleted) == 1 and any('CLIENT="LAB_C4"' in m for m in fake.deleted[0])
    assert result["points"] == 3


def test_rename_labels_only_touches_exact_names():
    m = {"__name__": "X", "CLIENT": "LAB_C4X", "SERVER": "LAB_C4", "UID": "LAB_C4X__TO__LAB_C4__ON__DSCP0"}
    out = vm.rename_labels(m, "LAB_C4", "STARLINK")
    assert out == {"__name__": "X", "CLIENT": "LAB_C4X", "SERVER": "STARLINK", "UID": "LAB_C4X__TO__STARLINK__ON__DSCP0"}


def test_imports_are_split_by_size():
    fake = FakeVmData()
    fake.series[0]["values"] = list(range(300))
    fake.series[0]["timestamps"] = [(NOW - 1000 + i) * 1000 for i in range(300)]
    bodies = []
    original = fake.__call__

    def spy(method, path, params=None, body=None):
        if path == "/api/v1/import":
            bodies.append(len(body.encode()))
        return original(method, path, params, body)

    admin = vm.VmAdmin({"DB_UID": "VM", "DB_SERVER": "vm", "DB_PORT": "8428"}, http=spy, now=lambda: NOW)
    result = admin.rename_node("LAB_C4", "STARLINK", max_import_bytes=2000)
    assert len(bodies) > 1 and max(bodies) <= 2000 + 400  # au plus un morceau de série au-delà du plafond
    assert result["points"] == 301 and sum(len(s["values"]) for s in fake.imported) == 301

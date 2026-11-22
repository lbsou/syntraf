"""Administration des données dans VictoriaMetrics (lib/st_vm_admin.py) : état, rétention, instantanés, purge.

Transport HTTP simulé : aucun VictoriaMetrics nécessaire.
"""
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_vm_admin as vm  # noqa: E402

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

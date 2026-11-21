"""Écriture du fichier de configuration : historique des versions et journal d'audit (lib/st_config_store.py)."""
import datetime as dt

import pytest

toml = pytest.importorskip("toml")
from lib import st_config_store as store  # noqa: E402


def t(second):
    return dt.datetime(2026, 11, 21, 10, 0, second, tzinfo=dt.timezone.utc)


@pytest.fixture
def path(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(toml.dumps({"MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "100K"}]}))
    return str(p)


def test_save_writes_the_new_config(path):
    store.save(path, {"MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "120K"}]}, "10.0.0.5", "EDIT_MESH_GROUP",
               "GROUP1 edited", now=t(1))
    assert toml.load(path)["MESH_GROUP"][0]["BANDWIDTH"] == "120K"


def test_first_save_keeps_the_original_as_a_version(path):
    original = open(path).read()
    store.save(path, {"MESH_GROUP": []}, "10.0.0.5", "DELETE_MESH_GROUPS", "GROUP1 deleted", now=t(1))
    versions = store.versions(path)
    assert len(versions) == 2
    assert store.read_version(path, versions[-1]["version"]) == original


def test_audit_entry_records_who_what_and_the_diff(path):
    store.save(path, {"MESH_GROUP": [{"UID": "GROUP1", "BANDWIDTH": "120K"}]}, "10.0.0.5", "EDIT_MESH_GROUP",
               "GROUP1 edited", now=t(1))
    [entry] = store.audit_entries(path)
    assert entry["actor"] == "10.0.0.5"
    assert entry["action"] == "EDIT_MESH_GROUP"
    assert entry["summary"] == "GROUP1 edited"
    assert '-BANDWIDTH = "100K"' in entry["diff"]
    assert '+BANDWIDTH = "120K"' in entry["diff"]
    assert entry["version"] == store.versions(path)[0]["version"]


def test_audit_entries_are_newest_first_and_limited(path):
    for i in range(3):
        store.save(path, {"N": i}, "a", "ACT", f"change {i}", now=t(i + 1))
    entries = store.audit_entries(path, limit=2)
    assert [e["summary"] for e in entries] == ["change 2", "change 1"]


def test_versions_saved_in_the_same_instant_do_not_overwrite_each_other(path):
    store.save(path, {"N": 1}, "a", "ACT", "one", now=t(1))
    store.save(path, {"N": 2}, "a", "ACT", "two", now=t(1))
    assert len({v["version"] for v in store.versions(path)}) == 3


def test_read_version_refuses_names_outside_the_history(path):
    store.save(path, {"N": 1}, "a", "ACT", "one", now=t(1))
    with pytest.raises(KeyError):
        store.read_version(path, "../config.toml")


def test_history_is_pruned_to_its_limit(path, monkeypatch):
    monkeypatch.setattr(store, "HISTORY_LIMIT", 3)
    for i in range(5):
        store.save(path, {"N": i}, "a", "ACT", str(i), now=t(i + 1))
    versions = store.versions(path)
    assert len(versions) == 3
    assert toml.loads(store.read_version(path, versions[0]["version"])) == {"N": 4}


def test_redact_masks_secret_keys_and_whole_secret_sections():
    text = ('[SERVER]\nPORT = 6666\nIPERF3_PASSWORD = "hunter2"\n\n[SERVER.TOKEN]\nsite_a = "abc123"\n\n'
            '[GLOBAL]\nLOGDIR = "/logs"\n')
    red = store.redact(text)
    assert "hunter2" not in red and "abc123" not in red
    assert "PORT = 6666" in red and 'LOGDIR = "/logs"' in red
    assert "site_a = " in red


def test_audit_diff_never_contains_secret_values(path):
    store.save(path, {"SERVER": {"TOKEN": {"site_a": "abc123"}}, "MESH_GROUP": []}, "a", "ACT", "x", now=t(1))
    assert "abc123" not in store.audit_entries(path)[0]["diff"]

"""Composants embarqués par les packages (packaging/build_packages.py) : versions à jour et archives vérifiées.

- latest_versions : dernière version de chaque composant ; montée automatique permise pour VictoriaMetrics, les
  versions mineures de Grafana (même majeure) et Python (même 3.x) ; une majeure de Grafana et iperf3v : signalées
  seulement (à valider à la main).
- bump_text : réécrit les constantes de version (utilisé par la CI hebdomadaire, qui ouvre une PR).
- Les archives de VictoriaMetrics et de Grafana sont vérifiées contre les empreintes publiées par leurs projets.
"""
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_packages", ROOT / "packaging" / "build_packages.py")
bp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bp)


def fake_api(vm_tags, grafana_tags, py_assets, pbs_tag, iperf_tag):
    def api(url):
        if "VictoriaMetrics/VictoriaMetrics/releases" in url:
            return [{"tag_name": t, "prerelease": False, "draft": False} for t in vm_tags]
        if "grafana/grafana/releases" in url:
            return [{"tag_name": t, "prerelease": "beta" in t, "draft": False} for t in grafana_tags]
        if "python-build-standalone/releases/latest" in url:
            return {"tag_name": pbs_tag, "assets": [{"name": n} for n in py_assets]}
        if "iperf3v/releases/latest" in url:
            return {"tag_name": iperf_tag}
        raise AssertionError(url)
    return api


def test_the_latest_version_of_each_component(monkeypatch):
    monkeypatch.setattr(bp, "VM_VERSION", "v1.156.0")
    monkeypatch.setattr(bp, "GRAFANA_VERSION", "13.0.2")
    monkeypatch.setattr(bp, "PY_VERSION", "3.14.10")
    monkeypatch.setattr(bp, "PY_BUILD", "20261123")
    monkeypatch.setattr(bp, "IPERF3V_TAG", "v3.22.1-v2")
    api = fake_api(["v1.157.0", "v1.156.0", "v1.122.9"],  # une LTS ancienne ne compte pas
                   ["v14.0.0-beta1", "v13.3.2", "v13.2.7", "v12.4.16", "v13.0.14"],
                   ["cpython-3.14.11+20261201-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
                    "cpython-3.15.0+20261201-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"],
                   "20261201", "v3.22.1-v3")
    v = bp.latest_versions(api)
    assert v["victoriametrics"] == {"pinned": "v1.156.0", "latest": "v1.157.0", "auto": True, "behind": True}
    assert v["grafana"] == {"pinned": "13.0.2", "latest": "13.3.2", "auto": True, "behind": True}  # pas la bêta 14
    assert v["python"] == {"pinned": "3.14.10+20261123", "latest": "3.14.11+20261201", "auto": True, "behind": True}
    assert v["iperf3v"] == {"pinned": "v3.22.1-v2", "latest": "v3.22.1-v3", "auto": False, "behind": True}
    assert "grafana-major" not in v  # 14 n'existe qu'en bêta


def test_a_new_grafana_major_is_reported_but_never_applied(monkeypatch):
    monkeypatch.setattr(bp, "GRAFANA_VERSION", "13.3.2")
    api = fake_api(["v1.156.0"], ["v14.0.0", "v13.3.2"], [], "x", "v3.22.1-v2")
    v = bp.latest_versions(api)
    assert v["grafana"]["behind"] is False
    assert v["grafana-major"] == {"pinned": "13.3.2", "latest": "14.0.0", "auto": False, "behind": True}


def test_bump_rewrites_only_the_automatic_components():
    text = ('PY_VERSION, PY_BUILD = "3.14.10", "20261123"\nIPERF3V_TAG = "v3.22.1-v2"\n'
            'VM_VERSION, GRAFANA_VERSION = "v1.156.0", "13.0.2"\n')
    versions = {"victoriametrics": {"pinned": "v1.156.0", "latest": "v1.157.0", "auto": True, "behind": True},
                "grafana": {"pinned": "13.0.2", "latest": "13.3.2", "auto": True, "behind": True},
                "python": {"pinned": "3.14.10+20261123", "latest": "3.14.11+20261201", "auto": True, "behind": True},
                "iperf3v": {"pinned": "v3.22.1-v2", "latest": "v3.22.1-v3", "auto": False, "behind": True},
                "grafana-major": {"pinned": "13.0.2", "latest": "14.0.0", "auto": False, "behind": True}}
    new, changes = bp.bump_text(text, versions)
    assert 'VM_VERSION, GRAFANA_VERSION = "v1.157.0", "13.3.2"' in new
    assert 'PY_VERSION, PY_BUILD = "3.14.11", "20261201"' in new
    assert 'IPERF3V_TAG = "v3.22.1-v2"' in new  # signalé, jamais monté seul
    assert len(changes) == 3 and any("Grafana 13.0.2 → 13.3.2" in c for c in changes)
    assert bp.bump_text(new, {k: dict(v, pinned=v["latest"], behind=False) for k, v in versions.items()})[1] == []


def test_a_victoriametrics_archive_is_checked_against_its_published_checksums(tmp_path, monkeypatch):
    archive = tmp_path / "victoria-metrics-linux-amd64-v1.157.0.tar.gz"
    archive.write_bytes(b"vm")
    sums = tmp_path / "sums.txt"
    monkeypatch.setattr(bp, "VM_VERSION", "v1.157.0")
    monkeypatch.setattr(bp, "fetch", lambda url, name: sums if name.endswith("_checksums.txt") else archive)
    sums.write_text(f"{hashlib.sha256(b'vm').hexdigest()}  {archive.name}\n{'1' * 64}  victoria-metrics-prod\n")
    assert bp.victoriametrics("linux-x86_64") == archive
    sums.write_text(f"{'0' * 64}  {archive.name}\n")
    with pytest.raises(SystemExit):
        bp.victoriametrics("linux-x86_64")
    assert not archive.exists()  # retiré du cache : la construction suivante le retélécharge


def test_a_grafana_archive_is_checked_against_its_published_checksum(tmp_path, monkeypatch):
    archive = tmp_path / "grafana-13.3.2.linux-amd64.tar.gz"
    archive.write_bytes(b"grafana")
    sha = tmp_path / "g.sha256"
    monkeypatch.setattr(bp, "GRAFANA_VERSION", "13.3.2")
    monkeypatch.setattr(bp, "fetch", lambda url, name: sha if name.endswith(".sha256") else archive)
    sha.write_text(hashlib.sha256(b"grafana").hexdigest() + "\n")
    assert bp.grafana("linux-x86_64") == archive
    sha.write_text("f" * 64)
    with pytest.raises(SystemExit):
        bp.grafana("linux-x86_64")


def test_the_weekly_workflow_bumps_tests_and_opens_a_pull_request():
    wf = (ROOT / ".github" / "workflows" / "bundle-versions.yml").read_text(encoding="utf-8")
    for needle in ("schedule:", "workflow_dispatch:", "--bump", "test_install.sh", "gh pr create"):
        assert needle in wf, needle
    assert json  # (import gardé pour les évolutions du test)

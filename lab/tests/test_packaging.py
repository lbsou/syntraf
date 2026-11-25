"""Packages d'installation hors ligne (packaging/build_packages.py) : scripts prêts à l'emploi sur chaque système."""
import importlib.util
import io
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_packages", ROOT / "packaging" / "build_packages.py")
bp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bp)


def test_shell_scripts_get_unix_line_endings_and_the_execute_bit(tmp_path):
    src = tmp_path / "install.sh"
    src.write_bytes(b"#!/bin/sh\r\necho ok\r\n")
    a = bp.Archive(tmp_path / "p.tar.gz", "pkg")
    a.add_file("install.sh", src, 0o755)
    a.close()
    with tarfile.open(tmp_path / "p.tar.gz") as t:
        m = t.getmember("pkg/install.sh")
        assert m.mode == 0o755 and b"\r" not in t.extractfile(m).read()


def test_powershell_scripts_get_a_utf8_bom_for_windows_powershell(tmp_path):
    src = tmp_path / "install.ps1"
    src.write_text("Write-Host \"installé\"\n", encoding="utf-8")
    a = bp.Archive(tmp_path / "p.zip", "pkg")
    a.add_file("install.ps1", src)
    a.close()
    data = zipfile.ZipFile(tmp_path / "p.zip").read("pkg/install.ps1")
    assert data.startswith(b"\xef\xbb\xbf") and "installé".encode() in data


def test_targets_and_templates():
    assert set(bp.TARGETS) == {"linux-x86_64", "linux-musl-x86_64", "windows-x86_64", "macos-arm64"}
    for name in ("install.sh", "uninstall.sh", "install.ps1", "uninstall.ps1", "README.txt"):
        assert (ROOT / "packaging" / "templates" / name).is_file()
    install = (ROOT / "packaging" / "templates" / "install.sh").read_text(encoding="utf-8")
    assert "--no-index" in install and "SYNTRAF_BASE_DIR" in install  # hors ligne ; données hors du code


def test_the_provisioned_datasource_is_the_one_the_dashboards_use():
    """Le serveur installe Grafana relié à VictoriaMetrics : l'uid provisionné doit être celui des tableaux de bord."""
    import json
    uids = {m for _, data in bp.dashboards() for m in __import__("re").findall(r'"uid": "([^"]+)"', data.decode())
            if m.startswith("syntraf-vm")}
    assert uids == {"syntraf-vm"}
    for name in ("install.sh", "install.ps1"):
        text = (ROOT / "packaging" / "templates" / name).read_text(encoding="utf-8")
        assert "uid: syntraf-vm" in text and "url: http://127.0.0.1:8428" in text
        assert '"syntraf.json"' not in text and "syntraf.json" in text  # tableau d'accueil
    assert [n for n, _ in bp.dashboards()][0] == "syntraf.json"
    json.loads(dict(bp.dashboards())["syntraf.json"])


def test_a_fresh_server_gets_the_suggested_profiles():
    """install.sh et install.ps1 écrivent les profils suggérés (mêmes valeurs que SUGGESTED_PROFILES)."""
    import re
    import sys
    sys.path.insert(0, str(ROOT))
    from lib.st_mesh_group_ops import SUGGESTED_PROFILES
    for name in ("install.sh", "install.ps1"):
        text = (ROOT / "packaging" / "templates" / name).read_text(encoding="utf-8")
        text = re.sub(r"^\s*echo(?: '(.*)')?\r?$", r"\1", text, flags=re.M)  # install.sh : echo '...'
        blocks =re.findall(r"\[\[IPERF3_PROFILE\]\]((?:\s*\w+ = \"[^\"\n]*\")+)", text)
        found = [dict(re.findall(r"(\w+) = \"([^\"\n]*)\"", b)) for b in blocks]
        assert found == [{k: str(v) for k, v in p.items()} for p in SUGGESTED_PROFILES], name


def test_the_linux_probe_runs_on_glibc_2_17():
    """RHEL/CentOS 7 : la sonde ne doit embarquer aucun wheel manylinux_2_28 (pip prend le premier tag qui convient)."""
    probe = bp.platforms_of("linux-x86_64", "probe")
    assert probe[0] == "manylinux2014_x86_64" and not any("2_28" in p for p in probe)
    assert bp.TARGETS["linux-x86_64"]["glibc"] == {"probe": "2.17", "server": "2.28"}
    assert bp.platforms_of("windows-x86_64", "probe") == ["win_amd64"]


def test_archive_entries_are_not_dated_1970(tmp_path):
    a = bp.Archive(tmp_path / "p.tar.gz", "pkg")
    a.add_bytes("x.txt", b"x")
    a.close()
    with tarfile.open(tmp_path / "p.tar.gz") as t:
        assert t.getmembers()[0].mtime > 1_600_000_000


def test_iperf3v_release_assets_are_checked_against_their_sha256sums(tmp_path, monkeypatch):
    """Binaires iperf3v téléchargés (Windows, macOS) : refusés si leur empreinte n'est pas celle de SHA256SUMS."""
    import hashlib
    import pytest
    asset = tmp_path / "iperf3v-x-macos-arm64.tar.gz"
    asset.write_bytes(b"binaire")
    sums = tmp_path / "SHA256SUMS"
    monkeypatch.setattr(bp, "fetch", lambda url, name: sums if name.endswith("SHA256SUMS") else asset)
    sums.write_text(f"{hashlib.sha256(b'binaire').hexdigest()}  {asset.name}\n")
    assert bp.iperf3v_asset(asset.name) == asset
    sums.write_text(f"{'0' * 64}  {asset.name}\n")
    with pytest.raises(SystemExit):
        bp.iperf3v_asset(asset.name)


def test_the_macos_package_ships_iperf3v():
    assert bp.TARGETS["macos-arm64"]["iperf"] == "macos"
    install = (ROOT / "packaging" / "templates" / "install.sh").read_text(encoding="utf-8")
    assert "com.apple.quarantine" in install  # archive téléchargée par un navigateur : binaire bloqué sinon

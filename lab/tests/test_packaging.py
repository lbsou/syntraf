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

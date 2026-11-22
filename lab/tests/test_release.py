"""Releases de SYNTRAF (lib/st_release.py) : archive des sources fabriquée par le serveur, identité par empreinte,
extraction sûre. Module sans dépendance : tourne dans lab/.venv.
"""
import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_release as rel  # noqa: E402


def tree(root, files):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


@pytest.fixture
def src(tmp_path):
    return tree(tmp_path / "src", {
        "syntraf.py": "print('main')\n", "lib/st_x.py": "X = 1\n", "requirements_client.txt": "toml==0.10.2\n",
        "lib/__pycache__/st_x.cpython-314.pyc": "junk", "venv/bin/python": "junk", "crypto/key.pem": "secret",
        "lab/tests/t.py": "test", "releases/dist/old.tar.gz": "old", ".git/HEAD": "ref",
    })


def test_digest_covers_the_code_only(src):
    d1 = rel.source_digest(str(src))
    (src / "crypto" / "key.pem").write_text("other secret")
    (src / "lib" / "__pycache__" / "st_x.cpython-314.pyc").write_text("other junk")
    assert rel.source_digest(str(src)) == d1
    (src / "lib" / "st_x.py").write_text("X = 2\n")
    assert rel.source_digest(str(src)) != d1


def test_release_id_is_version_plus_digest(src):
    rid = rel.release_id(str(src), "0.45")
    assert rid.startswith("0.45+") and len(rid) == len("0.45+") + 10


def test_build_contains_the_code_and_a_manifest_but_no_secrets(src, tmp_path):
    info = rel.build(str(src), str(tmp_path / "out"), "0.45")
    with tarfile.open(info["path"]) as t:
        names = t.getnames()
        manifest = json.load(t.extractfile("manifest.json"))
    assert {"syntraf.py", "lib/st_x.py", "requirements_client.txt", "manifest.json"} <= set(names)
    assert not any(n.startswith(("crypto", "venv", "lab", "releases", ".git")) or "__pycache__" in n for n in names)
    assert manifest["id"] == info["id"] and manifest["has_wheelhouse"] is False
    assert manifest["requirements_sha256"] == rel.requirements_sha256(str(src))
    assert info["sha256"] == rel.file_sha256(info["path"]) and info["size"] > 0


def test_build_is_cached_and_reproducible(src, tmp_path):
    a = rel.build(str(src), str(tmp_path / "out"), "0.45")
    b = rel.build(str(src), str(tmp_path / "out2"), "0.45")
    assert a["sha256"] == b["sha256"]
    assert rel.build(str(src), str(tmp_path / "out"), "0.45")["path"] == a["path"]


def test_wheelhouse_is_shipped_when_present(src, tmp_path):
    tree(src, {"wheelhouse/toml-0.10.2-py2.py3-none-any.whl": "wheel"})
    info = rel.build(str(src), str(tmp_path / "out"), "0.45")
    with tarfile.open(info["path"]) as t:
        assert "wheelhouse/toml-0.10.2-py2.py3-none-any.whl" in t.getnames()
        assert json.load(t.extractfile("manifest.json"))["has_wheelhouse"] is True


def test_safe_extract_refuses_paths_leaving_the_destination(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        data = b"x"
        info = tarfile.TarInfo("../escaped.txt")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    with pytest.raises(rel.ReleaseError):
        rel.safe_extract(str(archive), str(tmp_path / "dest"))
    assert not (tmp_path / "escaped.txt").exists()


def test_safe_extract_refuses_links(tmp_path):
    archive = tmp_path / "link.tar.gz"
    with tarfile.open(archive, "w:gz") as t:
        info = tarfile.TarInfo("lib/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        t.addfile(info)
    with pytest.raises(rel.ReleaseError):
        rel.safe_extract(str(archive), str(tmp_path / "dest"))

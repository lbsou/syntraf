"""Mise à jour du serveur depuis les releases GitHub (lib/st_github_update.py) : vérification, signature du projet,
installation par le superviseur (st_updater) avec retour arrière automatique."""
import base64
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

from lib import st_github_update as gu  # noqa: E402

KEY = ed25519.Ed25519PrivateKey.generate()
PUB = KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
ARCHIVE = b"release archive bytes"
API = "https://api.github.com/repos/lbsou/syntraf/releases/latest"


def release(version="0.45.20", signed=True, archive=ARCHIVE, key=KEY):
    """Un faux GitHub : {url: octets}."""
    rid = f"{version}+abc123"
    manifest = gu.manifest_bytes({"version": version, "id": rid, "file": f"syntraf-{rid}.tar.gz",
                                  "sha256": hashlib.sha256(ARCHIVE).hexdigest(), "size": len(ARCHIVE),
                                  "profile": "full"})
    base = f"https://github.com/lbsou/syntraf/releases/download/v{version}/"
    assets = [{"name": f"syntraf-{rid}.tar.gz", "browser_download_url": base + f"syntraf-{rid}.tar.gz"}]
    files = {base + f"syntraf-{rid}.tar.gz": archive}
    if signed:
        files[base + f"syntraf-release-{version}.json"] = manifest
        files[base + f"syntraf-release-{version}.json.sig"] = gu.sign(manifest, key).encode()
        assets += [{"name": f"syntraf-release-{version}.json", "browser_download_url": base + f"syntraf-release-{version}.json"},
                   {"name": f"syntraf-release-{version}.json.sig", "browser_download_url": base + f"syntraf-release-{version}.json.sig"}]
    files[API] = json.dumps({"tag_name": f"v{version}", "html_url": f"https://github.com/lbsou/syntraf/releases/tag/v{version}",
                             "published_at": "2026-11-25T10:00:00Z", "assets": assets}).encode()

    def http_get(url):
        if url not in files:
            raise OSError(f"404 {url}")
        return files[url]
    return http_get


def test_versions_compare_numerically():
    assert gu.parse_version("v0.45.10") == (0, 45, 10)
    assert gu.is_newer("0.45.10", "0.45.9") and not gu.is_newer("0.45.9", "0.45.10")
    assert not gu.is_newer("0.45.13", "0.45.13")


def test_a_signed_manifest_verifies_and_any_change_is_refused():
    m = gu.manifest_bytes({"version": "1.0.0", "id": "1.0.0+x", "file": "syntraf-1.0.0+x.tar.gz", "sha256": "a" * 64, "size": 1,
                           "profile": "full"})
    sig = gu.sign(m, KEY)
    assert gu.verify(m, sig, [PUB])["version"] == "1.0.0"
    with pytest.raises(gu.UpdateError):
        gu.verify(m.replace(b"1.0.0", b"9.9.9"), sig, [PUB])
    other = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises(gu.UpdateError):
        gu.verify(m, gu.sign(m, other), [PUB])


def test_a_newer_signed_release_is_offered():
    st = gu.check(release(), "0.45.13", keys=[PUB])
    assert st["available"] is True and st["latest"] == "0.45.20" and st["current"] == "0.45.13"
    assert st["url"].endswith("/v0.45.20") and st["error"] is None


def test_an_unsigned_release_is_never_offered():
    st = gu.check(release(signed=False), "0.45.13", keys=[PUB])
    assert st["available"] is False and "signed" in st["note"]


def test_the_same_version_is_up_to_date():
    st = gu.check(release(version="0.45.13"), "0.45.13", keys=[PUB])
    assert st["available"] is False and st["latest"] == "0.45.13"


def test_github_unreachable_is_reported_not_raised():
    def down(url):
        raise OSError("network unreachable")
    st = gu.check(down, "0.45.13", keys=[PUB])
    assert st["available"] is False and "unreachable" in st["error"]


def test_apply_downloads_verifies_then_lets_the_supervisor_switch(tmp_path):
    staged, restarted = [], []
    out = gu.apply(release(), "0.45.13", str(tmp_path), "/opt/python3", keys=[PUB],
                   stage=lambda base, path, sha, rid, py: staged.append((base, Path(path).read_bytes(), sha, rid, py)),
                   request_restart=lambda base: restarted.append(base))
    assert out == {"version": "0.45.20", "release": "0.45.20+abc123"}
    assert staged == [(str(tmp_path), ARCHIVE, hashlib.sha256(ARCHIVE).hexdigest(), "0.45.20+abc123", "/opt/python3")]
    assert restarted == [str(tmp_path)]


def test_apply_refuses_a_release_signed_by_another_key(tmp_path):
    with pytest.raises(gu.UpdateError):
        gu.apply(release(key=ed25519.Ed25519PrivateKey.generate()), "0.45.13", str(tmp_path), "py", keys=[PUB],
                 stage=lambda *a: pytest.fail("staged"), request_restart=lambda b: pytest.fail("restarted"))


def test_apply_refuses_an_archive_that_does_not_match_its_signed_digest(tmp_path):
    with pytest.raises(gu.UpdateError):
        gu.apply(release(archive=b"tampered"), "0.45.13", str(tmp_path), "py", keys=[PUB],
                 stage=lambda *a: pytest.fail("staged"), request_restart=lambda b: pytest.fail("restarted"))


def test_apply_never_goes_back_to_an_older_version(tmp_path):
    with pytest.raises(gu.UpdateError):
        gu.apply(release(version="0.45.10"), "0.45.13", str(tmp_path), "py", keys=[PUB],
                 stage=lambda *a: pytest.fail("staged"), request_restart=lambda b: pytest.fail("restarted"))


def test_the_project_key_is_built_in():
    assert gu.PUBLIC_KEYS and all("BEGIN PUBLIC KEY" in k for k in gu.PUBLIC_KEYS)
    assert base64  # (import gardé)

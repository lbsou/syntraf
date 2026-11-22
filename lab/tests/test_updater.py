"""Mise à jour d'un client (lib/st_updater.py) : installation d'une release à côté de la version en place, choix de
la version à démarrer, confirmation, retour arrière. Module sans dépendance : tourne dans lab/.venv.
"""
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_release as rel  # noqa: E402
from lib import st_updater as up  # noqa: E402


def tree(root, files):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


@pytest.fixture
def base(tmp_path):
    """Installation en place du client (première installation, faite à la main)."""
    return tree(tmp_path / "base", {"syntraf.py": "print('v1')\n", "lib/st_x.py": "X = 1\n",
                                    "requirements_client.txt": "toml==0.10.2\n"})


def release(tmp_path, files=None):
    src = tree(tmp_path / "release_src", dict({"syntraf.py": "print('v2')\n", "lib/st_x.py": "X = 2\n",
                                               "requirements_client.txt": "toml==0.10.2\n"}, **(files or {})))
    return rel.build(str(src), str(tmp_path / "dist"), "0.46")


def test_staging_installs_the_release_beside_the_current_one(base, tmp_path):
    info = release(tmp_path)
    path = up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    assert Path(path, "syntraf.py").read_text() == "print('v2')\n"
    state = up.read_state(str(base))
    assert state["current"] == info["id"] and state["previous"] is None
    assert state["pending"]["id"] == info["id"] and state["pending"]["attempts"] == 0
    assert (base / "syntraf.py").read_text() == "print('v1')\n"  # la version en place n'est pas touchée


def test_a_corrupted_download_is_refused(base, tmp_path):
    info = release(tmp_path)
    with pytest.raises(up.UpdateError):
        up.stage(str(base), info["path"], "0" * 64, info["id"], python=sys.executable)
    assert up.read_state(str(base))["current"] is None


def test_removing_a_requirement_needs_no_wheelhouse(tmp_path):
    # le client a déjà tout ce que la release demande (elle en demande moins) : elle s'installe
    base = tree(tmp_path / "base2", {"syntraf.py": "print('v1')\n", "lib/st_x.py": "X = 1\n",
                                     "requirements_client.txt": "toml==0.10.2\n# commentaire\nscapy==2.8.0\n"})
    info = release(tmp_path, {"requirements_client.txt": "toml==0.10.2\n"})
    path = up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    assert Path(path, "syntraf.py").read_text() == "print('v2')\n"


def test_changed_requirements_without_wheelhouse_are_refused(base, tmp_path):
    info = release(tmp_path, {"requirements_client.txt": "toml==0.10.2\nnewdep==1.0\n"})
    with pytest.raises(up.UpdateError) as err:
        up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    assert "wheelhouse" in str(err.value)


def test_a_wheelhouse_gets_its_own_venv_installed_offline(base, tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        if cmd[1:3] == ["-m", "venv"]:  # comme python -m venv : l'interpréteur du venv apparaît
            exe = Path(cmd[3], "Scripts", "python.exe") if os.name == "nt" else Path(cmd[3], "bin", "python")
            exe.parent.mkdir(parents=True)
            exe.write_text("")
    monkeypatch.setattr(up, "_run", fake_run)
    info = release(tmp_path, {"requirements_client.txt": "toml==0.10.2\nnewdep==1.0\n",
                              "wheelhouse/newdep-1.0-py3-none-any.whl": "wheel"})
    path = up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    assert calls[0][1:4] == ["-m", "venv", os.path.join(path, "venv")]
    assert "--no-index" in calls[1] and "--find-links" in calls[1]
    assert up.release_python(path).startswith(os.path.join(path, "venv"))


def test_choose_runs_the_current_release_and_counts_attempts(base, tmp_path):
    info = release(tmp_path)
    path = up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    choice = up.choose(str(base), now=100.0)
    assert choice.release_id == info["id"] and choice.directory == path
    assert up.read_state(str(base))["pending"]["attempts"] == 1


def test_confirmed_release_stays(base, tmp_path):
    info = release(tmp_path)
    up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    up.confirm(str(base), info["id"])
    assert up.read_state(str(base))["pending"] is None
    for _ in range(5):
        assert up.choose(str(base), now=1e12).release_id == info["id"]


def test_release_failing_to_confirm_is_rolled_back_after_its_attempts(base, tmp_path):
    info = release(tmp_path)
    up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    for _ in range(up.MAX_ATTEMPTS):
        assert up.choose(str(base), now=0.0).release_id == info["id"]
    choice = up.choose(str(base), now=0.0)
    assert choice.release_id is None and choice.directory == str(base)  # retour à l'installation en place
    state = up.read_state(str(base))
    assert state["current"] is None and state["failed"][-1]["id"] == info["id"]


def test_release_not_confirmed_in_time_is_rolled_back(base, tmp_path):
    info = release(tmp_path)
    up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    up.choose(str(base), now=1000.0)
    assert up.overdue(str(base), now=1000.0 + up.CONFIRM_GRACE_S + 1)
    up.rollback(str(base), reason="not confirmed in time")
    assert up.read_state(str(base))["current"] is None


def test_failed_release_is_not_retried_automatically(base, tmp_path):
    info = release(tmp_path)
    up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    up.rollback(str(base), reason="test")
    with pytest.raises(up.UpdateError):
        up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable, force=True)


def test_rollback_from_a_second_release_returns_to_the_first(base, tmp_path):
    first = release(tmp_path)
    up.stage(str(base), first["path"], first["sha256"], first["id"], python=sys.executable)
    up.confirm(str(base), first["id"])
    second = release(tmp_path / "b", {"lib/st_x.py": "X = 3\n"})
    up.stage(str(base), second["path"], second["sha256"], second["id"], python=sys.executable)
    up.rollback(str(base), reason="test")
    assert up.read_state(str(base))["current"] == first["id"]


def test_old_releases_are_cleaned_but_current_and_previous_stay(base, tmp_path, monkeypatch):
    monkeypatch.setattr(up, "KEEP_RELEASES", 2)
    ids = []
    for i in range(4):
        info = release(tmp_path / str(i), {"lib/st_x.py": f"X = {i}\n"})
        up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
        up.confirm(str(base), info["id"])
        ids.append(info["id"])
    kept = sorted(d for d in os.listdir(base / "releases") if d != up.STATE_FILE)
    assert sorted(ids[-2:]) == kept


# ------------------------------------------------------------------- supervision, avec de vrais sous-processus

REPO = str(Path(__file__).resolve().parents[2])
CONFIRM = ("import os, sys; sys.path.insert(0, {repo!r}); from lib import st_updater as u; "
           "u.confirm(os.environ[u.ENV_BASE], os.environ[u.ENV_RELEASE])\n").format(repo=REPO)


def test_supervise_restarts_on_request_then_returns_the_exit_code(base, monkeypatch):
    monkeypatch.setattr(up, "MAX_ATTEMPTS", 3)
    (base / "syntraf.py").write_text(f"import os, sys\nm = {str(base / 'marker')!r}\n"
                                     "if not os.path.exists(m):\n    open(m, 'w').close()\n    sys.exit(75)\nsys.exit(0)\n")
    assert up.supervise(str(base), [], poll_s=0.05) == 0
    assert (base / "marker").exists()


def test_supervise_rolls_back_a_release_that_crashes_before_confirming(base, tmp_path):
    (base / "syntraf.py").write_text("import sys; sys.exit(0)\n")
    info = release(tmp_path, {"syntraf.py": "import sys; sys.exit(1)\n"})
    up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    assert up.supervise(str(base), [], poll_s=0.05) == 0          # l'installation en place a repris la main
    state = up.read_state(str(base))
    assert state["current"] is None and state["failed"][-1]["id"] == info["id"]


def test_supervise_keeps_a_release_that_confirms(base, tmp_path):
    info = release(tmp_path, {"syntraf.py": CONFIRM})
    up.stage(str(base), info["path"], info["sha256"], info["id"], python=sys.executable)
    assert up.supervise(str(base), [], poll_s=0.05) == 0
    state = up.read_state(str(base))
    assert state["current"] == info["id"] and state["pending"] is None


def test_restart_request_stops_the_running_version_and_starts_the_new_one(base):
    import threading
    marker = base / "started_once"
    (base / "syntraf.py").write_text(
        f"import os, sys, time\nm = {str(marker)!r}\n"
        "if os.path.exists(m):\n    sys.exit(0)\nopen(m, 'w').close()\ntime.sleep(60)\n")
    def restart_once_started():  # quand la première version tourne vraiment (pas un délai fixe : machine chargée)
        import time
        deadline = time.time() + 30
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.05)
        up.request_restart(str(base))
    threading.Thread(target=restart_once_started, daemon=True).start()
    t0 = __import__("time").time()
    assert up.supervise(str(base), [], poll_s=0.1) == 0
    assert __import__("time").time() - t0 < 30 and marker.exists()
    assert up.read_state(str(base)).get("restart") is not True

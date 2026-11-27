"""Les iperf3 lancés par SYNTRAF ne lui survivent pas.

Vu en production (V0930-TELECOM, Windows, après la mise à jour 0.45.42) : l'ancien SYNTRAF s'est arrêté, mais son
iperf3 a survécu (sous Windows, un parent qui meurt ne tue pas ses enfants). Il tenait le port 15999 et servait la
session de W34650 : le sens qu'il recevait n'était plus lu par personne (gris sur la carte), et le nouvel écouteur,
sans port, était relancé toutes les 10 s.
"""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_children  # noqa: E402

WINDOWS = os.name == "nt"


def fake_iperf3(tmp_path):
    """Un exécutable à nous (copie d'un programme qui attend), qui joue le rôle de l'iperf3 de SYNTRAF."""
    if WINDOWS:
        src = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "ping.exe"
        dst = tmp_path / "iperf3v.exe"
        args = ["-n", "60", "127.0.0.1"]
    else:
        src = Path(shutil.which("sleep"))
        dst = tmp_path / "iperf3v"
        args = ["60"]
    shutil.copy2(src, dst)
    return dst, args


def alive(pid):
    import psutil
    try:
        return psutil.Process(pid).status() != psutil.STATUS_ZOMBIE
    except psutil.NoSuchProcess:
        return False


def wait_dead(pid, seconds=10.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if not alive(pid):
            return True
        time.sleep(0.1)
    return not alive(pid)


def test_an_iperf3_left_by_a_previous_run_is_found_and_killed(tmp_path):
    binary, args = fake_iperf3(tmp_path)
    left = subprocess.Popen([str(binary)] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert [p.pid for p in st_children.strays(str(binary))] == [left.pid]
        killed = st_children.kill_strays(str(binary))
        assert killed == [left.pid]
        assert wait_dead(left.pid)
    finally:
        left.kill()
        left.wait()


def test_other_programs_and_an_unknown_binary_are_left_alone(tmp_path):
    binary, args = fake_iperf3(tmp_path)
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    other, _ = fake_iperf3(other_dir)  # même nom, autre installation : pas à nous
    p = subprocess.Popen([str(other)] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert st_children.kill_strays(str(binary)) == []
        assert st_children.kill_strays("") == [] and st_children.kill_strays(None) == []
        assert alive(p.pid)
    finally:
        p.kill()
        p.wait()


PARENT = r"""
import subprocess, sys, time
sys.path.insert(0, sys.argv[1])
from lib import st_children
if sys.argv[2] == "job":
    assert st_children.bind_to_me()
child = subprocess.Popen(sys.argv[3:], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(child.pid, flush=True)
time.sleep(60)
"""


def run_parent(tmp_path, mode):
    """Un SYNTRAF simulé qui lance un iperf3 puis meurt d'un coup (kill), sans rien arrêter."""
    binary, args = fake_iperf3(tmp_path)
    script = tmp_path / "parent.py"
    script.write_text(PARENT, encoding="utf-8")
    root = str(Path(__file__).resolve().parents[2])
    parent = subprocess.Popen([sys.executable, str(script), root, mode, str(binary)] + args,
                              stdout=subprocess.PIPE, text=True)
    child = int(parent.stdout.readline())
    assert alive(child)
    parent.kill()
    parent.wait()
    return child


@pytest.mark.skipif(not WINDOWS, reason="job object : Windows seulement (Linux : groupe de processus du superviseur)")
def test_on_windows_the_iperf3_dies_with_syntraf_even_when_it_is_killed(tmp_path):
    child = run_parent(tmp_path, "job")
    try:
        assert wait_dead(child), "l'iperf3 a survécu à SYNTRAF"
    finally:
        if alive(child):
            import psutil
            psutil.Process(child).kill()


@pytest.mark.skipif(not WINDOWS, reason="comportement de Windows sans job object")
def test_without_the_job_windows_lets_the_iperf3_survive(tmp_path):
    """Témoin : sans job object, l'enfant survit au parent tué (c'est le bogue)."""
    child = run_parent(tmp_path, "nojob")
    try:
        time.sleep(1)
        assert alive(child)
    finally:
        if alive(child):
            import psutil
            psutil.Process(child).kill()


def test_binding_elsewhere_than_windows_does_nothing():
    if WINDOWS:
        pytest.skip("Windows : couvert par le test du job object")
    assert st_children.bind_to_me() is False


def test_a_restart_asked_by_the_server_goes_through_the_supervisor(monkeypatch, tmp_path):
    """Sous le superviseur, RESTART_CLIENT sort avec EXIT_RESTART (le superviseur relance SYNTRAF) au lieu d'un
    execv qui, sous Windows, créerait un enfant tué avec SYNTRAF par le job object."""
    try:
        import lib.st_process_and_thread  # noqa: F401 - ordre d'import du serveur
        from lib import st_mesh, st_updater
    except (ImportError, SystemExit):
        pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)")
    from lib.st_global import DefaultValues

    class Conn:
        def shutdown(self, how): pass
        def close(self): pass

    def exit_(code):
        raise SystemExit(code)
    monkeypatch.setenv(st_updater.ENV_CHILD, "1")
    monkeypatch.setattr(DefaultValues, "SYNTRAF_PID_FILE", str(tmp_path / "absent.pid"))  # déjà supprimé : sans erreur
    monkeypatch.setattr(st_mesh.os, "_exit", exit_)
    monkeypatch.setattr(st_mesh.os, "execv", lambda *a: pytest.fail("execv sous le superviseur"))
    monkeypatch.setattr(st_mesh.os, "execl", lambda *a: pytest.fail("execl sous le superviseur"))
    with pytest.raises(SystemExit) as stop:
        st_mesh.client_command_restart(Conn())
    assert stop.value.code == st_updater.EXIT_RESTART


# --------------------------------------------------------------------- port d'écoute pris (V0930-TELECOM, 27 nov.)
# Un écouteur relancé toutes les 10 s, « LAST BREATH : ' - ' » : iperf3 avait dit pourquoi (port pris), dans sa
# sortie JSON, mais SYNTRAF ne l'affichait pas ; et personne ne savait qui tenait le port.

def test_the_program_holding_a_port_is_found():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    try:
        port = s.getsockname()[1]
        assert os.getpid() in [pid for pid, _ in st_children.port_holders(port)]
    finally:
        s.close()


class Proc:
    def __init__(self, pid, exe):
        self.pid, self._exe, self.killed = pid, exe, False

    def exe(self):
        return self._exe

    def kill(self):
        self.killed = True


def test_a_port_held_by_our_own_stray_iperf3_is_freed(monkeypatch, caplog, tmp_path):
    ours, other = Proc(4242, str(tmp_path / "iperf3v.exe")), Proc(4343, r"C:\Tools\other.exe")
    monkeypatch.setattr(st_children, "_holders", lambda port: [ours, other])
    monkeypatch.setattr(st_children, "_wait", lambda procs, timeout: None)
    with caplog.at_level("WARNING"):
        killed, others = st_children.free_port(15999, str(tmp_path / "iperf3v.exe"))
    assert (killed, others) == ([4242], [(4343, r"C:\Tools\other.exe")])
    assert ours.killed and not other.killed
    text = caplog.text
    assert "PORT 15999" in text and "4242" in text and "other.exe" in text


def test_a_foreign_holder_is_reported_once_not_every_ten_seconds(monkeypatch, caplog, tmp_path):
    other = Proc(5151, r"C:\Tools\other.exe")
    monkeypatch.setattr(st_children, "_holders", lambda port: [other])
    st_children._REPORTED.clear()
    with caplog.at_level("WARNING"):
        st_children.free_port(15999, str(tmp_path / "iperf3v.exe"))
        st_children.free_port(15999, str(tmp_path / "iperf3v.exe"))
    assert caplog.text.count("other.exe") == 1


def test_the_death_of_an_iperf3_says_what_iperf3_said(caplog):
    try:
        import lib.st_process_and_thread as pt
    except (ImportError, SystemExit):
        pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)")
    from types import SimpleNamespace
    done = subprocess.Popen([sys.executable, "-c", "pass"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    done.wait()
    thr = SimpleNamespace(subproc=done, last_error="error - unable to start listener for connections: Address already in use")
    threads = [thr]
    with caplog.at_level("WARNING"):
        breath = pt.iperf3_print_last_breath("KEY_SERVING_W34650", "LISTENER", threads, thr)
    assert "Address already in use" in caplog.text and "Address already in use" in breath
    assert threads == []

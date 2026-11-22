"""Mise à jour d'un client SYNTRAF : installation d'une release à côté de la version en place, démarrage supervisé,
confirmation et retour arrière automatique.

Disposition, sous le dossier d'installation en place (« base », installé une fois à la main) :
  releases/state.json         {"current", "previous", "pending", "failed"}
  releases/<id>/              sources de la release (et venv/ si la release apporte ses paquets)

Le service (systemd, service Windows) lance toujours « python syntraf.py » de la base. syntraf.py ne fait alors que
superviser (supervise) : il démarre la version courante comme sous-processus. Une version nouvellement installée est
« en attente » tant qu'elle n'a pas confirmé (connexion au serveur réussie, config reçue) ; si elle n'y parvient pas
en MAX_ATTEMPTS démarrages ou en CONFIRM_GRACE_S secondes, on revient à la précédente.

Module sans dépendance externe (il tourne avant l'import du reste de SYNTRAF).
"""
import collections
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from lib import st_release

STATE_FILE = "state.json"
MAX_ATTEMPTS = 3
CONFIRM_GRACE_S = 600
KEEP_RELEASES = 3
EXIT_RESTART = 75          # code de sortie du processus SYNTRAF : « redémarre-moi (nouvelle version) »
ENV_CHILD = "SYNTRAF_SUPERVISED"
ENV_RELEASE = "SYNTRAF_RELEASE_ID"
ENV_BASE = "SYNTRAF_BASE_DIR"

Choice = collections.namedtuple("Choice", "release_id directory python")


class UpdateError(Exception):
    pass


# --------------------------------------------------------------------------------------------------------- état

def _releases(base):
    return os.path.join(base, "releases")


def read_state(base):
    try:
        with open(os.path.join(_releases(base), STATE_FILE), encoding="utf-8") as f:
            state = json.load(f)
    except (FileNotFoundError, ValueError):
        state = {}
    return {"current": state.get("current"), "previous": state.get("previous"), "pending": state.get("pending"),
            "failed": state.get("failed", []), "restart": state.get("restart", False)}


def _write_state(base, state):
    directory = _releases(base)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, os.path.join(directory, STATE_FILE))


# ---------------------------------------------------------------------------------------------- installation

def _run(cmd):
    subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)


def release_python(directory):
    """Interpréteur d'une release : son venv s'il en a un, sinon celui noté à l'installation."""
    for candidate in (os.path.join(directory, "venv", "Scripts", "python.exe"),
                      os.path.join(directory, "venv", "bin", "python")):
        if os.path.isfile(candidate):
            return candidate
    try:
        with open(os.path.join(directory, ".python"), encoding="utf-8") as f:
            return f.read().strip() or sys.executable
    except FileNotFoundError:
        return sys.executable


def stage(base, archive, expected_sha256, release_id, python, force=False):
    """Vérifie et installe une release ; elle devient la version courante, « en attente » de confirmation.
    Renvoie son dossier. La version en place n'est pas modifiée."""
    state = read_state(base)
    if not force and any(f["id"] == release_id for f in state["failed"]):
        raise UpdateError(f"release {release_id} already failed on this client; force it to try again")
    actual = st_release.file_sha256(archive)
    if actual != expected_sha256:
        raise UpdateError(f"checksum mismatch for {release_id} (got {actual[:12]}…): download corrupted")

    target = os.path.join(_releases(base), release_id)
    tmp = target + ".tmp"
    shutil.rmtree(tmp, ignore_errors=True)
    try:
        st_release.safe_extract(archive, tmp)
        manifest = st_release.read_manifest(tmp)
        if manifest.get("id") != release_id:
            raise UpdateError(f"the archive contains release {manifest.get('id')}, not {release_id}")
        if not manifest.get("has_wheelhouse"):
            running = _running_requirements_sha(base, state)
            if manifest.get("requirements_sha256") != running:
                raise UpdateError("the release needs other Python packages and ships no wheelhouse: build the "
                                  "server's release with its wheelhouse")
            with open(os.path.join(tmp, ".python"), "w", encoding="utf-8") as f:
                f.write(python)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    shutil.rmtree(target, ignore_errors=True)
    os.replace(tmp, target)
    if manifest.get("has_wheelhouse"):
        # Le venv est créé à sa place définitive : un venv contient des chemins absolus, il ne se déplace pas.
        try:
            _run([python, "-m", "venv", os.path.join(target, "venv")])
            _run([release_python(target), "-m", "pip", "install", "--no-index", "--find-links",
                  os.path.join(target, st_release.WHEELHOUSE), "-r",
                  os.path.join(target, st_release.CLIENT_REQUIREMENTS)])
        except Exception as exc:
            shutil.rmtree(target, ignore_errors=True)
            raise UpdateError(f"installing the release's Python packages failed: {exc}")

    if state["current"] != release_id:
        state["previous"] = state["current"]
    state["current"] = release_id
    state["pending"] = {"id": release_id, "since": None, "attempts": 0}
    state["failed"] = [f for f in state["failed"] if f["id"] != release_id]
    _write_state(base, state)
    _clean(base, state)
    return target


def _running_requirements_sha(base, state):
    directory = os.path.join(_releases(base), state["current"]) if state["current"] else base
    return st_release.requirements_sha256(directory)


def _clean(base, state):
    """Garde les KEEP_RELEASES releases les plus récentes, et toujours la courante et la précédente."""
    directory = _releases(base)
    entries = [d for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d)) and not d.endswith(".tmp")]
    entries.sort(key=lambda d: os.path.getmtime(os.path.join(directory, d)), reverse=True)
    keep = set(entries[:KEEP_RELEASES]) | {state["current"], state["previous"]}
    for d in entries:
        if d not in keep:
            shutil.rmtree(os.path.join(directory, d), ignore_errors=True)


# ------------------------------------------------------------------------------------ choix, confirmation, retour

def choose(base, now=None):
    """Version à démarrer. Une version en attente a MAX_ATTEMPTS démarrages pour confirmer, sinon retour arrière."""
    now = time.time() if now is None else now
    state = read_state(base)
    pending = state["pending"]
    if pending and pending["id"] == state["current"]:
        if pending["attempts"] >= MAX_ATTEMPTS:
            rollback(base, reason=f"not confirmed after {MAX_ATTEMPTS} starts")
            return choose(base, now)
        pending["attempts"] += 1
        if pending["since"] is None:
            pending["since"] = now
        _write_state(base, state)
    if state["current"]:
        directory = os.path.join(_releases(base), state["current"])
        if os.path.isfile(os.path.join(directory, "syntraf.py")):
            return Choice(state["current"], directory, release_python(directory))
        rollback(base, reason="release directory missing")
        return choose(base, now)
    return Choice(None, base, sys.executable)


def overdue(base, now=None):
    now = time.time() if now is None else now
    pending = read_state(base)["pending"]
    return bool(pending and pending.get("since") is not None and now - pending["since"] > CONFIRM_GRACE_S)


def confirm(base, release_id):
    """Appelé par la version démarrée quand elle a rejoint le serveur : elle devient définitive."""
    state = read_state(base)
    if state["pending"] and state["pending"]["id"] == release_id:
        state["pending"] = None
        _write_state(base, state)
        return True
    return False


def rollback(base, reason):
    state = read_state(base)
    failed_id = state["current"]
    state["failed"] = (state["failed"] + [{"id": failed_id, "reason": reason, "at": time.time()}])[-10:]
    state["current"], state["previous"], state["pending"] = state["previous"], None, None
    _write_state(base, state)
    return failed_id


# ---------------------------------------------------------------------------------------------- supervision

def request_restart(base):
    """Demande au superviseur d'arrêter la version en cours et de démarrer la version courante (après stage)."""
    state = read_state(base)
    state["restart"] = True
    _write_state(base, state)


def _start(cmd, env):
    # Groupe de processus à part : l'arrêt atteint aussi les iperf3 lancés par SYNTRAF
    if os.name == "nt":
        return subprocess.Popen(cmd, env=env, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    return subprocess.Popen(cmd, env=env, start_new_session=True)


def _stop(child, timeout=30):
    """Arrêt propre (SIGTERM, CTRL_BREAK : SYNTRAF arrête ses iperf3), puis forcé sur tout l'arbre de processus."""
    if child.poll() is not None:
        return
    try:
        if os.name == "nt":
            child.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(child.pid, signal.SIGTERM)
        child.wait(timeout)
    except (subprocess.TimeoutExpired, OSError):
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(child.pid), "/T", "/F"], capture_output=True)
        else:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except OSError:
                pass
        child.wait(10)


def supervise(base, argv, poll_s=5.0):
    """Boucle du processus lancé par le service : démarre la version courante, la surveille, la remplace."""
    child = None

    def stop(signum, _frame):
        if child is not None:
            _stop(child)
        sys.exit(128 + signum)

    for name in ("SIGTERM", "SIGINT", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), stop)

    while True:
        choice = choose(base)
        env = dict(os.environ, **{ENV_CHILD: "1", ENV_BASE: base, ENV_RELEASE: choice.release_id or ""})
        # Dossier courant hérité : les chemins relatifs passés en arguments (-c config.toml) restent valides
        child = _start([choice.python, os.path.join(choice.directory, "syntraf.py")] + list(argv), env)
        restart = False
        while child.poll() is None:
            time.sleep(poll_s)
            state = read_state(base)
            if state.get("restart"):
                state["restart"] = False
                _write_state(base, state)
                _stop(child)
                restart = True
            elif overdue(base):
                _stop(child)
                rollback(base, reason=f"not confirmed within {CONFIRM_GRACE_S} s")
                restart = True
        if restart:
            continue
        code = child.returncode
        if code == EXIT_RESTART:
            continue  # nouvelle version installée : on la démarre
        if read_state(base)["pending"] and choice.release_id:
            continue  # la nouvelle version s'est arrêtée avant de confirmer : on retente (choose compte)
        return code

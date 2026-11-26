"""Releases de SYNTRAF : le serveur distribue sa propre version (« release intégrée »).

Une release est une archive tar.gz des sources (syntraf.py, lib/, requirements_*.txt), avec le dossier wheelhouse/
s'il existe (paquets Python pour installer un venv hors ligne chez les clients) et un manifest.json.
Son identité est « version+empreinte » : l'empreinte porte sur le code, si bien que deux codes différents ne
partagent jamais le même identifiant, même avec le même numéro de version.

Module sans dépendance externe : il est aussi utilisé par le démarrage supervisé des clients (st_updater).
"""
import gzip
import hashlib
import io
import json
import os
import tarfile

EXCLUDED_DIRS = {"venv", ".venv", ".git", ".idea", ".superpowers", "crypto", "log", "logs", "lab", "test", "tests",
                 "fake_data", "iperf3_temp", "doc", "docs", "proc", "releases", "__pycache__", "node_modules"}
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".pid", ".db", ".log")
WHEELHOUSE = "wheelhouse"
CLIENT_REQUIREMENTS = "requirements_client.txt"


class ReleaseError(Exception):
    pass


# Liste blanche : une release se télécharge sur le canal de contrôle ; seul le code y entre. (Avant, une liste
# d'exclusions y laissait passer .env, un config.toml posé à la racine, ses versions, ses jetons...)
INCLUDED_TOP_FILES = {"syntraf.py", "requirements_client.txt", "requirements_server.txt"}
INCLUDED_TOP_DIRS = {"lib"}
CODE_SUFFIXES = (".py", ".html", ".js", ".css", ".json", ".svg", ".png", ".jpg", ".gif", ".ico", ".woff", ".woff2",
                 ".ttf", ".eot", ".otf", ".map", ".txt", ".md")
SECRET_NAMES = ("syntraf_client_token", "syntraf_client_uid", "credentials")

# Release des sondes (profil « client ») : ni l'interface web ni les modules propres au serveur. Ce que le serveur
# distribue : une sonde n'en exécute rien, et l'interface pèse 98 % de la release complète.
PROFILES = ("full", "client")
# l'interface (lib/webui), et ses anciens noms : un dossier resté d'une ancienne installation n'est jamais envoyé
CLIENT_EXCLUDED_DIRS = ("lib/webui/", "lib/web_ui_kindafixed2/", "lib/web_ui/", "lib/webui_kindafixed/")
CLIENT_EXCLUDED_FILES = {"requirements_server.txt", "lib/st_mesh_group_ops.py", "lib/st_vm_admin.py",
                         "lib/st_db_factory.py", "lib/st_victoriametrics.py", "lib/st_capacity.py",
                         "lib/st_config_store.py", "lib/st_certs.py", "lib/st_flow_catalog.py"}


def _shippable(name):
    low = name.lower()
    return (low.endswith(CODE_SUFFIXES) and not low.startswith(".") and not low.endswith(".pending.json")
            and not low.startswith(SECRET_NAMES))


def _for_clients(rel):
    return rel not in CLIENT_EXCLUDED_FILES and not rel.startswith(CLIENT_EXCLUDED_DIRS)


def _included(root, profile="full"):
    """Fichiers de la release (chemins relatifs, triés), hors wheelhouse."""
    if profile not in PROFILES:
        raise ReleaseError(f"unknown release profile '{profile}'")
    out = [name for name in INCLUDED_TOP_FILES if os.path.isfile(os.path.join(root, name))]
    for top in INCLUDED_TOP_DIRS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(root, top)):
            dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_DIRS and not d.startswith((".", "venv")))
            rel_dir = os.path.relpath(dirpath, root)
            for name in filenames:
                if _shippable(name) and not name.endswith(EXCLUDED_SUFFIXES):
                    out.append(os.path.normpath(os.path.join(rel_dir, name)).replace(os.sep, "/"))
    if profile == "client":
        out = [rel for rel in out if _for_clients(rel)]
    return sorted(out)


def _wheels(root):
    directory = os.path.join(root, WHEELHOUSE)
    if not os.path.isdir(directory):
        return []
    return sorted(f"{WHEELHOUSE}/{n}" for n in os.listdir(directory) if os.path.isfile(os.path.join(directory, n)))


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def source_digest(root, profile="full"):
    """Empreinte du code : chemins et contenus des fichiers de la release (hors wheelhouse). Une sonde installée
    depuis la release client retrouve le même identifiant en calculant celui de ses propres fichiers."""
    h = hashlib.sha256()
    for rel in _included(root, profile):
        h.update(rel.encode() + b"\0")
        with open(os.path.join(root, rel), "rb") as f:
            h.update(hashlib.sha256(f.read()).digest())
    return h.hexdigest()


def release_id(root, version, profile="full"):
    return f"{version}+{source_digest(root, profile)[:10]}"


def requirements_sha256(root):
    path = os.path.join(root, CLIENT_REQUIREMENTS)
    return file_sha256(path) if os.path.isfile(path) else None


def build(root, out_dir, version, profile="full"):
    """Fabrique (ou retrouve) l'archive de la release du code de root. Reproductible : mêmes sources, même archive."""
    rid = release_id(root, version, profile)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"syntraf-{rid}.tar.gz")
    wheels = _wheels(root)
    manifest = {"id": rid, "version": version, "profile": profile, "has_wheelhouse": bool(wheels),
                "requirements_sha256": requirements_sha256(root)}
    if not os.path.isfile(path):
        tmp = path + ".tmp"
        with open(tmp, "wb") as raw:
            # gzip sans date ni nom de fichier, entrées triées et horodatées à 0 : archive reproductible
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w") as tar:
                    for rel in _included(root, profile) + wheels:
                        _add(tar, rel, open(os.path.join(root, rel), "rb").read())
                    _add(tar, "manifest.json", json.dumps(manifest, indent=1, sort_keys=True).encode())
        os.replace(tmp, path)
    return dict(manifest, path=path, sha256=file_sha256(path), size=os.path.getsize(path))


def _add(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = len(data), 0, 0o644
    tar.addfile(info, io.BytesIO(data))


def safe_extract(archive, dest):
    """Extrait une release : refuse les chemins hors de dest et tout ce qui n'est pas fichier ou dossier."""
    dest = os.path.abspath(dest)
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        for m in members:
            target = os.path.abspath(os.path.join(dest, m.name))
            if not (m.isfile() or m.isdir()):
                raise ReleaseError(f"unexpected entry type in the release: {m.name}")
            if os.path.isabs(m.name) or not (target == dest or target.startswith(dest + os.sep)):
                raise ReleaseError(f"entry outside of the release directory: {m.name}")
        os.makedirs(dest, exist_ok=True)
        for m in members:
            target = os.path.join(dest, m.name)
            if m.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with tar.extractfile(m) as src, open(target, "wb") as out:
                out.write(src.read())


_BUILTIN = {}
_BUILTIN_LOCK = __import__("threading").Lock()


def builtin(root, data_dir, version):
    """Release que le serveur distribue à ses sondes : son propre code, profil client (sans interface web),
    fabriquée une fois puis gardée en cache (sous <données>/releases/dist)."""
    with _BUILTIN_LOCK:
        info = _BUILTIN.get((str(root), version))
        if info is None or not os.path.isfile(info["path"]):
            info = build(str(root), os.path.join(str(data_dir), "releases", "dist"), version, profile="client")
            _BUILTIN[(str(root), version)] = info
        return info


def read_manifest(release_dir):
    with open(os.path.join(release_dir, "manifest.json"), encoding="utf-8") as f:
        return json.load(f)

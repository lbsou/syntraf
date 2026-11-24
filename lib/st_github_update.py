"""Mise à jour du serveur depuis les releases GitHub du projet.

Chaque jour (et à la demande), le serveur lit la dernière release de lbsou/syntraf. Une release installable apporte :
  syntraf-<id>.tar.gz              la release du code (lib/st_release.py, profil « full »)
  syntraf-release-<v>.json         son manifeste : version, id, fichier, sha256, taille
  syntraf-release-<v>.json.sig     la signature Ed25519 du manifeste, par la clé du projet (tools/release_key.py)
Elle n'est proposée que si elle est plus récente et signée par une clé de PUBLIC_KEYS. Sur un clic d'un
administrateur, le serveur la télécharge, vérifie signature, taille et empreinte, puis la confie au superviseur
(st_updater) : installée à côté de la version en place, elle démarre, et revient automatiquement à la précédente si
elle ne se confirme pas. Ensuite, la page Mises à jour diffuse cette version aux sondes, comme d'habitude.

Ne sont pas mis à jour par ce chemin : Python, iperf3v, VictoriaMetrics, Grafana (le package d'installation les
remplace : relancer install.sh d'une version plus récente).
"""
import base64
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
import time
import urllib.request

log = logging.getLogger("syntraf." + __name__)

REPOSITORY = "lbsou/syntraf"
API_BASE = os.environ.get("SYNTRAF_UPDATE_API") or "https://api.github.com"  # autre adresse : essais seulement
CHECK_EVERY_S = 24 * 3600
TIMEOUT_S = 60
MAX_ARCHIVE = 200 * 1024 * 1024
# Clé publique du projet (tools/release_key.py public) ; plusieurs clés possibles pour une rotation
PUBLIC_KEYS = [
    "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAZVFCQfMjLCQ2752aS2mSLeGPAHnUcdM3f5ta6rfCcMM=\n-----END PUBLIC KEY-----\n",
]
MANIFEST_FIELDS = ("version", "id", "file", "sha256", "size", "profile")
SAFE_FILE = re.compile(r"^syntraf-[0-9A-Za-z.+_-]+\.tar\.gz$")


class UpdateError(Exception):
    pass


def parse_version(text):
    nums = re.findall(r"\d+", str(text or ""))
    return tuple(int(n) for n in nums[:4]) if nums else ()


def is_newer(candidate, current):
    return parse_version(candidate) > parse_version(current)


def manifest_bytes(info):
    """Forme canonique du manifeste : c'est elle qui est signée."""
    return json.dumps({k: info[k] for k in MANIFEST_FIELDS}, sort_keys=True, separators=(",", ":")).encode()


def sign(manifest, private_key):
    return base64.b64encode(private_key.sign(manifest)).decode()


def verify(manifest, signature, keys=None):
    """Le manifeste (dict) s'il est signé par une clé du projet, sinon UpdateError."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    try:
        sig = base64.b64decode(signature.strip() if isinstance(signature, str) else signature.decode().strip())
    except (ValueError, UnicodeDecodeError):
        raise UpdateError("the release signature is unreadable")
    for pem in keys if keys is not None else PUBLIC_KEYS:
        try:
            serialization.load_pem_public_key(pem.encode()).verify(sig, manifest)
        except InvalidSignature:
            continue
        info = json.loads(manifest)
        if set(info) != set(MANIFEST_FIELDS) or not SAFE_FILE.match(str(info["file"])):
            raise UpdateError("the signed manifest is malformed")
        return info
    raise UpdateError("the release is not signed by the SYNTRAF project key: refused")


def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "syntraf-update", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
        data = r.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise UpdateError(f"{url} is too large")
    return data


def _latest(get, repository):
    data = json.loads(get(f"{API_BASE}/repos/{repository}/releases/latest"))
    version = ".".join(map(str, parse_version(data.get("tag_name"))))
    assets = {a.get("name"): a.get("browser_download_url") for a in data.get("assets") or []}
    return data, version, assets


def check(get, current, repository=REPOSITORY, keys=None):
    """État : {current, latest, available, url, published_at, checked_at, note, error} ; ne lève jamais."""
    status = {"current": current, "latest": None, "available": False, "url": None, "published_at": None,
              "checked_at": time.time(), "note": None, "error": None, "repository": repository}
    try:
        data, version, assets = _latest(get, repository)
    except (OSError, ValueError, UpdateError) as exc:
        status["error"] = f"GitHub unreachable or unreadable: {exc}"
        return status
    status.update(latest=version or None, url=data.get("html_url"), published_at=data.get("published_at"))
    if not version or not is_newer(version, current):
        return status
    name = f"syntraf-release-{version}.json"
    if name not in assets or f"{name}.sig" not in assets:
        status["note"] = (f"version {version} has no signed server release: install its package by hand "
                          f"(install.sh), it cannot be applied from here")
        return status
    try:
        verify(get(assets[name]), get(assets[f"{name}.sig"]), keys)
    except (OSError, UpdateError) as exc:
        status["note"] = f"version {version} cannot be applied: {exc}"
        return status
    status["available"] = True
    return status


def apply(get, current, base, python, repository=REPOSITORY, keys=None, stage=None, request_restart=None):
    """Télécharge et vérifie la dernière release, la confie au superviseur ; il bascule dans les secondes qui
    suivent (et revient en arrière si elle ne se confirme pas)."""
    if stage is None or request_restart is None:
        from lib import st_updater
        stage, request_restart = stage or st_updater.stage, request_restart or st_updater.request_restart
    _data, version, assets = _latest(get, repository)
    name = f"syntraf-release-{version}.json"
    if name not in assets or f"{name}.sig" not in assets:
        raise UpdateError(f"version {version} has no signed server release")
    info = verify(get(assets[name]), get(assets[f"{name}.sig"]), keys)
    if info["version"] != version or not is_newer(version, current):
        raise UpdateError(f"version {info['version']} is not newer than this server's {current}: refused")
    if info["file"] not in assets:
        raise UpdateError(f"the release archive {info['file']} is missing from the GitHub release")
    archive = get(assets[info["file"]])
    if len(archive) != int(info["size"]) or hashlib.sha256(archive).hexdigest() != info["sha256"]:
        raise UpdateError("the downloaded archive does not match its signed digest: refused")
    folder = os.path.join(base, "downloads")
    os.makedirs(folder, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="github-", suffix=".tar.gz", dir=folder)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(archive)
        stage(base, path, info["sha256"], info["id"], python)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass
    request_restart(base)
    log.warning(f"SERVER UPDATE FROM GITHUB: RELEASE {info['id']} INSTALLED, SWITCHING")
    return {"version": version, "release": info["id"]}


class Checker:
    """Vérification quotidienne, dans un fil à part ; l'état sert l'interface (page Mises à jour)."""

    def __init__(self):
        self.lock, self.last, self.running = threading.Lock(), None, False
        self.status = None

    def maybe(self, config, current, now=None, force=False):
        now = now if now is not None else time.time()
        g = (config or {}).get("GLOBAL", {}) or {}
        if not force and str(g.get("UPDATE_CHECK", True)).lower() in ("false", "0", "no", "off"):
            return False
        with self.lock:
            if self.running or (not force and self.last is not None and now - self.last < CHECK_EVERY_S):
                return False
            self.last, self.running = now, True
        repo = str(g.get("UPDATE_REPOSITORY") or REPOSITORY)
        threading.Thread(target=self._run, args=(current, repo), name="GITHUB_UPDATE_CHECK", daemon=True).start()
        return True

    def run_now(self, config, current):
        repo = str(((config or {}).get("GLOBAL", {}) or {}).get("UPDATE_REPOSITORY") or REPOSITORY)
        self.status = check(http_get, current, repo)
        self.last = time.time()
        return self.status

    def _run(self, current, repo):
        try:
            self.status = check(http_get, current, repo)
            if self.status.get("available"):
                log.warning(f"SYNTRAF {self.status['latest']} IS AVAILABLE (THIS SERVER: {current}): "
                            f"UPDATES PAGE, « UPDATE THIS SERVER »")
        finally:
            with self.lock:
                self.running = False


CHECKER = Checker()

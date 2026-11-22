"""Écriture du fichier de configuration du serveur, avec historique des versions et journal d'audit.

À côté de config.toml :
  config.toml.history/<horodatage>.toml   une copie par version écrite (les HISTORY_LIMIT plus récentes)
  config.toml.audit.jsonl                 une ligne JSON par changement : quand, qui, quoi, version, diff
"""
import datetime as dt
import difflib
import json
import os
import re
import shutil
import tempfile

from lib.st_files import open_private

import toml

HISTORY_LIMIT = 200
_LISTENERS = {}  # nom -> fonction(entrée d'audit), ex. l'écriture des changements dans les bases (repères Grafana)
MASK = "••••••••"
_SECRET_RE = re.compile(r"TOKEN|PASSWORD|SECRET|KEY", re.IGNORECASE)
_ASSIGN_RE = re.compile(r"^(\s*)([^=\s#\[][^=]*?)(\s*=\s*)(.*?)(\r?\n?)$")
_VERSION_RE = re.compile(r"^\d{8}T\d{12}Z(-\d+)?\.toml$")


def history_dir(path):
    return path + ".history"


def audit_path(path):
    return path + ".audit.jsonl"


def save(path, config, actor, action, summary, now=None):
    """Écrit config (dict) dans path de façon atomique, en garde une version et journalise le changement.

    Renvoie l'entrée d'audit écrite.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    return save_text(path, toml.dumps(config), actor, action, summary, now)


def save_text(path, new_text, actor, action, summary, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    old_text = _read(path)
    if old_text is not None and not versions(path):
        # Première écriture : on garde l'original, pour pouvoir y revenir.
        _snapshot(path, old_text, now - dt.timedelta(microseconds=1))
    _atomic_write(path, new_text)
    version = _snapshot(path, new_text, now)
    entry = {"time": now.isoformat(), "actor": actor, "action": action, "summary": summary, "version": version,
             "diff": redacted_diff(old_text or "", new_text)}
    with open(audit_path(path), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    _prune(path)
    _announce(entry)
    return entry


def set_listener(name, fn):
    """Abonne (ou désabonne, fn=None) une fonction aux nouvelles entrées du journal d'audit."""
    if fn is None:
        _LISTENERS.pop(name, None)
    else:
        _LISTENERS[name] = fn


def _announce(entry):
    for fn in list(_LISTENERS.values()):
        try:
            fn(entry)
        except Exception:  # noqa: BLE001 - un abonné défaillant n'empêche pas l'écriture de la config
            pass


def log_event(path, actor, action, summary, now=None):
    """Entrée d'audit pour une action qui ne modifie pas le fichier (purge de données, instantané...)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    entry = {"time": now.isoformat(), "actor": actor, "action": action, "summary": summary, "version": None,
             "diff": ""}
    with open(audit_path(path), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    _announce(entry)
    return entry


def redact(text):
    """Texte TOML avec les valeurs secrètes masquées : clés dont le nom évoque un secret, et toutes les clés d'une
    section dont le nom en évoque un (ex. [SERVER.TOKEN], dont les clés sont des noms de sites)."""
    out, secret_section = [], False
    for line in (text or "").splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith("["):
            secret_section = bool(_SECRET_RE.search(stripped))
            out.append(line)
            continue
        m = _ASSIGN_RE.match(line)
        if m and (secret_section or _SECRET_RE.search(m.group(2))):
            out.append(f'{m.group(1)}{m.group(2)}{m.group(3)}"{MASK}"{m.group(5)}')
        else:
            out.append(line)
    return "".join(out)


def redacted_diff(old, new, old_name="before", new_name="after"):
    return diff_text(redact(old), redact(new), old_name, new_name)


def diff_text(old, new, old_name="before", new_name="after"):
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        old_name, new_name))


def versions(path):
    """Versions gardées, de la plus récente à la plus ancienne : [{"version", "time", "size"}]."""
    d = history_dir(path)
    if not os.path.isdir(d):
        return []
    names = sorted((n for n in os.listdir(d) if _VERSION_RE.match(n)), key=_sort_key, reverse=True)
    return [{"version": n, "time": _time_of(n), "size": os.path.getsize(os.path.join(d, n))} for n in names]


def read_version(path, version):
    if not _VERSION_RE.match(version or "") or not os.path.isfile(os.path.join(history_dir(path), version)):
        raise KeyError(version)
    with open(os.path.join(history_dir(path), version), encoding="utf-8") as f:
        return f.read()


def audit_entries(path, limit=100):
    """Dernières entrées du journal d'audit, la plus récente d'abord."""
    p = audit_path(path)
    if not os.path.isfile(p):
        return []
    with open(p, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    entries = []
    for line in reversed(lines[-limit:] if limit else lines):
        try:
            entries.append(json.loads(line))
        except ValueError:
            continue
    return entries


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _atomic_write(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".config-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)  # la configuration contient les jetons : lisible par le seul propriétaire
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _snapshot(path, text, now):
    d = history_dir(path)
    os.makedirs(d, exist_ok=True)
    base = now.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    name, n = f"{base}.toml", 0
    while os.path.exists(os.path.join(d, name)):
        n += 1
        name = f"{base}-{n}.toml"
    with open_private(os.path.join(d, name)) as f:  # une version contient les jetons en clair
        f.write(text)
    return name


def _prune(path):
    for v in versions(path)[HISTORY_LIMIT:]:
        os.unlink(os.path.join(history_dir(path), v["version"]))


def _sort_key(name):
    stem = name[:-len(".toml")]
    base, _, n = stem.partition("-")
    return base, int(n or 0)


def _time_of(name):
    return dt.datetime.strptime(name[:21], "%Y%m%dT%H%M%S%f").replace(tzinfo=dt.timezone.utc).isoformat()

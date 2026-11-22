"""Recherche dans les journaux du serveur et des clients (LOGDIR/syntraf.log*, LOGDIR/clients/<UID>/syntraf.log*).

Chaque entrée : nœud, heure (ISO avec fuseau), niveau, module, type, message, et les lignes de suite (traceback).
Types : control (canal de contrôle), measurement (iperf3, pertes), database, config (configuration), webui, system.
"""
import collections
import datetime as dt
import os
import re
import shlex

from lib.st_log_store import CLIENTS_DIR, FILENAME

LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
TYPES = ("control", "measurement", "database", "config", "webui", "system")
LINE_RE = re.compile(r"^\s?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[+-]\d{4})?) - (DEBUG|INFO|WARNING|ERROR|CRITICAL) - "
                     r"(\S+) \(([^)]*)\) - (.*)$")
MODULE_TYPES = (
    # en premier : st_mesh_group_ops commence comme st_mesh (canal de contrôle)
    (re.compile(r"^(st_conf_validation|st_mesh_group_ops|st_config_store|st_read_toml|st_capacity|st_topology)"),
     "config"),
    (re.compile(r"^(st_mesh|st_cc_|st_crypto|st_obj_cc)"), "control"),
    (re.compile(r"^(st_iperf|st_outage|st_obj_process|st_stats|st_system_stats)"), "measurement"),
    (re.compile(r"^(st_influx|st_victoria|st_db)"), "database"),
    (re.compile(r"^(pywsgi|st_home_bp|st_api|app|web_ui)"), "webui"),
)
MAX_LINES_PER_FILE = 50_000
LOCAL_TZ = None  # fuseau des lignes sans décalage (ancien format) : celui du système qui les a écrites, par défaut


def parse_time(text):
    """Horodatage d'une ligne ; sans décalage (ancien format), c'est l'heure locale du serveur."""
    for fmt in ("%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            t = dt.datetime.strptime(text.strip(), fmt)
            if t.tzinfo:
                return t
            return t.replace(tzinfo=LOCAL_TZ) if LOCAL_TZ else t.astimezone()
        except ValueError:
            continue
    return None


def log_type(module):
    for pattern, kind in MODULE_TYPES:
        if pattern.match(module):
            return kind
    return "system"


def nodes(logdir):
    """« server », puis chaque client qui a envoyé des journaux."""
    found = ["server"] if os.path.isfile(os.path.join(logdir, FILENAME)) else []
    clients = os.path.join(logdir, CLIENTS_DIR)
    if os.path.isdir(clients):
        found += sorted(d for d in os.listdir(clients) if os.path.isdir(os.path.join(clients, d)))
    return found


def _files(logdir, node):
    directory = logdir if node == "server" else os.path.join(logdir, CLIENTS_DIR, node)
    if not os.path.isdir(directory):
        return []
    names = [n for n in os.listdir(directory) if n == FILENAME or re.match(re.escape(FILENAME) + r"\.\d+$", n)]
    # du plus ancien au plus récent : syntraf.log.N ... syntraf.log.1, syntraf.log
    names.sort(key=lambda n: -int(n.rsplit(".", 1)[1]) if n != FILENAME else 0)
    return [os.path.join(directory, n) for n in names]


def _entries(path, node):
    entry = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in collections.deque(f, maxlen=MAX_LINES_PER_FILE):
            line = raw.rstrip("\n")
            m = LINE_RE.match(line)
            if m:
                if entry:
                    yield entry
                when = parse_time(m.group(1))
                entry = {"node": node, "time": when.isoformat() if when else m.group(1), "_t": when,
                         "level": m.group(2), "module": m.group(3), "where": m.group(4),
                         "type": log_type(m.group(3)), "message": m.group(5), "detail": ""}
            elif entry is not None and line.strip():
                entry["detail"] += line + "\n"
    if entry:
        yield entry


def _matcher(query):
    """Mots (tous requis, sans casse), "expression exacte", -mot exclu."""
    try:
        terms = shlex.split(query or "")
    except ValueError:
        terms = (query or "").split()
    required = [t.lower() for t in terms if not t.startswith("-") or len(t) == 1]
    excluded = [t[1:].lower() for t in terms if t.startswith("-") and len(t) > 1]

    def match(entry):
        text = f"{entry['message']}\n{entry['detail']}\n{entry['module']}".lower()
        return all(t in text for t in required) and not any(t in text for t in excluded)
    return match


def search(logdir, nodes=None, types=None, level="", query="", since=None, until=None, limit=1000):
    """Entrées correspondant à tous les filtres, les plus récentes d'abord (au plus `limit`)."""
    wanted_nodes = nodes or globals()["nodes"](logdir)
    min_level = LEVELS.index(level.upper()) if (level or "").upper() in LEVELS else 0
    match = _matcher(query)
    found = []
    for node in wanted_nodes:
        for path in _files(logdir, node):
            for e in _entries(path, node):
                if types and e["type"] not in types:
                    continue
                if LEVELS.index(e["level"]) < min_level:
                    continue
                if since and e["_t"] and e["_t"] < since:
                    continue
                if until and e["_t"] and e["_t"] > until:
                    continue
                if match(e):
                    found.append(e)
    epoch = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    found.sort(key=lambda e: e["_t"] or epoch, reverse=True)
    out = found[:limit]
    for e in out:
        t = e.pop("_t")
        if t:
            e["time"] = t.astimezone(dt.timezone.utc).isoformat()  # UTC : le navigateur affiche l'heure locale
    return out

"""Fenêtres de maintenance, par sonde ou par mesh group : pendant une fenêtre, aucune alerte ne s'ouvre pour les flux
qui touchent la sonde (comme source ou destination) ou qui appartiennent au groupe, ni pour la santé de la sonde
(déconnectée, mesures en attente). Les mesures continuent ; Grafana montre la fenêtre en zone « Maintenance ».

Section [[MAINTENANCE]] : UID, TARGET_TYPE (node ou mesh_group), TARGET, MODE (once : START et END, date et heure du
serveur « 2026-11-23T10:00 » ; weekly : DAYS parmi mon…sun, FROM et TO « HH:MM », une plage qui passe minuit
continue le lendemain), ENABLED, DESCRIPTION. Bibliothèque standard uniquement.
"""
import datetime as dt
import re

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
UID_RE = re.compile(r"^[A-Za-z0-9_-]{4,50}$")
HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _minutes(text):
    h, m = str(text).split(":")
    return int(h) * 60 + int(m)


def _when(text):
    try:
        return dt.datetime.fromisoformat(str(text).strip())
    except ValueError:
        return None


def enabled(w):
    return w.get("ENABLED", True) is not False and str(w.get("ENABLED", "true")).lower() != "false"


def active(w, now):
    if not enabled(w):
        return False
    t = dt.datetime.fromtimestamp(now)
    if (w.get("MODE") or "once") == "once":
        start, end = _when(w.get("START")), _when(w.get("END"))
        return bool(start and end and start <= t < end)
    days = {d.lower()[:3] for d in (w.get("DAYS") or [])}
    start, end, minute = _minutes(w.get("FROM", "00:00")), _minutes(w.get("TO", "00:00")), t.hour * 60 + t.minute
    today, yesterday = DAYS[t.weekday()], DAYS[(t.weekday() - 1) % 7]
    if start <= end:
        return today in days and start <= minute < end
    # passe minuit : le soir du jour prévu, ou le petit matin qui suit
    return (today in days and minute >= start) or (yesterday in days and minute < end)


class Maintenance:
    """Fenêtres actives à l'instant now."""

    def __init__(self, windows, now):
        self.windows = [w for w in windows or [] if active(w, now)]
        self.nodes = {w.get("TARGET") for w in self.windows if w.get("TARGET_TYPE") == "node"}
        self.groups = {w.get("TARGET") for w in self.windows if w.get("TARGET_TYPE") == "mesh_group"}

    def covers_flow(self, group, source, destination):
        return group in self.groups or source in self.nodes or destination in self.nodes

    def covers_node(self, node):
        return node in self.nodes

    def active_uids(self):
        return sorted(w.get("UID") for w in self.windows)


_CACHE = {"path": None, "mtime": None, "windows": []}


def load(config_path):
    """Fenêtres écrites dans le fichier de configuration (relues seulement quand il change)."""
    import os
    if not config_path:
        return []
    try:
        mtime = os.path.getmtime(config_path)
    except OSError:
        return []
    if _CACHE["path"] != config_path or _CACHE["mtime"] != mtime:
        try:
            import toml
            windows = toml.load(config_path).get("MAINTENANCE", [])
        except Exception:  # noqa: BLE001 - fichier en cours d'écriture : on garde la dernière lecture
            return _CACHE["windows"]
        _CACHE.update(path=config_path, mtime=mtime, windows=windows)
    return _CACHE["windows"]


def field_errors(v, nodes=(), groups=(), with_uid=True):
    e = {}
    get = lambda k: str(v.get(k, "") or "").strip()  # noqa: E731
    if with_uid and not UID_RE.match(get("UID")):
        e["UID"] = "4 to 50 letters, digits, '_' or '-'"
    kind = get("TARGET_TYPE") or "node"
    if kind not in ("node", "mesh_group"):
        e["TARGET_TYPE"] = "node or mesh_group"
    elif get("TARGET") not in (set(nodes) if kind == "node" else set(groups)):
        e["TARGET"] = "A declared probe" if kind == "node" else "An existing mesh group"
    mode = get("MODE") or "once"
    if mode == "once":
        start, end = _when(get("START")), _when(get("END"))
        if start is None:
            e["START"] = "A date and time, e.g. 2026-11-23T22:00"
        if end is None:
            e["END"] = "A date and time, e.g. 2026-11-24T02:00"
        elif start is not None and end <= start:
            e["END"] = "After the start"
    elif mode == "weekly":
        days = v.get("DAYS") or []
        if not days or any(str(d).lower()[:3] not in DAYS for d in days):
            e["DAYS"] = "One or more of mon, tue, wed, thu, fri, sat, sun"
        for key in ("FROM", "TO"):
            if not HHMM.match(get(key)):
                e[key] = "HH:MM, e.g. 02:00"
        if not e.get("FROM") and not e.get("TO") and get("FROM") == get("TO"):
            e["TO"] = "Different from the start"
    else:
        e["MODE"] = "once or weekly"
    return e

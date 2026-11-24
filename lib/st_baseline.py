"""Baseline de chaque flux pour chaque métrique, et alertes quand une mesure en sort (dans le mauvais sens).

La norme d'un flux : médiane et écart robuste (MAD × 1.4826) de ses 7 derniers jours (moyennes de 5 min), insensibles
aux pannes passées ; par heure du jour dès 3 jours d'historique (une heure chargée ne se compare qu'aux mêmes heures).
Hors baseline : la moyenne des 5 dernières minutes s'écarte de la médiane, du côté du pire, de plus que
max(k × écart, marge minimale de la métrique) ; la marge évite qu'un flux toujours à 0 % de pertes alerte à 0,1 %.
Une alerte s'ouvre après OPEN_AFTER minutes hors baseline et se ferme après CLOSE_AFTER minutes franchement revenues
(à moins de la moitié du seuil) : pas de clignotement. Pas de norme (apprentissage) avant 24 h d'historique ; un
changement des paramètres du groupe (débit, taille de paquet, DSCP, intervalle) relance l'apprentissage.

Le silence (plus aucune mesure) n'est pas jugé ici : c'est une panne, signalée en absolu par les tableaux de bord.

Détecteurs interchangeables (DETECTORS) : un détecteur ne fait que fournir la norme d'une série ; le jugement, les
marges et les alertes sont communs. Un détecteur appris (ML) ne s'ajoute que s'il fait mieux que « robust » sur le banc
d'essai du lab (lab/bench_alerts.py : pannes injectées à des instants connus).

Points publiés : SYNTRAF_BASELINE{MESH_GROUP, CLIENT, SERVER, METRIC} = MEDIAN, LIMIT (seuil d'alerte), CURRENT, SCORE
(écart / seuil : au-delà de 1, hors baseline). Bibliothèque standard uniquement.
"""
import collections
import datetime as dt
import logging
import statistics
import threading
import time

log = logging.getLogger("syntraf." + __name__)

LEARN_S = 24 * 3600
SEASONAL_AFTER_S = 3 * 24 * 3600
MIN_BUCKET = 30
HISTORY_S = 7 * 24 * 3600
STEP_S = 300
RECENT_S = 300             # la mesure jugée : moyenne des 5 dernières minutes
EXCLUDE_S = 900            # l'historique s'arrête 15 min avant : une dérive en cours ne devient pas sa propre norme
DEFAULT_K = 4.0
OPEN_AFTER = 3
CLOSE_AFTER = 3
PERIOD_S = 60

Spec = collections.namedtuple("Spec", "name label unit metric worse abs_margin rel_margin keys window")
METRICS = {
    "loss": Spec("loss", "Loss", " %", "SYNTRAF_RX_PCT_LOSS", "up", 1.0, 0.0, "MESH_GROUP,CLIENT,SERVER", "5m"),
    "jitter": Spec("jitter", "Jitter", " ms", "SYNTRAF_RX_JITTER", "up", 2.0, 0.5, "MESH_GROUP,CLIENT,SERVER", "5m"),
    "rtt": Spec("rtt", "Round trip", " ms", "SYNTRAF_LATENCY_RTT_MS", "up", 10.0, 0.25, "MESH_GROUP,CLIENT,SERVER", "5m"),
    "mos": Spec("mos", "MOS", "", "SYNTRAF_RX_MOS", "down", 0.3, 0.0, "MESH_GROUP,CLIENT,SERVER", "5m"),
    # un point par test planifié : la norme est celle des tests précédents, la valeur jugée le dernier test
    "tcp": Spec("tcp", "TCP bitrate", " Mbit/s", "SYNTRAF_TCP_BITRATE_MBPS", "down", 0.0, 0.3,
                "MESH_GROUP,CLIENT,SERVER,DIRECTION,TEST", "2h"),
}

Baseline = collections.namedtuple("Baseline", "median spread n seasonal")


class Verdict(collections.namedtuple("Verdict", "anomalous score explanation current median limit")):
    __slots__ = ()

    def __new__(cls, anomalous, score, explanation, current=None, median=None, limit=None):
        return super().__new__(cls, anomalous, score, explanation, current, median, limit)


def robust(values):
    """(médiane, écart robuste) : MAD × 1.4826, l'écart-type d'une loi normale, mais insensible aux valeurs aberrantes."""
    values = list(values)
    median = statistics.median(values)
    return median, 1.4826 * statistics.median(abs(v - median) for v in values)


def since(points, t):
    return [(ts, v) for ts, v in points if ts >= t]


class RobustDetector:
    name = "robust"

    def baseline(self, points, now):
        if not points or now - points[0][0] < LEARN_S:
            return None
        values, seasonal = [v for _, v in points], False
        if now - points[0][0] >= SEASONAL_AFTER_S:
            hour = dt.datetime.fromtimestamp(now).hour
            bucket = [v for ts, v in points if dt.datetime.fromtimestamp(ts).hour == hour]
            if len(bucket) >= MIN_BUCKET:
                values, seasonal = bucket, True
        median, spread = robust(values)
        return Baseline(median, spread, len(values), seasonal)


DETECTORS = {"robust": RobustDetector}


def detector(name):
    return DETECTORS[name]()


def _fmt(v):
    return f"{v:.2f}".rstrip("0").rstrip(".") if abs(v) < 100 else f"{v:.0f}"


def judge(spec, base, current, k=DEFAULT_K, margin=None):
    """margin : marge minimale réglée (Server › Global) ; pour le débit TCP, en % de la norme."""
    sign = 1 if spec.worse == "up" else -1
    deviation = (current - base.median) * sign
    if margin is None:
        margin = max(spec.abs_margin, spec.rel_margin * abs(base.median))
    elif spec.name == "tcp":
        margin = margin / 100.0 * abs(base.median)
    else:
        margin = max(margin, spec.rel_margin * abs(base.median))
    limit = max(k * base.spread, margin, 1e-9)
    score = deviation / limit
    label, now_v, usual = spec.label, f"{_fmt(current)}{spec.unit}", f"{_fmt(base.median)}{spec.unit}"
    edge = f"{_fmt(base.median + sign * limit)}{spec.unit}"
    # Phrases entières (l'interface les traduit telles quelles, valeurs comprises)
    if sign > 0 and base.seasonal:
        explanation = f"{label} {now_v} instead of {usual} usually at this hour (alert above {edge})"
    elif sign > 0:
        explanation = f"{label} {now_v} instead of {usual} usually (alert above {edge})"
    elif base.seasonal:
        explanation = f"{label} {now_v} instead of {usual} usually at this hour (alert below {edge})"
    else:
        explanation = f"{label} {now_v} instead of {usual} usually (alert below {edge})"
    return Verdict(deviation > limit, score, explanation, current, base.median, limit)


class AlertBook:
    """État des alertes, avec hystérésis : ouverte après open_after jugements hors baseline de suite, fermée après
    close_after jugements franchement revenus (score < 0.5)."""

    def __init__(self, open_after=OPEN_AFTER, close_after=CLOSE_AFTER, keep=200):
        self.open_after, self.close_after = open_after, close_after
        self.state, self._open, self._recent = {}, {}, collections.deque(maxlen=keep)
        self.lock = threading.Lock()

    def update(self, key, verdict, now, info=None):
        with self.lock:
            st = self.state.setdefault(key, {"bad": 0, "good": 0})
            if verdict.anomalous:
                st["bad"], st["good"] = st["bad"] + 1, 0
            else:
                st["bad"] = 0
                st["good"] = st["good"] + 1 if verdict.score < 0.5 else 0
            alert, events = self._open.get(key), []
            if alert is not None:
                alert.update(last_at=now, explanation=verdict.explanation if verdict.anomalous else alert["explanation"],
                             score=round(max(alert["score"], verdict.score), 2))
                if st["good"] >= self.close_after:
                    alert["closed_at"] = now
                    self._recent.appendleft(self._open.pop(key))
                    events.append("close")
            elif st["bad"] >= self.open_after:
                self._open[key] = dict(info or {}, key=list(key), opened_at=now, last_at=now, closed_at=None,
                                       explanation=verdict.explanation, score=round(verdict.score, 2))
                events.append("open")
            return events

    def forget(self, keys_alive):
        """Flux qui n'existent plus (groupe retiré) : leurs alertes se ferment."""
        with self.lock:
            for key in [k for k in self._open if k not in keys_alive]:
                alert = self._open.pop(key)
                alert["closed_at"] = alert["last_at"]
                self._recent.appendleft(alert)
            for key in [k for k in self.state if k not in keys_alive]:
                del self.state[key]

    def open_keys(self):
        with self.lock:
            return set(self._open)

    def open(self):
        with self.lock:
            return sorted((dict(a) for a in self._open.values()), key=lambda a: a["opened_at"], reverse=True)

    def recent(self, limit=50):
        with self.lock:
            return [dict(a) for a in list(self._recent)[:limit]]


# --------------------------------------------------------------------------------- lecture dans VictoriaMetrics

def _key(spec, metric):
    return tuple(metric.get(k, "") for k in spec.keys.split(",")) + (spec.name,)


def history(vm, spec, now):
    q = f"avg by ({spec.keys}) (avg_over_time({spec.metric}[{STEP_S}s]))" if spec.name != "tcp" else \
        f"last_over_time({spec.metric}[{STEP_S}s])"
    out = {}
    for serie in vm.query_range(q, now - HISTORY_S, now - EXCLUDE_S, STEP_S):
        pts = [(float(t), float(v)) for t, v in serie.get("values", [])]
        if spec.name == "tcp":  # un point par test, pas un par pas de requête
            pts = [p for i, p in enumerate(pts) if i == 0 or p[1] != pts[i - 1][1]]
        out[_key(spec, serie["metric"])] = pts
    return out


def current(vm, spec):
    q = f"avg by ({spec.keys}) (avg_over_time({spec.metric}[{RECENT_S}s]))" if spec.name != "tcp" else \
        f"last_over_time({spec.metric}[{spec.window}])"
    return {_key(spec, s["metric"]): float(s["value"][1]) for s in vm.query(q)}


def group_resets(vm, now):
    """Dernier changement des paramètres de chaque groupe (au plus 7 jours) : l'historique repart de là."""
    # Regroupé par groupe et par métrique avant de chercher un changement : le nombre de membres et de flux sont des
    # étiquettes, un nouveau membre crée de nouvelles séries sans qu'aucune valeur ne change
    names = '{__name__=~"SYNTRAF_GROUP_(BANDWIDTH_KBPS|PACKET_SIZE|DSCP|INTERVAL)"}'
    q = (f"max by (MESH_GROUP) (tlast_change_over_time((max by (MESH_GROUP, __name__) ({names}))"
         f"[{HISTORY_S}s:{STEP_S}s]))")
    try:
        return {s["metric"].get("MESH_GROUP"): float(s["value"][1]) for s in vm.query(q)}
    except Exception as exc:  # noqa: BLE001 - sans cette information, on garde tout l'historique
        log.debug(f"BASELINE: GROUP CHANGES NOT READ: {exc}")
        return {}


# Réglages (Server › Global, et sensibilité propre au profil d'un groupe) : clé → (spec, défaut)
MARGIN_KEYS = {"loss": "BASELINE_MARGIN_LOSS", "jitter": "BASELINE_MARGIN_JITTER", "rtt": "BASELINE_MARGIN_RTT",
               "mos": "BASELINE_MARGIN_MOS", "tcp": "BASELINE_MARGIN_TCP"}


def _number(value, default, low=None, high=None):
    try:
        v = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    if (low is not None and v < low) or (high is not None and v > high):
        return default
    return v


class Settings:
    def __init__(self, k=DEFAULT_K, margins=None, open_after=OPEN_AFTER, close_after=CLOSE_AFTER, k_by_group=None):
        self.k, self.margins = k, dict(margins or {})
        self.open_after, self.close_after = int(open_after), int(close_after)
        self.k_by_group = dict(k_by_group or {})

    @classmethod
    def from_config(cls, config):
        g = (config or {}).get("GLOBAL", {}) or {}
        k = _number(g.get("BASELINE_SENSITIVITY"), DEFAULT_K, 1, 10)
        margins = {}
        for metric, key in MARGIN_KEYS.items():
            if str(g.get(key, "") or "").strip():
                value = _number(g.get(key), None, 0, 100 if metric == "tcp" else None)
                if value is not None:
                    margins[metric] = value
        profiles = {p.get("UID"): p for p in (config or {}).get("IPERF3_PROFILE", []) or []}
        k_by_group = {}
        for group in (config or {}).get("MESH_GROUP", []) or []:
            own = profiles.get(group.get("IPERF3_PROFILE"), {}).get("BASELINE_SENSITIVITY")
            if str(own or "").strip():
                k_by_group[group.get("UID")] = _number(own, k, 1, 10)
        return cls(k, margins, _number(g.get("BASELINE_OPEN_AFTER"), OPEN_AFTER, 1, 60),
                   _number(g.get("BASELINE_CLOSE_AFTER"), CLOSE_AFTER, 1, 60), k_by_group)

    def k_for(self, group):
        return self.k_by_group.get(group, self.k)

    def margin(self, metric):
        return self.margins.get(metric, METRICS[metric].abs_margin if metric != "tcp" else
                                METRICS[metric].rel_margin * 100)


STATUS = {"watched": 0, "learning": 0, "in_maintenance": 0, "maintenance_windows": [], "evaluated_at": None, "detector": "robust", "sensitivity": DEFAULT_K}
BOOK = AlertBook()


def evaluate(vm, now=None, det=None, book=BOOK, k=None, specs=None, write=None, settings=None, maintenance=None):
    now = now if now is not None else time.time()
    det = det or RobustDetector()
    if settings is not None:  # délais réglés ; sinon ceux du carnet
        book.open_after, book.close_after = settings.open_after, settings.close_after
    settings = settings or Settings(k if k is not None else DEFAULT_K)
    resets = group_resets(vm, now)
    alive, watched, learning, points, paused = set(), 0, 0, [], 0
    for spec in (specs or METRICS.values()):
        hist, cur = history(vm, spec, now), current(vm, spec)
        for key, value in cur.items():
            alive.add(key)
            info_keys = dict(zip(spec.keys.split(","), key))
            if maintenance is not None and maintenance.covers_flow(info_keys.get("MESH_GROUP"), info_keys.get("CLIENT"),
                                                                   info_keys.get("SERVER")):
                paused += 1  # fenêtre de maintenance : pas d'alerte (l'état reste, sans nouveau jugement)
                continue
            pts = since(hist.get(key, []), resets.get(key[0], 0))
            base = det.baseline(pts, now)
            if base is None:
                learning += 1
                continue
            watched += 1
            verdict = judge(spec, base, value, settings.k_for(key[0]),
                            settings.margins.get(spec.name))
            info = dict(zip(spec.keys.split(","), key), METRIC=spec.name, LABEL=spec.label, KIND="baseline")
            for event in book.update(key, verdict, now, info):
                flow = f"{info.get('CLIENT')} → {info.get('SERVER')}"
                action = "OPENED" if event == "open" else "CLOSED"
                (log.warning if event == "open" else log.info)(
                    f"ALERT {action}: {info.get('MESH_GROUP')} {flow} {spec.label.upper()}: {verdict.explanation}")
                # Repère sur les courbes de Grafana (annotation « Alertes »)
                points.append({"measurement": "SYNTRAF_ALERT", "time": dt.datetime.fromtimestamp(now, dt.timezone.utc),
                               "tags": {"ACTION": action, "MESH_GROUP": info.get("MESH_GROUP", ""),
                                        "METRIC": spec.name, "FLOW": flow, "SUMMARY": verdict.explanation[:200]},
                               "fields": {"EVENT": 1}})
            points.append({"measurement": "SYNTRAF_BASELINE", "time": dt.datetime.fromtimestamp(now, dt.timezone.utc),
                           "tags": {k2: v for k2, v in info.items() if k2 not in ("LABEL", "KIND")},
                           "fields": {"MEDIAN": base.median, "LIMIT": verdict.median + verdict.limit *
                                      (1 if spec.worse == "up" else -1), "CURRENT": value,
                                      "SCORE": round(verdict.score, 3),
                                      "ALERT": 1 if key in book.open_keys() else 0}})
    book.forget(alive)
    STATUS.update(watched=watched, learning=learning, evaluated_at=now, detector=det.name, sensitivity=settings.k,
                  in_maintenance=paused,
                  maintenance_windows=maintenance.active_uids() if maintenance is not None else [])
    if write and points:
        write(points)
    return STATUS


# ------------------------------------------------------------------------------------- santé de SYNTRAF

PROBE_BACKLOG = 1000      # mesures en attente chez une sonde (elles n'arrivent plus au serveur)
DATABASE_BACKLOG = 10000  # points en attente d'écriture dans une base
SERVER_QUEUE = 10000      # mesures reçues que le serveur n'a pas encore transmises
HEALTH_BOOK = AlertBook()


def health_checks(snap):
    """Contrôles absolus de l'outil lui-même (pas de baseline) : sondes déclarées déconnectées ou qui n'arrivent plus
    à envoyer leurs mesures, bases injoignables ou en retard, fils du serveur arrêtés, file du serveur qui gonfle."""
    out = []

    def check(metric, subject, bad, explanation):
        out.append({"metric": metric, "subject": subject, "anomalous": bool(bad), "explanation": explanation})
    for c in snap.get("clients", []):
        if not c.get("declared"):
            continue
        uid = c["uid"]
        since = c.get("status_since") or "?"
        check("probe_disconnected", uid, c.get("status") != "CONNECTED", f"Probe {uid} disconnected since {since}")
        backlog = c.get("metrics_buffer") or 0
        check("probe_backlog", uid, backlog > PROBE_BACKLOG,
              f"{backlog} measurements waiting on probe {uid} (they do not reach the server)")
    for d in snap.get("databases", []):
        uid = d["uid"]
        check("database_down", uid, d.get("status") != "ONLINE", f"Database {uid} unreachable")
        backlog = d.get("backlog") or 0
        check("database_backlog", uid, backlog > DATABASE_BACKLOG, f"{backlog} points waiting to be written to database {uid}")
    for t in snap.get("threads", []):
        name = t["name"]
        check("thread_dead", name, not t.get("alive"), f"Server thread {name} is not running")
    queue = snap.get("queue_length") or 0
    check("server_queue", "server", queue > SERVER_QUEUE, f"{queue} measurements received and not yet forwarded by the server")
    return out


def evaluate_health(snap, now=None, book=HEALTH_BOOK, write=None, settings=None, maintenance=None):
    now = now if now is not None else time.time()
    if settings is not None:
        book.open_after, book.close_after = settings.open_after, settings.close_after
    alive, points = set(), []
    when = dt.datetime.fromtimestamp(now, dt.timezone.utc)
    # Fenêtres actives : zone « Maintenance » dans Grafana (un point par minute tant qu'elles durent)
    for w in (maintenance.windows if maintenance is not None else []):
        points.append({"measurement": "SYNTRAF_MAINTENANCE", "time": when, "fields": {"ACTIVE": 1},
                       "tags": {"UID": w.get("UID", ""), "TARGET_TYPE": w.get("TARGET_TYPE", ""),
                                "TARGET": w.get("TARGET", ""), "DESCRIPTION": str(w.get("DESCRIPTION", ""))[:100]}})
    for c in health_checks(snap):
        key = ("SYNTRAF", c["subject"], "", c["metric"])
        alive.add(key)
        if maintenance is not None and c["metric"].startswith("probe_") and maintenance.covers_node(c["subject"]):
            continue  # sonde en maintenance : déconnexion attendue
        verdict = Verdict(c["anomalous"], 2.0 if c["anomalous"] else 0.0, c["explanation"])
        info = {"KIND": "health", "METRIC": c["metric"], "SUBJECT": c["subject"], "MESH_GROUP": "SYNTRAF",
                "CLIENT": c["subject"], "SERVER": ""}
        for event in book.update(key, verdict, now, info):
            action = "OPENED" if event == "open" else "CLOSED"
            (log.warning if event == "open" else log.info)(f"ALERT {action}: SYNTRAF {c['explanation']}")
            points.append({"measurement": "SYNTRAF_ALERT", "time": dt.datetime.fromtimestamp(now, dt.timezone.utc),
                           "tags": {"ACTION": action, "MESH_GROUP": "SYNTRAF", "METRIC": c["metric"],
                                    "FLOW": c["subject"], "SUMMARY": c["explanation"][:200]},
                           "fields": {"EVENT": 1}})
    book.forget(alive)
    if write and points:
        write(points)


class HealthPublisher:
    """Une vérification par minute, avec l'état du serveur (sondes, bases, fils)."""

    def __init__(self, period_s=PERIOD_S):
        self.period_s, self.last = period_s, None

    def maybe(self, state, conn_db, now=None):
        now = now if now is not None else time.time()
        if self.last is not None and now - self.last < self.period_s:
            return False
        self.last = now
        try:
            from lib.web_ui_kindafixed2 import st_status
            from lib.st_flow_catalog import _write
            from lib import st_maintenance
            evaluate_health(st_status.snapshot(state), now, settings=Settings.from_config(state.get("config")),
                            write=lambda pts: _write(pts, conn_db, "HEALTH_ALERTS"),
                            maintenance=st_maintenance.Maintenance(
                                st_maintenance.load(state.get("config_file_path")), now))
        except Exception as exc:  # noqa: BLE001 - jamais bloquant
            log.warning(f"SYNTRAF HEALTH NOT CHECKED: {type(exc).__name__}:{exc}")
        return True


HEALTH = HealthPublisher()


def summary(book=BOOK, health_book=HEALTH_BOOK):
    alerts = sorted(health_book.open() + book.open(), key=lambda a: a["opened_at"], reverse=True)
    recent = sorted(health_book.recent() + book.recent(), key=lambda a: a.get("closed_at") or 0, reverse=True)
    return {"open": alerts, "recent": recent[:50], **STATUS}


class Publisher:
    """Une évaluation par minute, dans un fil à part (une base lente ne retarde pas le chien de garde)."""

    def __init__(self, period_s=PERIOD_S):
        self.period_s, self.last, self.lock, self.running = period_s, None, threading.Lock(), False

    config_path = None

    def maybe(self, config, conn_db, now=None, config_path=None):
        now = now if now is not None else time.time()
        self.config_path = config_path or self.config_path
        g = config.get("GLOBAL", {})
        if str(g.get("BASELINE", True)).lower() in ("false", "0", "no", "off"):
            return False
        with self.lock:
            if self.running or (self.last is not None and now - self.last < self.period_s):
                return False
            self.last, self.running = now, True
        threading.Thread(target=self._run, args=(config, conn_db), name="BASELINE", daemon=True).start()
        return True

    def _run(self, config, conn_db):
        try:
            dbs = [d for d in config.get("DATABASE", []) if str(d.get("DB_ENGINE", "")).lower() == "victoriametrics"]
            if not dbs:
                return
            from lib.st_vm_admin import VmAdmin
            from lib.st_flow_catalog import _write
            from lib import st_maintenance
            evaluate(VmAdmin(dbs[0]), settings=Settings.from_config(config),
                     write=lambda pts: _write(pts, conn_db, "BASELINE"),
                     maintenance=st_maintenance.Maintenance(st_maintenance.load(self.config_path), time.time()))
        except Exception as exc:  # noqa: BLE001 - jamais bloquant
            log.warning(f"BASELINE NOT EVALUATED: {type(exc).__name__}:{exc}")
        finally:
            with self.lock:
                self.running = False


PUBLISHER = Publisher()

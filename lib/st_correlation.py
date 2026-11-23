"""Matrice de corrélation des flux, pour Grafana : des flux qui perdent (ou dont la gigue monte) en même temps
partagent probablement un lien, un équipement ou un goulot.

Toutes les PERIOD_S secondes, le serveur lit dans VictoriaMetrics les WINDOW_S dernières secondes des pertes et de
la gigue de chaque flux (un point toutes les STEP_S secondes), calcule la corrélation de Pearson de chaque paire et
l'écrit à côté des mesures :
    SYNTRAF_CORRELATION_LOSS{FLOW_A, FLOW_B} et SYNTRAF_CORRELATION_JITTER{FLOW_A, FLOW_B}, de -1 à 1
(les deux sens et la diagonale, pour une matrice complète). Une série constante (aucune perte) n'a pas de
corrélation : elle est écartée. Au-delà de MAX_FLOWS flux, les plus variables sont gardés (une matrice plus grande
serait illisible, et le nombre de paires croît comme le carré).

Module sans dépendance externe (la lecture passe par lib.st_vm_admin.VmAdmin).
"""
import datetime as dt
import logging
import math
import threading

log = logging.getLogger("syntraf." + __name__)

METRICS = {"LOSS": "SYNTRAF_RX_PCT_LOSS", "JITTER": "SYNTRAF_RX_JITTER"}
WINDOW_S = 900
STEP_S = 10
PERIOD_S = 60
MAX_FLOWS = 60
MIN_SAMPLES = 20


def pearson(xs, ys):
    """Coefficient de Pearson ; None si une série est constante (corrélation indéfinie)."""
    n = len(xs)
    if n < 2:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx <= 1e-12 or syy <= 1e-12:
        return None
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    return max(-1.0, min(1.0, sxy / math.sqrt(sxx * syy)))


def _variance(values):
    if len(values) < 2:
        return 0.0
    m = sum(values) / len(values)
    return sum((v - m) ** 2 for v in values) / len(values)


def correlate(flows):
    """flows : {nom: {horodatage: valeur}} → [(flux A, flux B, r)], les deux sens et la diagonale (1)."""
    usable = {name: s for name, s in flows.items()
              if len(s) >= MIN_SAMPLES and _variance(list(s.values())) > 1e-12}
    if len(usable) > MAX_FLOWS:
        keep = sorted(usable, key=lambda n: _variance(list(usable[n].values())), reverse=True)[:MAX_FLOWS]
        usable = {n: usable[n] for n in keep}
    names = sorted(usable)
    out = []
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            common = sorted(set(usable[a]) & set(usable[b]))
            if len(common) < MIN_SAMPLES:
                continue
            r = pearson([usable[a][t] for t in common], [usable[b][t] for t in common])
            if r is not None:
                out += [(a, b, round(r, 3)), (b, a, round(r, 3))]
    paired = {a for a, _, _ in out}
    out += [(n, n, 1) for n in names if n in paired]
    return out


def flows_from_query(result):
    """Résultat d'une requête query_range (par CLIENT, SERVER, MESH_GROUP) → {« A→B » : {t: valeur}}.
    Le mesh group n'est ajouté au nom que s'il y en a plusieurs."""
    groups = {r.get("metric", {}).get("MESH_GROUP", "") for r in result}
    flows = {}
    for r in result:
        m = r.get("metric", {})
        name = f"{m.get('CLIENT', '?')}→{m.get('SERVER', '?')}"
        if len(groups) > 1:
            name += f" · {m.get('MESH_GROUP', '')}"
        values = {}
        for t, v in r.get("values", []):
            try:
                x = float(v)
            except (TypeError, ValueError):
                continue
            if math.isfinite(x):
                values[int(float(t))] = x
        flows[name] = values
    return flows


def points(pairs, kind, now):
    now = now or dt.datetime.now(dt.timezone.utc)
    return [{"measurement": "SYNTRAF_CORRELATION", "tags": {"FLOW_A": a, "FLOW_B": b}, "time": now,
             "fields": {kind: r}} for a, b, r in pairs]


def publish(vm, write, now=None):
    """Calcule et écrit les deux matrices ; renvoie le nombre de points écrits."""
    end = int(now if now is not None else dt.datetime.now().timestamp())
    stamp = dt.datetime.fromtimestamp(end, dt.timezone.utc)
    out = []
    for kind, metric in METRICS.items():
        query = f"avg by (CLIENT, SERVER, MESH_GROUP) (avg_over_time({metric}[{STEP_S}s]))"
        result = vm.query_range(query, end - WINDOW_S, end, f"{STEP_S}s")
        out += points(correlate(flows_from_query(result)), kind, stamp)
    if out:
        write(out)
    return len(out)


class Publisher:
    """Au plus une publication par période, dans un fil à part (une base lente ne retarde pas le chien de garde)."""

    def __init__(self, period_s=PERIOD_S):
        self.period_s, self.last, self.lock, self.running = period_s, None, threading.Lock(), False

    def maybe(self, config, conn_db, now=None):
        now = now if now is not None else dt.datetime.now().timestamp()
        with self.lock:
            if self.running or (self.last is not None and now - self.last < self.period_s):
                return False
            self.last, self.running = now, True
        threading.Thread(target=self._run, args=(config, conn_db), name="CORRELATION", daemon=True).start()
        return True

    def _run(self, config, conn_db):
        try:
            databases = [d for d in config.get("DATABASE", []) if str(d.get("DB_ENGINE", "")).lower() == "victoriametrics"]
            if not databases:
                return
            from lib.st_vm_admin import VmAdmin
            from lib.st_flow_catalog import _write
            vm = VmAdmin(databases[0])
            publish(vm, lambda pts: _write(pts, conn_db, "FLOW_CORRELATION"))
        except Exception as exc:  # noqa: BLE001 - la corrélation est un plus : jamais bloquante
            log.warning(f"FLOW CORRELATION NOT PUBLISHED: {type(exc).__name__}:{exc}")
        finally:
            with self.lock:
                self.running = False


PUBLISHER = Publisher()

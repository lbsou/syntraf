"""Qualité perçue des flux : MOS de la voix et rafales de pertes.

MOS — modèle E (UIT-T G.107), forme simplifiée habituelle (Is et A nuls) :
    R = 93.2 - Id - Ie_eff
    Id = 0.024·Ta + 0.11·(Ta - 177.3)·H(Ta - 177.3)        Ta : délai bouche-oreille (ms)
    Ie_eff = Ie + (95 - Ie) · Ppl / (Ppl / BurstR + Bpl)    Ppl : pertes (%), BurstR : 1 si aléatoires
    MOS = 1 + 0.035·R + 7·10⁻⁶·R·(R - 60)·(100 - R)         (1 si R ≤ 0, 4.5 si R ≥ 100)
Ta = latence + tampon de gigue (2 × gigue) + délai du codec (paquétisation, anticipation). SYNTRAF ne mesure pas
encore la latence : elle vaut 0 tant qu'elle n'est pas fournie, et le MOS ne compte que la gigue et le codec.
Ie et Bpl : UIT-T G.113 (G.711 avec masquage des pertes ; G.729A). Opus n'y figure pas : valeurs de G.711, une
approximation prudente (Opus masque mieux les pertes).

Rafales — à la granularité de l'intervalle d'iperf3 (il ne donne pas le détail paquet par paquet) :
    rafale : suite d'intervalles à au moins BURST_LOSS_PCT % de pertes (à 5 % de pertes au hasard et 50 paquets/s,
    presque chaque seconde perd un paquet : « au moins une perte » ferait de tout le flux une seule rafale) ;
    ratio de rafale : longueur moyenne des rafales divisée par celle qu'auraient ces mauvaises secondes tombant au
    hasard (1/(1 - q)), à la manière de la BurstR de G.113 : 1 = aléatoire, plus de 1 = regroupées.

Bibliothèque standard uniquement.
"""
import datetime as dt
import logging
import threading

log = logging.getLogger("syntraf." + __name__)

# Ie : dégradation propre du codec ; Bpl : robustesse aux pertes ; delay : paquétisation + anticipation (ms)
CODECS = {
    "G711": {"Ie": 0, "Bpl": 25.1, "delay": 20.0},
    "G729": {"Ie": 11, "Bpl": 19.0, "delay": 25.0},
    "OPUS": {"Ie": 0, "Bpl": 25.1, "delay": 26.5},
}
DEFAULT_CODEC = "G711"
HEAVY_LOSS_PCT = 20
BURST_LOSS_PCT = 10
WINDOW_S = 900
PERIOD_S = 60


def mos(loss_pct, jitter_ms, latency_ms=0.0, codec=DEFAULT_CODEC, burst_ratio=1.0):
    """(R, MOS) d'une voix sur ce chemin."""
    c = CODECS.get(str(codec or "").upper(), CODECS[DEFAULT_CODEC])
    loss = min(max(float(loss_pct or 0), 0.0), 100.0)
    if loss >= 100:
        return 0.0, 1.0  # plus rien ne passe
    ta = max(float(latency_ms or 0), 0.0) + 2 * max(float(jitter_ms or 0), 0.0) + c["delay"]
    idd = 0.024 * ta + (0.11 * (ta - 177.3) if ta > 177.3 else 0.0)
    burst = max(float(burst_ratio or 1.0), 1.0)
    ie_eff = c["Ie"] + (95 - c["Ie"]) * loss / (loss / burst + c["Bpl"]) if loss else c["Ie"]
    r = 93.2 - idd - ie_eff
    if r <= 0:
        return round(r, 1), 1.0
    if r >= 100:
        return round(r, 1), 4.5
    return round(r, 1), round(1 + 0.035 * r + 7e-6 * r * (r - 60) * (100 - r), 2)


def add_mos(point, codec=None, latency_ms=None):
    """Ajoute RX_MOS et RX_R_FACTOR (et l'étiquette CODEC, et RX_LATENCY_MS si la latence est connue) à un point de
    mesure SYNTRAF."""
    fields = point.get("fields", {})
    if "RX_PCT_LOSS" not in fields or "RX_JITTER" not in fields:
        return point
    name = str(codec or DEFAULT_CODEC).upper()
    name = name if name in CODECS else DEFAULT_CODEC
    r, score = mos(fields["RX_PCT_LOSS"], fields["RX_JITTER"], latency_ms=latency_ms or 0.0, codec=name)
    fields["RX_MOS"], fields["RX_R_FACTOR"] = score, r
    if latency_ms is not None:
        fields["RX_LATENCY_MS"] = round(latency_ms, 2)
    point.setdefault("tags", {})["CODEC"] = name
    return point


def codec_by_group(config):
    """Codec de chaque mesh group : celui de son profil iperf3 (CODEC), sinon G.711."""
    profiles = {p.get("UID"): p for p in config.get("IPERF3_PROFILE", [])}
    out = {}
    for g in config.get("MESH_GROUP", []):
        codec = str(profiles.get(g.get("IPERF3_PROFILE"), {}).get("CODEC") or g.get("CODEC") or DEFAULT_CODEC).upper()
        out[g.get("UID")] = codec if codec in CODECS else DEFAULT_CODEC
    return out


# Dernier RTT de chaque paire de sondes (lib/st_twamp.py), quelle que soit celle qui l'a mesuré : {paire: (ms, t)}
LATENCY = {}
LATENCY_MAX_AGE_S = 120
_LATENCY_LOCK = threading.Lock()


def _pair(tags):
    return frozenset((tags.get("CLIENT"), tags.get("SERVER")))


def latest_rtt(tags, now=None):
    import time
    now = now if now is not None else time.monotonic()
    with _LATENCY_LOCK:
        found = LATENCY.get(_pair(tags))
    return found[0] if found and now - found[1] <= LATENCY_MAX_AGE_S else None


def enrich(points, config):
    """Ajoute le MOS aux mesures (points SYNTRAF) reçues par le serveur, selon le codec de leur mesh group et le
    dernier RTT de la paire (latence d'un sens = RTT / 2)."""
    import time
    now = time.monotonic()
    for p in points:
        if isinstance(p, dict) and p.get("measurement") == "SYNTRAF_LATENCY" and "RTT_MS" in p.get("fields", {}):
            with _LATENCY_LOCK:
                LATENCY[_pair(p.get("tags", {}))] = (float(p["fields"]["RTT_MS"]), now)
    codecs = codec_by_group(config or {})
    for p in points:
        if isinstance(p, dict) and p.get("measurement") == "SYNTRAF":
            rtt = latest_rtt(p.get("tags", {}), now)
            add_mos(p, codecs.get(p.get("tags", {}).get("MESH_GROUP")), latency_ms=None if rtt is None else rtt / 2)
    return points


# ------------------------------------------------------------------------------------------------ rafales

def episodes(losses, threshold=0.0):
    """Longueurs (en intervalles) des suites d'intervalles à plus de threshold % de pertes (0 : toute perte)."""
    out, run = [], 0
    for v in losses:
        if v > threshold if threshold == 0 else v >= threshold:
            run += 1
        elif run:
            out.append(run)
            run = 0
    if run:
        out.append(run)
    return out


def burst_metrics(losses, interval_s=1):
    losses = [float(v) for v in losses]
    eps = episodes(losses, BURST_LOSS_PCT)
    total = sum(losses)
    if not eps or not total:
        return {"EPISODES": 0, "LONGEST_S": 0, "BURST_RATIO": 0.0, "HEAVY_SHARE": 0.0,
                "LOSS_PCT": round(total / len(losses), 2) if losses else 0.0}
    bad = sum(1 for v in losses if v >= BURST_LOSS_PCT)
    q = bad / len(losses)
    expected_run = 1 / (1 - q) if q < 1 else float(len(losses))
    return {"EPISODES": len(eps), "LONGEST_S": round(max(eps) * interval_s),
            "BURST_RATIO": round((sum(eps) / len(eps)) / expected_run, 2),
            "HEAVY_SHARE": round(100 * sum(v for v in losses if v >= HEAVY_LOSS_PCT) / total, 1),
            "LOSS_PCT": round(total / len(losses), 2)}


def _interval(timestamps):
    gaps = sorted(b - a for a, b in zip(timestamps, timestamps[1:]) if b > a)
    return gaps[len(gaps) // 2] if gaps else 1


def publish_bursts(vm, write, now=None):
    """Rafales de pertes de chaque flux sur les WINDOW_S dernières secondes ; renvoie le nombre de points."""
    end = int(now if now is not None else dt.datetime.now().timestamp())
    stamp = dt.datetime.fromtimestamp(end, dt.timezone.utc)
    result = vm.query_range("last_over_time(SYNTRAF_RX_PCT_LOSS[1s])", end - WINDOW_S, end, "1s")
    points = []
    for r in result:
        m = r.get("metric", {})
        samples = []
        for t, v in r.get("values", []):
            try:
                samples.append((int(float(t)), float(v)))
            except (TypeError, ValueError):
                continue
        if len(samples) < 10:
            continue
        metrics = burst_metrics([v for _, v in samples], _interval([t for t, _ in samples]))
        tags = {k: m[k] for k in ("CLIENT", "SERVER", "MESH_GROUP", "UID") if k in m}
        points.append({"measurement": "SYNTRAF_LOSS_BURST", "tags": tags, "time": stamp, "fields": metrics})
    if points:
        write(points)
    return len(points)


class Publisher:
    """Au plus une publication par période, dans un fil à part (comme la corrélation)."""

    def __init__(self, period_s=PERIOD_S):
        self.period_s, self.last, self.lock, self.running = period_s, None, threading.Lock(), False

    def maybe(self, config, conn_db, now=None):
        now = now if now is not None else dt.datetime.now().timestamp()
        with self.lock:
            if self.running or (self.last is not None and now - self.last < self.period_s):
                return False
            self.last, self.running = now, True
        threading.Thread(target=self._run, args=(config, conn_db), name="LOSS_BURSTS", daemon=True).start()
        return True

    def _run(self, config, conn_db):
        try:
            dbs = [d for d in config.get("DATABASE", []) if str(d.get("DB_ENGINE", "")).lower() == "victoriametrics"]
            if not dbs:
                return
            from lib.st_vm_admin import VmAdmin
            from lib.st_flow_catalog import _write
            publish_bursts(VmAdmin(dbs[0]), lambda pts: _write(pts, conn_db, "LOSS_BURSTS"))
        except Exception as exc:  # noqa: BLE001 - un plus : jamais bloquant
            log.warning(f"LOSS BURSTS NOT PUBLISHED: {type(exc).__name__}:{exc}")
        finally:
            with self.lock:
                self.running = False


PUBLISHER = Publisher()

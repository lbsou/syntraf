"""
Détection du silence d'iperf3 : pertes à 100 % pour chaque intervalle muet.

Pendant une coupure, iperf3 n'écrit plus rien (ou s'arrête sur --rcv-timeout) et le thread de
lecture reste bloqué sur sa sortie : il ne peut pas constater le silence lui-même. Le lecteur
enregistre donc l'horodatage de chaque vraie mesure (record), et la boucle de surveillance comble
périodiquement les intervalles muets (fill).

On ne comble que jusqu'à now - lag_intervals × intervalle : une vraie ligne encore en cours de
lecture ne doit jamais se retrouver en doublon d'un point généré.

L'état est indexé par l'UID du flux (CLIENT__TO__SERVER__ON__DSCPn), pas par la clé du listener
(qui change quand la config est régénérée) : il survit au redémarrage d'un iperf3 ou d'un lecteur.

Bibliothèque standard uniquement.
"""
import hashlib
import logging
import threading
from datetime import datetime, timezone

log = logging.getLogger("syntraf." + __name__)

DEFAULT_LAG_INTERVALS = 3


def flow_uid(ctx: dict) -> str:
    return f"{ctx['CLIENT']}__TO__{ctx['SERVER']}__ON__DSCP{ctx['DSCP']}"


def loss_point(ctx: dict, utime: float) -> dict:
    """Point au même format que st_influxdb.generate_json, avec 100 % de pertes."""
    return {
        "measurement": "SYNTRAF",
        "tags": {"MESH_GROUP": ctx['MESH_GROUP'], "CLIENT": ctx['CLIENT'], "SERVER": ctx['SERVER'],
                 "UID": flow_uid(ctx)},
        "time": datetime.fromtimestamp(utime, timezone.utc),
        "fields": {"RX_BITRATE": 0.0, "RX_JITTER": 0.0, "RX_PCT_LOSS": 100.0,
                   "RX_PACKET_TOTAL": 0, "RX_PACKET_LOSS": 0},
    }


def enqueue(queue: dict, point: dict, max_size: int) -> None:
    """Ajoute un point à la file du client (clé = sha1 du point), en retirant les plus anciens au-delà de max_size."""
    while len(queue) >= max_size:
        queue.pop(next(iter(queue)))
    queue[hashlib.sha1(str(point).encode()).hexdigest()] = point


class SilenceTracker:
    """Détection du silence d'iperf3.

    clock : horloge monotone (time.monotonic en production). La durée d'un silence se mesure avec elle, et non
    avec l'horloge murale qui horodate les lignes d'iperf3 : un recalage de l'heure (NTP, VM WSL qui saute de
    plusieurs secondes) ferait sinon apparaître de fausses pertes à 100 %. Sans clock, les horodatages des
    lignes et le `now` de fill() font foi.
    """

    def __init__(self, lag_intervals: int = DEFAULT_LAG_INTERVALS, clock=None):
        self.lag_intervals = lag_intervals
        self._clock = clock
        self._flows = {}
        self._lock = threading.Lock()

    def record(self, uid: str, utime: float, interval: int, ctx: dict) -> list:
        """Une vraie mesure horodatée utime vient d'être lue pour le flux uid.

        Renvoie les points à 100 % de pertes du trou qui la précède, s'il est assez long pour être une panne
        et que fill() ne l'a pas (entièrement) couvert : au dégel d'un nœud figé, iperf3 publie souvent une
        ligne avant le passage suivant de la boucle de surveillance. Un trou dans les horodatages sans silence
        réel (horloge murale qui a sauté) n'est pas une panne.
        """
        mono = self._clock() if self._clock else utime
        with self._lock:
            flow = self._flows.get(uid)
            if flow is None:
                self._flows[uid] = {"last": utime, "interval": interval, "ctx": dict(ctx), "silent": False,
                                    "anchor_t": utime, "anchor_m": mono}
                return []
            points = []
            step = flow["interval"]
            threshold = (self.lag_intervals + 1) * step
            if flow["silent"]:
                points = self._generate(uid, flow, utime - step)
            elif utime - flow["last"] >= threshold:
                if mono - flow["anchor_m"] >= threshold:
                    points = self._generate(uid, flow, utime - step)
                else:
                    log.info(f"{uid} - WALL CLOCK JUMPED {utime - flow['last']:.1f} S BETWEEN TWO IPERF3 REPORTS "
                             f"{mono - flow['anchor_m']:.1f} S APART: NOT AN OUTAGE")
            if flow["silent"] and utime > flow["last"]:
                log.warning(f"{uid} - IPERF3 IS REPORTING AGAIN, END OF OUTAGE")
                flow["silent"] = False
            flow["last"] = max(flow["last"], utime)
            flow["anchor_t"], flow["anchor_m"] = utime, mono
            flow["interval"] = interval
            flow["ctx"] = dict(ctx)
            return points

    def _generate(self, uid: str, flow: dict, limit: float) -> list:
        """Points à 100 % de pertes de flow["last"] + intervalle jusqu'à limit inclus ; avance flow["last"]."""
        step = flow["interval"]
        t = flow["last"] + step
        if t > limit:
            return []
        if not flow["silent"]:
            log.warning(f"{uid} - SYNTRAF HAS DETECTED AN OUTAGE (NO IPERF3 REPORT SINCE {flow['last']:.0f}), GENERATING 100% LOSSES")
            flow["silent"] = True
        points = []
        while t <= limit:
            points.append(loss_point(flow["ctx"], t))
            flow["last"] = t
            t += step
        return points

    def fill(self, now: float, active=lambda uid: True) -> list:
        """Points à 100 % de pertes pour les intervalles muets jusqu'à now - lag. Un flux inactif est oublié.

        « now » se lit sur la chronologie du flux : horodatage de sa dernière vraie ligne + temps (monotone)
        écoulé depuis. Ainsi un saut de l'horloge murale ne fait pas croire à un silence.
        """
        mono_now = self._clock() if self._clock else now
        points = []
        with self._lock:
            for uid in list(self._flows):
                if not active(uid):
                    del self._flows[uid]
                    continue
                flow = self._flows[uid]
                flow_now = flow["anchor_t"] + (mono_now - flow["anchor_m"])
                points.extend(self._generate(uid, flow, flow_now - self.lag_intervals * flow["interval"]))
        return points

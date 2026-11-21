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
    def __init__(self, lag_intervals: int = DEFAULT_LAG_INTERVALS):
        self.lag_intervals = lag_intervals
        self._flows = {}
        self._lock = threading.Lock()

    def record(self, uid: str, utime: float, interval: int, ctx: dict) -> None:
        """Une vraie mesure horodatée utime vient d'être lue pour le flux uid."""
        with self._lock:
            flow = self._flows.get(uid)
            if flow is None:
                self._flows[uid] = {"last": utime, "interval": interval, "ctx": dict(ctx), "silent": False}
                return
            if flow["silent"] and utime > flow["last"]:
                log.warning(f"{uid} - IPERF3 IS REPORTING AGAIN, END OF OUTAGE")
                flow["silent"] = False
            flow["last"] = max(flow["last"], utime)
            flow["interval"] = interval
            flow["ctx"] = dict(ctx)

    def fill(self, now: float, active=lambda uid: True) -> list:
        """Points à 100 % de pertes pour les intervalles muets jusqu'à now - lag. Un flux inactif est oublié."""
        points = []
        with self._lock:
            for uid in list(self._flows):
                if not active(uid):
                    del self._flows[uid]
                    continue
                flow = self._flows[uid]
                step = flow["interval"]
                limit = now - self.lag_intervals * step
                t = flow["last"] + step
                if t > limit:
                    continue
                if not flow["silent"]:
                    log.warning(f"{uid} - SYNTRAF HAS DETECTED AN OUTAGE (NO IPERF3 REPORT SINCE {flow['last']:.0f}), GENERATING 100% LOSSES")
                    flow["silent"] = True
                while t <= limit:
                    points.append(loss_point(flow["ctx"], t))
                    flow["last"] = t
                    t += step
        return points

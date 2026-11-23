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


CLOCK_JUMP_SUMMARY_S = 600  # au plus un message visible (INFO) par période sur les sauts d'horloge
# Mesure qui s'établit avec un pair qui a répondu : son silence est un trou (l'outil redémarre, le réseau marche),
# sauf après MAX_FAILED_STARTS échecs de suite (UDP bloqué, panne réelle) ou au-delà de HOLD_MAX_S.
# La vraie limite est HOLD_MAX_S (une mesure qui ne s'établit pas en une minute est une panne) ; le nombre d'échecs
# n'est qu'un garde-fou : juste après une coupure, les échecs rapides s'enchaînent bien plus que le hasard ne le dit.
MAX_FAILED_STARTS = 10
HOLD_MAX_S = 60


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
        # Sauts d'horloge : un message au premier, puis un résumé par période (un saut touche tous les flux à la
        # fois ; une VM WSL en fait plusieurs par minute) ; le détail de chacun en DEBUG
        self._jumps = {"count": 0, "largest": 0.0, "since": None, "reported": None}
        self._holds = {}     # uid -> instant (monotone) où la mesure a commencé à s'établir
        self._failures = {}  # uid -> sessions de suite terminées sans aucune mesure

    def _mono(self):
        import time
        return self._clock() if self._clock else time.monotonic()

    def establishing(self, uid: str) -> None:
        """Une session iperf3 de ce flux a joint son pair et attend sa première mesure : pas de pertes inventées
        pendant ce temps (sauf après MAX_FAILED_STARTS échecs de suite)."""
        with self._lock:
            if self._failures.get(uid, 0) < MAX_FAILED_STARTS:
                self._holds.setdefault(uid, self._mono())

    def failed_start(self, uid: str) -> None:
        """La session s'est terminée sans aucune mesure alors que le pair avait répondu."""
        with self._lock:
            self._failures[uid] = self._failures.get(uid, 0) + 1
            if self._failures[uid] < MAX_FAILED_STARTS:
                self._holds.setdefault(uid, self._mono())  # morte avant d'annoncer le pair : trou quand même
            elif self._holds.pop(uid, None) is not None:
                log.warning(f"{uid} - {MAX_FAILED_STARTS} IPERF3 SESSIONS IN A ROW REACHED THE PEER WITHOUT ANY "
                            f"MEASUREMENT (UDP BLOCKED?): COUNTED AS AN OUTAGE")

    def unreachable(self, uid: str) -> None:
        """Le pair n'a pas répondu : le silence est une panne."""
        with self._lock:
            self._holds.pop(uid, None)

    def _held(self, uid, mono):
        since = self._holds.get(uid)
        if since is None:
            return False
        if mono - since > HOLD_MAX_S:
            del self._holds[uid]
            return False
        return True

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
            if self._held(uid, mono):
                pass  # première mesure d'une session qui s'établissait : le trou reste un trou
            elif flow["silent"]:
                points = self._generate(uid, flow, utime - step)
            elif utime - flow["last"] >= threshold:
                if mono - flow["anchor_m"] >= threshold:
                    points = self._generate(uid, flow, utime - step)
                else:
                    self._clock_jump(uid, utime - flow["last"], mono - flow["anchor_m"], mono)
            if self._jumps["reported"] is not None:
                self._report_jumps(mono)
            if flow["silent"] and utime > flow["last"]:
                log.warning(f"{uid} - IPERF3 IS REPORTING AGAIN, END OF OUTAGE")
                flow["silent"] = False
            flow["last"] = max(flow["last"], utime)
            flow["anchor_t"], flow["anchor_m"] = utime, mono
            self._holds.pop(uid, None)  # la mesure est établie
            self._failures.pop(uid, None)
            flow["interval"] = interval
            flow["ctx"] = dict(ctx)
            return points

    def _clock_jump(self, uid, jump, real, mono):
        log.debug(f"{uid} - WALL CLOCK JUMPED {jump:.1f} S BETWEEN TWO IPERF3 REPORTS {real:.1f} S APART: NOT AN OUTAGE")
        j = self._jumps
        if j["reported"] is None:
            log.info(f"WALL CLOCK JUMPED {jump:.1f} S WHILE ONLY {real:.1f} S PASSED: THIS HOST'S CLOCK IS UNSTABLE "
                     f"(NTP STEP, VIRTUAL MACHINE). NOT COUNTED AS AN OUTAGE; FURTHER JUMPS ARE SUMMARIZED EVERY "
                     f"{CLOCK_JUMP_SUMMARY_S // 60} MIN")
            j["reported"] = mono
            return
        j["count"] += 1
        j["largest"] = max(j["largest"], jump)
        self._report_jumps(mono)

    def _report_jumps(self, mono):
        j = self._jumps
        if j["count"] and mono - j["reported"] >= CLOCK_JUMP_SUMMARY_S:
            log.info(f"{j['count']} WALL CLOCK JUMP(S) IN THE LAST {(mono - j['reported']) / 60:.0f} MIN (LARGEST "
                     f"{j['largest']:.1f} S): NOT COUNTED AS OUTAGES")
            j.update(count=0, largest=0.0, reported=mono)

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
                limit = flow_now - self.lag_intervals * flow["interval"]
                if self._held(uid, mono_now):
                    flow["last"] = max(flow["last"], limit)  # trou : la mesure s'établit
                    continue
                points.extend(self._generate(uid, flow, limit))
        return points

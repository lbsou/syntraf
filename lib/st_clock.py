"""Horloge des sondes : écart au serveur et dérive, mesurés en continu sur le canal de contrôle.

Chaque AWAITING_COMMAND est un aller-retour : la sonde l'envoie à T1 (son horloge), le serveur le reçoit à T2 et
répond à T3 (horloge du serveur), la sonde reçoit la réponse à T4. Comme NTP :
    écart (serveur - sonde) = ((T2 - T1) + (T3 - T4)) / 2      trajet = (T4 - T1) - (T3 - T2)
La sonde rapporte T1 et T4 de l'échange précédent dans le suivant ; le serveur, qui a gardé T2 et T3, calcule.
Estimation : l'échange le moins retardé parmi les derniers (le moins faussé par l'asymétrie du trajet). Dérive : pente
de l'écart sur la dernière heure (un point par minute), en ppm ; positive, la sonde avance (gagne du temps).
Une sonde ou un serveur plus ancien n'envoie rien : la sonde n'est simplement pas mesurée.
"""
import collections
import threading

OFFSET_MAX_MS = 1000.0     # au-delà : courbes décalées, et iperf3 refuse l'authentification passé 10 s
DRIFT_MAX_PPM = 15.0       # ~1,3 s par jour : horloge libre (pas de NTP)
RECENT = 32                # échanges gardés pour l'estimation de l'écart
DRIFT_WINDOW_S = 3600
DRIFT_MIN_SPAN_S = 45 * 60
DRIFT_MIN_POINTS = 30


def sample(t1, t2, t3, t4):
    """(écart serveur - sonde, trajet aller-retour), en secondes."""
    return ((t2 - t1) + (t3 - t4)) / 2.0, (t4 - t1) - (t3 - t2)


class ClientClock:
    """Côté sonde : horodate chaque AWAITING_COMMAND et rapporte l'échange précédent."""

    def __init__(self):
        self.prev = None

    def request(self, t1):
        payload = {"T1": t1}
        if self.prev:
            payload["PREV_T1"], payload["PREV_T4"] = self.prev
        return payload

    def replied(self, t1, t4):
        self.prev = (t1, t4)


CLIENT = ClientClock()


def _num(v):
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


class ClockTracker:
    """Côté serveur, une par sonde."""

    def __init__(self):
        self.lock = threading.Lock()
        self.pending = collections.OrderedDict()   # T1 de la sonde -> (T2, T3) du serveur
        self.recent = collections.deque(maxlen=RECENT)
        self.minutes = collections.OrderedDict()   # minute -> (instant, écart, trajet) le moins retardé

    def exchange(self, payload, t2, t3):
        """Appelé une fois la réponse à AWAITING_COMMAND envoyée."""
        if not isinstance(payload, dict):
            return
        t1 = _num(payload.get("T1"))
        p1, p4 = _num(payload.get("PREV_T1")), _num(payload.get("PREV_T4"))
        with self.lock:
            if p1 is not None and p4 is not None and p1 in self.pending:
                pt2, pt3 = self.pending.pop(p1)
                offset, delay = sample(p1, pt2, pt3, p4)
                if 0 <= delay < 60:
                    self._add(pt2, offset, delay)
            if t1 is not None:
                self.pending[t1] = (t2, t3)
                while len(self.pending) > 8:
                    self.pending.popitem(last=False)

    def add(self, at, offset, delay):
        with self.lock:
            self._add(at, offset, delay)

    def _add(self, at, offset, delay):
        self.recent.append((at, offset, delay))
        minute = int(at // 60)
        best = self.minutes.get(minute)
        if best is None or delay < best[2]:
            self.minutes[minute] = (at, offset, delay)
        while self.minutes and next(iter(self.minutes)) < minute - DRIFT_WINDOW_S // 60 - 5:
            self.minutes.popitem(last=False)

    def estimate(self, now=None):
        """{"offset_ms", "delay_ms", "drift_ppm" (None sans une heure d'historique), "measured_at"} ou None."""
        with self.lock:
            if not self.recent:
                return None
            at, offset, delay = min(self.recent, key=lambda s: s[2])
            last = self.recent[-1][0]
            pts = [(t, o) for t, o, _ in self.minutes.values() if t >= (now if now is not None else last) - DRIFT_WINDOW_S]
        drift = None
        if len(pts) >= DRIFT_MIN_POINTS and pts[-1][0] - pts[0][0] >= DRIFT_MIN_SPAN_S:
            mt = sum(t for t, _ in pts) / len(pts)
            mo = sum(o for _, o in pts) / len(pts)
            var = sum((t - mt) ** 2 for t, _ in pts)
            slope = sum((t - mt) * (o - mo) for t, o in pts) / var if var else 0.0
            drift = round(-slope * 1e6, 2)  # l'écart serveur - sonde diminue quand la sonde avance
        return {"offset_ms": round(offset * 1000, 1), "delay_ms": round(delay * 1000, 1), "drift_ppm": drift,
                "measured_at": last}


_LOCK = threading.Lock()


def tracker(obj):
    """Le suivi d'horloge d'une sonde, rangé sur son objet côté serveur."""
    with _LOCK:
        t = getattr(obj, "_clock_tracker", None)
        if t is None:
            t = ClockTracker()
            setattr(obj, "_clock_tracker", t)
        return t


def estimate_of(obj):
    t = getattr(obj, "_clock_tracker", None) if obj is not None else None
    return t.estimate() if t is not None else None


def human(seconds):
    s = abs(seconds)
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.1f} s"

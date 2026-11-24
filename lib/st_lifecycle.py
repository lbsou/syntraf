"""Redémarrages, mises à jour et retours arrière, en repères sur les courbes de Grafana.

SYNTRAF_LIFECYCLE{EVENT, SUBJECT, SUMMARY} = 1 (métrique SYNTRAF_LIFECYCLE_EVENT), à l'instant de l'événement :
- SERVER_STARTED : le serveur démarre (après un arrêt, une panne, une mise à jour) ;
- PROBE_RECONNECTED : une sonde revient après une déconnexion (redémarrage, coupure réseau) ;
- PROBE_UPDATED : une sonde revient avec une autre release (mise à jour installée) ;
- PROBE_ROLLED_BACK : une sonde a abandonné une release (son superviseur est revenu à la précédente).
Le premier contact d'une sonde après le démarrage du serveur n'est pas un événement (sinon une rafale de repères à
chaque redémarrage du serveur). Les points sont mis en attente puis écrits par la boucle du serveur (flush).
"""
import collections
import datetime as dt
import logging
import threading

log = logging.getLogger("syntraf." + __name__)

_PENDING = collections.deque(maxlen=1000)
_LOCK = threading.Lock()


def events(uid, prev, new):
    """[(EVENT, résumé)] d'après ce que le serveur savait de la sonde (prev) et ce qu'elle annonce (new)."""
    out = []
    if prev.get("status") == "DISCONNECTED":
        out.append(("PROBE_RECONNECTED", f"Probe {uid} reconnected"))
    old, release = prev.get("release"), new.get("release")
    if old and release and old != release:
        out.append(("PROBE_UPDATED", f"Probe {uid} updated: release {old} → {release}"))
    failed = new.get("update_failed")
    if failed and failed != prev.get("update_failed"):
        out.append(("PROBE_ROLLED_BACK", f"Probe {uid} abandoned release {failed} and went back to {release}"))
    return out


def record(event, subject, summary, when=None):
    when = when or dt.datetime.now(dt.timezone.utc)
    log.info(f"{event}: {summary}")
    with _LOCK:
        _PENDING.append({"measurement": "SYNTRAF_LIFECYCLE", "time": when, "fields": {"EVENT": 1},
                         "tags": {"EVENT": event, "SUBJECT": subject, "SUMMARY": summary[:200]}})


def flush(write):
    """Écrit les événements en attente (write(points)) ; les garde si l'écriture échoue."""
    with _LOCK:
        points = list(_PENDING)
        _PENDING.clear()
    if not points:
        return
    try:
        write(points)
    except Exception as exc:  # noqa: BLE001 - retentés au prochain passage
        log.warning(f"LIFECYCLE EVENTS NOT WRITTEN: {type(exc).__name__}:{exc}")
        with _LOCK:
            _PENDING.extendleft(reversed(points))

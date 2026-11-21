"""Logique commune aux scénarios de coupure S3–S5."""
import time
from datetime import datetime, timedelta, timezone

from lab_fixtures import wait_until
from lablib import checks, faults, health, topology

R = topology.RECOVERY_S
CUT_S = 60


def now() -> datetime:
    return datetime.now(timezone.utc)


def cut_and_check(metrics, window, svc: str, mode: str, check_peers_iperf: bool = False) -> dict:
    """Coupe svc pendant 60 s, rétablit, et renvoie les écarts constatés (vide = réussite)."""
    uid = topology.CLIENT_UID[svc]
    peers = [s for s in topology.CLIENTS if s != svc]
    before = {s: health.snapshot(s) for s in peers} if check_peers_iperf else {}
    problems: dict = {}

    window.mark_start()
    faults.cut(svc, mode)
    time.sleep(CUT_S)
    faults.heal(svc)
    heal_t = window.mark_stop()

    # Tous modes : pertes à 100 % enregistrées par les pairs pour les flux émis par svc.
    wait_until(heal_t + timedelta(seconds=R))
    for f in topology.flows_involving(uid, "from"):
        pts = metrics.points(f, window.start, window.stop)
        cov = checks.value_coverage(pts, window.start, window.stop, lambda v: v >= 99.9)
        if cov < 0.8:
            problems[f"{f} : couverture des pertes 100 % pendant la coupure"] = round(cov, 2)

    # Tous modes : reprise de vraies mesures sur les 6 flux de svc dans le délai R.
    nr = checks.not_recovered(metrics, topology.flows_involving(uid, "both"), heal_t, now())
    if nr:
        problems[f"flux sans vraie mesure {R} s après le rétablissement"] = nr

    zombies = {s: z for s in topology.SYNTRAF_NODES if (z := health.snapshot(s).zombies)}
    if zombies:
        problems["processus zombies"] = zombies

    wait_until(heal_t + timedelta(seconds=60))
    # IP fixe : les mesures prises par svc pendant la coupure sont livrées après coup.
    if svc in topology.FIXED:
        for f in topology.flows_involving(uid, "to"):
            pts = metrics.points(f, window.start, window.stop)
            cov = checks.value_coverage(pts, window.start, window.stop, lambda v: v >= 99.9)
            if cov < 0.8:
                problems[f"{f} : couverture des pertes 100 % mesurées par {uid} (tampon)"] = round(cov, 2)

    if check_peers_iperf:
        counts = {s: (before[s].iperf3_count, health.snapshot(s).iperf3_count) for s in peers}
        changed = {s: v for s, v in counts.items() if v[0] != v[1]}
        if changed:
            problems["nombre d'iperf3 des pairs (avant, 60 s après)"] = changed
    return problems

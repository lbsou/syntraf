"""S9 — coupure du seul canal de contrôle client ↔ serveur pendant 60 s."""
import time
from datetime import datetime, timedelta, timezone

import pytest

from lab_fixtures import wait_until
from lablib import checks, faults, health, series, topology

R = topology.RECOVERY_S


@pytest.mark.parametrize("svc", ["c2", "c4"], ids=["c2-ip-fixe", "c4-ip-dynamique"])
def test_s9_control_channel(lab_up, metrics, window, svc):
    uid = topology.CLIENT_UID[svc]
    window.mark_start()
    faults.cut(svc, "drop", to="server")
    time.sleep(60)
    faults.heal(svc)
    heal_t = window.mark_stop()
    problems = {}

    if svc in topology.FIXED:
        # Les mesures entre clients continuent ; celles prises par svc sont livrées après coup.
        wait_until(heal_t + timedelta(seconds=R))
        for f in topology.flows_involving(uid, "from"):
            m = series.mean([v for _, v in metrics.points(f, window.start, window.stop)])
            if m >= 5:
                problems[f"{f} : pertes moyennes pendant la coupure du contrôle"] = round(m, 2)
        wait_until(heal_t + timedelta(seconds=60))
        for f in topology.flows_involving(uid, "to"):
            pts = metrics.points(f, window.start, window.stop)
            cov = checks.value_coverage(pts, window.start, window.stop, lambda v: v < 5)
            if cov < 0.9:
                problems[f"{f} : couverture des mesures livrées après coup"] = round(cov, 2)
    else:
        # IP dynamique : les flux vers svc s'arrêtent proprement puis reprennent après reconnexion.
        wait_until(heal_t + timedelta(seconds=R + 30))
        nr = checks.not_recovered(metrics, topology.flows_involving(uid, "both"), heal_t, datetime.now(timezone.utc))
        if nr:
            problems[f"flux sans vraie mesure {R + 30} s après le rétablissement"] = nr
        wait_until(heal_t + timedelta(seconds=60))
        zombies = {s: z for s in topology.CLIENTS if s != svc and (z := health.snapshot(s).zombies)}
        if zombies:
            problems["zombies chez les pairs"] = zombies
    checks.assert_no_problems(problems)

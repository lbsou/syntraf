"""S7 — redémarrage du serveur SYNTRAF : les clients reviennent et livrent les mesures en tampon."""
from datetime import datetime, timedelta, timezone

from lab_fixtures import wait_until
from lablib import checks, faults, health, series, topology

RESTART_WINDOW_S = 30


def test_s7_server_restart(lab_up, metrics, window):
    window.mark_start()
    faults.restart("server")
    up = datetime.now(timezone.utc)
    window.stop = window.start + timedelta(seconds=RESTART_WINDOW_S)
    problems = {}

    wait_until(up + timedelta(seconds=topology.RECOVERY_S + 30))
    stale = health.stale_flows(metrics, topology.expected_flows(), topology.FRESH_S)
    if stale:
        problems[f"flux muets {topology.RECOVERY_S + 30} s après le redémarrage"] = stale

    wait_until(up + timedelta(seconds=60))
    for f in topology.expected_flows():
        times = [t for t, _ in metrics.points(f, window.start, window.stop)]
        cov = series.coverage(times, window.start, window.stop, topology.INTERVAL)
        if cov < 0.9:
            problems[f"{f} : couverture de la fenêtre de redémarrage"] = round(cov, 2)
    checks.assert_no_problems(problems)

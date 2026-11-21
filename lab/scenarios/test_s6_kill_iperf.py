"""S6 — iperf3 tués sur c1 : relancés et mesurant de nouveau en moins de R s, sans zombie."""
from datetime import datetime, timedelta, timezone

from lab_fixtures import wait_until
from lablib import checks, faults, health, topology


def test_s6_kill_iperf(lab_up, metrics):
    t = datetime.now(timezone.utc)
    faults.kill_iperf("c1")
    wait_until(t + timedelta(seconds=topology.RECOVERY_S))
    since = t + timedelta(seconds=2)  # ignorer l'intervalle en cours au moment du kill
    problems = {}
    nr = checks.not_recovered(metrics, topology.flows_involving("LAB_C1", "both"), since, datetime.now(timezone.utc))
    if nr:
        problems[f"flux sans vraie mesure {topology.RECOVERY_S} s après le kill"] = nr
    z = health.snapshot("c1").zombies
    if z:
        problems["zombies sur c1"] = z
    checks.assert_no_problems(problems)

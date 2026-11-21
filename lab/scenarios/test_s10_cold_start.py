"""S10 — démarrage à froid répété : les deux clients à IP dynamique s'annoncent coup sur coup.

Course au démarrage (rapport du 2026-11-20, § 6) : quand C3 et C4 s'authentifient presque en même
temps, les clients à IP fixe doivent apprendre les deux IP et ouvrir leurs 6 flux.
"""
import time

from lablib import checks, docker, health, topology

ROUNDS = 3
FIXED_CONNECT_S = 15   # serveur + C1/C2 connectés ; > FRESH_S, donc aucun ancien point ne paraît frais
HEALTHY_S = 60


def test_s10_cold_start(lab_up, metrics):
    problems = {}
    nodes = [topology.container(s) for s in topology.SYNTRAF_NODES]
    fixed = [topology.container(s) for s in ("server",) + topology.FIXED]
    dynamic = [topology.container(s) for s in topology.DYNAMIC]
    for i in range(1, ROUNDS + 1):
        docker.run(["stop", "-t", "5", *nodes], timeout=120)
        docker.run(["start", *fixed], timeout=120)
        time.sleep(FIXED_CONNECT_S)
        docker.run(["start", *dynamic], timeout=120)
        try:
            health.wait_healthy(metrics, timeout_s=HEALTHY_S)
        except TimeoutError:
            problems[f"tour {i} : flux muets {HEALTHY_S} s après le démarrage de C3 et C4"] = \
                health.stale_flows(metrics, topology.expected_flows(), topology.FRESH_S)
    checks.assert_no_problems(problems)

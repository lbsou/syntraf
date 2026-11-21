"""S8 — 30 coupures de 5 s (toutes les 15 s) sur c2 : pas de fuite d'iperf3, de zombies, de threads ni de mémoire."""
import time

import pytest

from lablib import checks, faults, health, topology


@pytest.mark.slow
def test_s8_flap(lab_up, metrics):
    before = {s: health.snapshot(s) for s in topology.SYNTRAF_NODES}
    faults.flap("c2", "drop", off_s=5, on_s=10, count=30)
    time.sleep(60)
    after = {s: health.snapshot(s) for s in topology.SYNTRAF_NODES}
    problems = {}
    for s in topology.SYNTRAF_NODES:
        b, a = before[s], after[s]
        if a.iperf3_count != b.iperf3_count:
            problems[f"{s} iperf3 (avant, après)"] = (b.iperf3_count, a.iperf3_count)
        if a.zombies:
            problems[f"{s} zombies"] = a.zombies
        if not checks.within_pct(a.threads, b.threads, 10):
            problems[f"{s} threads (avant, après)"] = (b.threads, a.threads)
        if not checks.within_pct(a.rss_kb, b.rss_kb, 10):
            problems[f"{s} RSS ko (avant, après)"] = (b.rss_kb, a.rss_kb)
    checks.assert_no_problems(problems)

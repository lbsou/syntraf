"""S2 — dégradation 200 ms / 10 % sur c2 : pertes mesurées dans [5, 15] %, autres flux intacts."""
import time

from lablib import checks, faults, series, topology


def test_s2_degrade(lab_up, metrics, window):
    faults.degrade("c2", delay_ms=200, loss_pct=10)
    time.sleep(10)  # laisser passer la transition
    window.mark_start()
    time.sleep(120)
    window.mark_stop()
    faults.heal("c2")
    time.sleep(topology.FRESH_S)

    def mean_loss(f):
        return round(series.mean([v for _, v in metrics.points(f, window.start, window.stop)]), 2)

    from_c2 = {f: mean_loss(f) for f in topology.flows_involving("LAB_C2", "from")}
    others = {f: mean_loss(f) for f in topology.expected_flows() if "LAB_C2" not in f}
    problems = {f"{f} (attendu 5–15 %)": m for f, m in from_c2.items() if not 5 <= m <= 15}
    problems |= {f"{f} (attendu < 1 %)": m for f, m in others.items() if m >= 1}
    checks.assert_no_problems(problems)

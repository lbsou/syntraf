"""S1 — régime stable 10 min : aucun trou de plus de 2 s, pertes moyennes < 1 %."""
import time

import pytest

from lablib import checks, series, topology


@pytest.mark.slow
def test_s1_steady(lab_up, metrics, window):
    window.mark_start()
    time.sleep(600)
    window.mark_stop()
    time.sleep(topology.FRESH_S)
    problems = {}
    for f in topology.expected_flows():
        pts = metrics.points(f, window.start, window.stop)
        holes = series.gaps([t for t, _ in pts], window.start, window.stop, max_gap_s=2)
        loss = series.mean([v for _, v in pts])
        if holes or loss >= 1.0:
            longest = max(((b - a).total_seconds() for a, b in holes), default=0)
            problems[f] = {"trous": len(holes), "plus_long_s": round(longest, 1), "pertes_moy": round(loss, 2)}
    checks.assert_no_problems(problems)

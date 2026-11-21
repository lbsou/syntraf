from datetime import datetime, timedelta, timezone

from lablib import checks

T0 = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


def at(s):
    return T0 + timedelta(seconds=s)


class FakeMetrics:
    def __init__(self, data):
        self.data = data  # flow -> [(t, v)]

    def points(self, flow, start, stop, field="RX_PCT_LOSS"):
        return [(t, v) for t, v in self.data.get(flow, []) if start <= t <= stop]


def test_value_coverage_counts_only_matching_values():
    pts = [(at(s), 100.0) for s in range(0, 8)] + [(at(s), 0.0) for s in range(8, 10)]
    assert checks.value_coverage(pts, at(0), at(10), lambda v: v >= 99.9) == 0.8


def test_not_recovered_requires_real_measure_after_since():
    m = FakeMetrics({
        "A": [(at(5), 100.0), (at(12), 0.0)],    # vraie mesure après 10 → repris
        "B": [(at(11), 100.0), (at(12), 100.0)],  # seulement des 100 % générés → pas repris
        "C": [(at(3), 0.0)],                      # rien après 10 → pas repris
    })
    assert checks.not_recovered(m, ["A", "B", "C"], since=at(10), until=at(20)) == ["B", "C"]


def test_within_pct():
    assert checks.within_pct(105, 100, 10) and not checks.within_pct(111, 100, 10)
    assert checks.within_pct(0, 0, 10)


def test_assert_no_problems_shows_every_item():
    import pytest
    problems = {f"flux {i}": i for i in range(12)}
    with pytest.raises(AssertionError) as exc:
        checks.assert_no_problems(problems)
    assert all(f"flux {i}" in str(exc.value) for i in range(12))
    checks.assert_no_problems({})

from datetime import datetime, timedelta, timezone

from lablib import series

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ts(*secs):
    return [T0 + timedelta(seconds=s) for s in secs]


def at(s):
    return T0 + timedelta(seconds=s)


def test_gaps_detects_hole_larger_than_threshold():
    assert series.gaps(ts(0, 1, 2, 8, 9), T0, at(9), max_gap_s=2) == [(at(2), at(8))]


def test_gaps_counts_missing_edges_of_window():
    assert series.gaps(ts(5), T0, at(10), max_gap_s=2) == [(at(0), at(5)), (at(5), at(10))]


def test_gaps_empty_series_is_one_big_gap():
    assert series.gaps([], T0, at(10), max_gap_s=2) == [(at(0), at(10))]


def test_gaps_unsorted_input_is_handled():
    assert series.gaps(ts(2, 0, 1), T0, at(2), max_gap_s=2) == []


def test_coverage_full_and_half():
    assert series.coverage(ts(*range(10)), T0, at(10), 1) == 1.0
    assert series.coverage(ts(*range(0, 10, 2)), T0, at(10), 1) == 0.5


def test_coverage_ignores_points_outside_window():
    assert series.coverage(ts(-5, 20), T0, at(10), 1) == 0.0


def test_mean_empty_is_zero():
    assert series.mean([]) == 0.0
    assert series.mean([1.0, 3.0]) == 2.0

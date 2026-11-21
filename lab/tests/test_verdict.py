"""Tests du plugin de verdicts des scénarios (scenarios/verdict.py)."""
from pathlib import Path

SCENARIOS = str(Path(__file__).resolve().parent.parent / "scenarios")


def run(pytester, known: str):
    pytester._monkeypatch.setenv("PYTHONPATH", SCENARIOS)
    pytester._monkeypatch.setenv("PYTHONUTF8", "1")
    kf = pytester.path / "kf.txt"
    kf.write_text(known, encoding="utf-8")
    rep = pytester.path / "rep"
    r = pytester.runpytest_subprocess("-p", "verdict", f"--known-failures={kf}", f"--report-dir={rep}")
    summary = (rep / "summary.md").read_text(encoding="utf-8")
    return r, summary


def test_listed_failure_is_known_and_exit_zero(pytester):
    pytester.makepyfile(test_a="def test_x():\n    assert False\n")
    r, summary = run(pytester, "test_a.py::test_x | bogue connu\n")
    assert r.ret == 0
    assert "known_failure" in summary and "bogue connu" in summary


def test_unlisted_failure_is_regression_and_exit_one(pytester):
    pytester.makepyfile(test_a="def test_x():\n    assert False\n\ndef test_y():\n    pass\n")
    r, summary = run(pytester, "# vide\n")
    assert r.ret == 1
    assert "regression" in summary and "test_a.py::test_x" in summary


def test_listed_test_that_passes_is_fixed(pytester):
    pytester.makepyfile(test_a="def test_x():\n    pass\n")
    r, summary = run(pytester, "test_a.py::test_x | ancien bogue\n")
    assert r.ret == 0
    assert "fixed" in summary


def test_setup_error_counts_as_failure(pytester):
    pytester.makepyfile(test_a="import pytest\n\n@pytest.fixture\ndef boom():\n    raise RuntimeError('x')\n\n"
                               "def test_x(boom):\n    pass\n")
    r, summary = run(pytester, "")
    assert r.ret == 1 and "regression" in summary

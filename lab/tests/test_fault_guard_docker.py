"""Piège n° 3 : un scénario qui plante ne doit laisser aucune panne active (lab démarré requis)."""
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.docker

LAB = Path(__file__).resolve().parent.parent


def test_fixture_heals_on_failure(pytester):
    pytester._monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(LAB / "scenarios"), str(LAB)]))
    pytester._monkeypatch.setenv("PYTHONUTF8", "1")
    pytester.makepyfile(test_guard='''
from lablib import faults


def test_a_crashes_with_fault_active(lab_up):
    faults.cut("c2", "drop")
    raise RuntimeError("scénario qui plante")


def test_b_starts_clean(lab_up):
    assert faults.active("c2") == []
''')
    r = pytester.runpytest_subprocess("-p", "lab_fixtures", "-p", "no:cacheprovider")
    r.assert_outcomes(passed=1, failed=1)

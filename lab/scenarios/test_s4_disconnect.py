"""S4 — interface retirée (docker network disconnect) 60 s, sur c2 (IP fixe) puis c3 (IP dynamique)."""
import pytest

from cut_common import cut_and_check
from lablib import checks


@pytest.mark.parametrize("svc", ["c2", "c3"], ids=["c2-ip-fixe", "c3-ip-dynamique"])
def test_s4_disconnect(lab_up, metrics, window, svc):
    checks.assert_no_problems(cut_and_check(metrics, window, svc, "disconnect"))

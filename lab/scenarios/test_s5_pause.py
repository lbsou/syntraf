"""S5 — hôte figé (docker pause) 60 s, sur c2 (IP fixe) puis c3 (IP dynamique) ; les pairs ne restent pas bloqués."""
import pytest

from cut_common import cut_and_check
from lablib import checks


@pytest.mark.parametrize("svc", ["c2", "c3"], ids=["c2-ip-fixe", "c3-ip-dynamique"])
def test_s5_pause(lab_up, metrics, window, svc):
    checks.assert_no_problems(cut_and_check(metrics, window, svc, "pause", check_peers_iperf=True))

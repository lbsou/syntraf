"""S3 — perte silencieuse (iptables DROP) de 60 s, sur un client à IP fixe (c2) puis dynamique (c3)."""
import pytest

from cut_common import cut_and_check
from lablib import checks


@pytest.mark.parametrize("svc", ["c2", "c3"], ids=["c2-ip-fixe", "c3-ip-dynamique"])
def test_s3_drop(lab_up, metrics, window, svc):
    checks.assert_no_problems(cut_and_check(metrics, window, svc, "drop"))

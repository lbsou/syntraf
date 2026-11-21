"""S0 (migration) — aucun avertissement de dépréciation venant du code SYNTRAF, horodatages UTC."""
from datetime import datetime, timezone

from lablib import docker, topology


def test_no_deprecation_warning_from_syntraf_code(lab_up):
    for svc in topology.SYNTRAF_NODES:
        logs = docker.compose(["logs", "--no-color", svc]).stdout
        offending = [line for line in logs.splitlines()
                     if "DeprecationWarning" in line and ("/app/lib/" in line or "/app/syntraf.py" in line)]
        assert offending == [], (svc, offending[:3])


def test_points_are_utc_now(lab_up, metrics):
    t = metrics.last_point_time(topology.expected_flows()[0])
    assert t is not None
    assert abs((datetime.now(timezone.utc) - t).total_seconds()) < topology.FRESH_S

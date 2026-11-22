"""Garde-fous de capacité (lib/st_capacity.py) : mesure d'une configuration générée, comparaison aux limites.
Module sans dépendance : tourne dans lab/.venv.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_capacity as cap  # noqa: E402


def mesh(members, bandwidth="100K", interval="1"):
    """Config générée d'un maillage complet : chaque membre a un connecteur et un listener par autre membre."""
    generated = {}
    for a in members:
        generated[a] = {
            "CONNECTORS": {f"{a}->{b}": {"BANDWIDTH": bandwidth, "INTERVAL": interval} for b in members if b != a},
            "LISTENERS": {f"{b}->{a}": {"INTERVAL": interval} for b in members if b != a},
        }
    return generated


NODES4 = [f"N{i}" for i in range(4)]
NODES30 = [f"N{i}" for i in range(30)]


def test_measure_counts_flows_processes_bandwidth_and_points():
    m = cap.measure(mesh(NODES4))
    assert m["total_flows"] == 12 and m["points_per_s"] == 12
    assert m["clients"]["N0"] == {"connectors": 3, "listeners": 3, "processes": 6, "kbps_out": 300.0}


def test_bandwidth_units_are_understood():
    assert cap.measure(mesh(["A", "B"], bandwidth="1.5M"))["clients"]["A"]["kbps_out"] == 1500.0
    assert cap.measure(mesh(["A", "B"], bandwidth="2000"))["clients"]["A"]["kbps_out"] == 2.0


def test_limits_have_defaults_and_read_the_server_section():
    assert cap.limits({}) == {"MAX_FLOWS_PER_CLIENT": 50, "MAX_TOTAL_FLOWS": 2000, "FLOW_ALERT_ADDED": 100,
                              "FLOW_ALERT_RATIO": 2.0}
    assert cap.limits({"MAX_TOTAL_FLOWS": "500", "FLOW_ALERT_RATIO": "1.5"})["MAX_TOTAL_FLOWS"] == 500


def test_small_change_is_neither_alerted_nor_blocked():
    a = cap.assess(cap.measure(mesh(NODES4)), cap.measure(mesh(NODES4 + ["N9"])), cap.limits({}))
    assert a["violations"] == [] and a["alert"] is False
    assert a["after"]["total_flows"] == 20 and a["added_flows"] == 8


def test_switching_thirty_members_to_mesh_is_blocked_with_the_reason():
    a = cap.assess(cap.measure({}), cap.measure(mesh(NODES30)), cap.limits({}))
    assert a["alert"] is True
    assert any("per client" in v for v in a["violations"]) is False  # 29 flux par client : sous 50
    a = cap.assess(cap.measure({}), cap.measure(mesh(NODES30)), cap.limits({"MAX_TOTAL_FLOWS": "500"}))
    assert any("870 flows in total" in v for v in a["violations"])


def test_per_client_limit():
    big = [f"N{i}" for i in range(60)]
    a = cap.assess(cap.measure({}), cap.measure(mesh(big)), cap.limits({}))
    assert any("59 flows" in v and "per client" in v for v in a["violations"])


def test_alert_on_flows_added_or_total_multiplied():
    eight, thirteen = cap.measure(mesh(NODES30[:8])), cap.measure(mesh(NODES30[:13]))  # 56 -> 156 : +100, x2.8
    assert cap.assess(eight, thirteen, cap.limits({}))["alert"] is True
    assert cap.assess(eight, thirteen, cap.limits({"FLOW_ALERT_RATIO": "3"}))["alert"] is False
    assert cap.assess(eight, cap.measure(mesh(NODES30[:14])), cap.limits({"FLOW_ALERT_RATIO": "3"}))["alert"] is True


def test_small_installations_are_not_alerted_by_the_growth_factor():
    assert cap.assess(cap.measure(mesh(["A", "B"])), cap.measure(mesh(["A", "B", "C"])), cap.limits({}))["alert"] is False


def test_an_installation_already_over_a_limit_can_still_change_without_growing():
    over = cap.measure(mesh(NODES30))
    a = cap.assess(over, over, cap.limits({"MAX_TOTAL_FLOWS": "100"}))
    assert a["violations"] == [] and a["alert"] is False
    smaller = cap.measure(mesh(NODES30[:-1]))
    assert cap.assess(over, smaller, cap.limits({"MAX_TOTAL_FLOWS": "100"}))["violations"] == []


def test_busiest_client_is_reported():
    hub = mesh(["H", "A"])
    hub["H"]["CONNECTORS"].update({"H->B": {"BANDWIDTH": "100K", "INTERVAL": "1"}})
    a = cap.assess(cap.measure({}), cap.measure(hub), cap.limits({}))
    assert a["busiest"] == "H" and a["after"]["clients"]["H"]["connectors"] == 2

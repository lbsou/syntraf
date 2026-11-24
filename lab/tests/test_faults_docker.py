"""Tests d'intégration de l'injection de pannes : nécessitent le lab démarré (labctl up)."""
import re

import pytest

from lablib import docker, faults, health, topology

pytestmark = pytest.mark.docker


def ping_avg_ms(src: str, dst: str, count: int = 5) -> float | None:
    """RTT moyen en ms de src vers dst, None si 100 % de perte."""
    r = docker.exec_(src, ["ping", "-c", str(count), "-i", "0.2", "-W", "1", "-q", topology.SERVICES[dst]],
                     check=False, timeout=30)
    m = re.search(r"= [\d.]+/([\d.]+)/", r.stdout)
    return float(m.group(1)) if m else None


@pytest.fixture(autouse=True)
def always_heal():
    yield
    faults.heal_all()


def test_degrade_adds_latency():
    faults.degrade("c2", delay_ms=100)
    assert ping_avg_ms("c1", "c2") >= 95
    faults.heal("c2")
    assert ping_avg_ms("c1", "c2") < 10


def test_degrade_to_targets_only_that_destination():
    faults.degrade("c1", delay_ms=100, to="c2")
    assert ping_avg_ms("c1", "c2") >= 95
    assert ping_avg_ms("c1", "c3") < 50  # c3 a son propre lien dégradé (12 ± 4 ms, LINK_PROFILES), loin des 100 ms


def test_drop_blocks_and_heal_restores():
    faults.cut("c2", "drop")
    assert ping_avg_ms("c1", "c2") is None
    faults.heal("c2")
    assert ping_avg_ms("c1", "c2") is not None


def test_drop_to_server_keeps_peers_reachable():
    faults.cut("c2", "drop", to="server")
    assert ping_avg_ms("c2", "server") is None
    assert ping_avg_ms("c2", "c1") is not None


def test_disconnect_reconnect_keeps_ip():
    faults.cut("c3", "disconnect")
    assert topology.NETWORK not in docker.inspect_state("c3")["networks"]
    faults.heal("c3")
    assert docker.inspect_state("c3")["networks"][topology.NETWORK] == "172.30.0.33"


def test_pause_unpause():
    faults.cut("c3", "pause")
    assert docker.inspect_state("c3")["paused"] is True
    faults.heal("c3")
    assert docker.inspect_state("c3")["paused"] is False


def test_degrade_after_reconnect_targets_lab_interface():
    faults.cut("c3", "disconnect")
    faults.heal("c3")
    faults.degrade("c3", delay_ms=100)
    assert ping_avg_ms("c1", "c3") >= 95


def test_heal_twice_is_noop():
    faults.heal("c2")
    faults.heal("c2")
    assert faults.active("c2") == []


def test_degrade_twice_replaces():
    faults.degrade("c2", delay_ms=50)
    faults.degrade("c2", delay_ms=80, loss_pct=1)
    out = docker.exec_("c2", ["tc", "qdisc", "show"]).stdout
    assert out.count("netem") == 1 and "delay 80ms" in out


def test_status_reports_active_faults():
    faults.cut("c2", "drop")
    assert faults.active("c2") != []
    faults.heal("c2")
    assert faults.active("c2") == []


def test_kill_iperf_kills_processes():
    assert health.snapshot("c1").iperf3_count > 0
    faults.kill_iperf("c1")
    assert health.snapshot("c1").iperf3_count == 0

"""Charge du poste des sondes : lecture de SAVE_STATS_METRIC, dernière valeur, publication sur /metrics, carte."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_host_stats as hs  # noqa: E402

OLD_PROBE = {"timestamp": "2026-11-27 10:00:00", "mem_pct_free": 38, "cpu_pct_usage": 91,
             "if_pct_usage_rx": "Network interface not found, see NETWORK_INTERFACE_NAME",
             "if_pct_usage_tx": "Network interface not found, see NETWORK_INTERFACE_NAME"}


def probe(status="CONNECTED"):
    return SimpleNamespace(status=status)


def test_a_probe_payload_gives_used_memory_and_both_cpu_figures():
    v = hs.from_payload(dict(OLD_PROBE, cpu_pct=23.456, if_pct_usage_rx=4.2, if_pct_usage_tx=0.5))
    assert {k: v[k] for k in ("cpu_pct", "cpu_busiest_core_pct", "mem_used_pct", "nic_rx_pct", "nic_tx_pct")} == {
        "cpu_pct": 23.5, "cpu_busiest_core_pct": 91.0, "mem_used_pct": 62.0, "nic_rx_pct": 4.2, "nic_tx_pct": 0.5}


def test_a_recent_probe_reports_the_real_nic_throughput_and_its_share_of_the_link():
    v = hs.from_payload(dict(OLD_PROBE, nic="Wi-Fi", nic_rx_bps=25_000_000.4, nic_tx_bps=1_000_000,
                             nic_speed_mbps=100, if_pct_usage_rx=25, if_pct_usage_tx=1))
    assert (v["nic"], v["nic_rx_bps"], v["nic_tx_bps"], v["nic_speed_mbps"]) == ("Wi-Fi", 25_000_000, 1_000_000, 100)
    assert (v["nic_rx_pct"], v["nic_tx_pct"]) == (25.0, 1.0)


def test_an_unknown_link_speed_gives_an_unknown_share_not_zero():
    v = hs.from_payload(dict(OLD_PROBE, nic_rx_bps=8_000_000, nic_tx_bps=0, nic_speed_mbps=None,
                             if_pct_usage_rx=0, if_pct_usage_tx=0))
    assert v["nic_rx_bps"] == 8_000_000 and v["nic_rx_pct"] is None and v["nic_tx_pct"] is None


def test_an_older_probe_has_no_average_cpu_and_text_instead_of_nic_figures():
    v = hs.from_payload(OLD_PROBE)
    assert v["cpu_pct"] is None and v["cpu_busiest_core_pct"] == 91.0
    assert v["nic_rx_pct"] is None and v["nic_tx_pct"] is None


def test_out_of_range_or_invalid_values_are_bounded_or_dropped():
    v = hs.from_payload({"cpu_pct": 130, "cpu_pct_usage": float("nan"), "mem_pct_free": -5, "if_pct_usage_rx": True})
    assert v["cpu_pct"] == 100.0 and v["cpu_busiest_core_pct"] is None
    assert v["mem_used_pct"] == 100.0 and v["nic_rx_pct"] is None
    assert hs.from_payload(None)["cpu_pct"] is None


def test_the_latest_values_are_kept_with_the_server_time():
    p = probe()
    hs.record(p, OLD_PROBE, now=1000.0)
    v = hs.latest(p, now=1010.0)
    assert (v["cpu_pct"], v["cpu_busiest_core_pct"], v["mem_used_pct"], v["age_s"]) == (None, 91.0, 62.0, 10.0)
    assert v["nic_rx_bps"] is None and v["nic"] is None


def test_stale_values_or_a_disconnected_probe_show_nothing():
    p = probe()
    hs.record(p, OLD_PROBE, now=1000.0)
    assert hs.latest(p, now=1000.0 + hs.MAX_AGE_S + 1) is None
    p.status = "DISCONNECTED"
    assert hs.latest(p, now=1001.0) is None
    assert hs.latest(probe("CONNECTED (PASSIVE)"), now=1.0) is None  # jamais rien reçu
    assert hs.latest(None) is None


def test_a_passive_probe_still_reports_its_load():
    p = probe("CONNECTED (PASSIVE)")
    hs.record(p, OLD_PROBE, now=5.0)
    assert hs.latest(p, now=6.0)["mem_used_pct"] == 62.0


def test_the_nic_meter_measures_the_throughput_over_the_whole_period(monkeypatch):
    import psutil
    from lib import st_system_stats as ss
    counters = {"rx": 1_000_000, "tx": 0}
    monkeypatch.setattr(psutil, "net_io_counters", lambda **k: {"eth0": SimpleNamespace(
        bytes_recv=counters["rx"], bytes_sent=counters["tx"])})
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {"eth0": SimpleNamespace(speed=0)})
    clock = iter([10.0, 14.0])
    meter = ss.NicMeter("eth0", clock=lambda: next(clock))
    assert meter.sample() is None  # référence
    counters.update(rx=6_000_000, tx=500_000)  # 5 Mo reçus et 0,5 Mo envoyés en 4 s
    assert meter.sample() == {"rx_bps": 10_000_000.0, "tx_bps": 1_000_000.0, "speed_mbps": None}
    assert ss.nic_percent(10_000_000, 100) == 10.0 and ss.nic_percent(10_000_000, None) is None


def test_the_probe_cpu_gives_the_average_and_the_busiest_core(monkeypatch):
    import psutil
    from lib import st_system_stats as ss
    monkeypatch.setattr(ss.time, "sleep", lambda s: None)
    monkeypatch.setattr(psutil, "cpu_times_percent", lambda **k: [
        SimpleNamespace(_asdict=lambda: {"idle": 90.0}), SimpleNamespace(_asdict=lambda: {"idle": 10.0})])
    assert ss.grab_cpu() == (50.0, 90)
    assert ss.grab_cpu_usage() == 90


def test_the_metrics_endpoint_publishes_the_load_of_connected_probes_only():
    import pytest
    st_status = pytest.importorskip("lib.webui.st_status")
    busy, gone = probe(), probe("DISCONNECTED")
    hs.record(busy, dict(OLD_PROBE, cpu_pct=12.5, nic="eth0", nic_rx_bps=4_000_000, nic_tx_bps=0, nic_speed_mbps=1000))
    hs.record(gone, OLD_PROBE)
    rows = [{"uid": "BUSY", "status": "CONNECTED", "host": hs.latest(busy)},
            {"uid": "GONE", "status": "DISCONNECTED", "host": hs.latest(gone)}]
    snap = {"version": "x", "clients": [dict(r, listeners=0, connectors=0, metrics_buffer=None) for r in rows],
            "mesh_groups_summary": {"enabled": 0, "disabled": 0}, "databases": [], "threads": [], "queue_length": 0}
    import unittest.mock as um
    with um.patch.object(st_status, "snapshot", lambda state: snap):
        text = st_status.metrics({})
    assert 'syntraf_client_cpu_percent{client="BUSY"} 12.5' in text
    assert 'syntraf_client_cpu_busiest_core_percent{client="BUSY"} 91.0' in text
    assert 'syntraf_client_memory_used_percent{client="BUSY"} 62.0' in text
    assert 'syntraf_client_nic_rx_bits_per_second{client="BUSY"} 4000000' in text
    assert 'syntraf_client_nic_speed_mbps{client="BUSY"} 1000' in text
    assert 'syntraf_client_nic_rx_percent{client="BUSY"} 0.4' in text
    assert 'client="GONE"} ' not in text.split("syntraf_client_cpu_busiest_core_percent", 1)[1].split("# HELP syntraf_mesh", 1)[0]


def test_a_probe_builds_and_sends_the_load_of_its_host(monkeypatch):
    import psutil
    from lib import st_system_stats as ss
    monkeypatch.setattr(ss.time, "sleep", lambda s: None)
    monkeypatch.setattr(psutil, "cpu_times_percent", lambda **k: [SimpleNamespace(_asdict=lambda: {"idle": 80.0})])
    monkeypatch.setattr(psutil, "virtual_memory", lambda: SimpleNamespace(_asdict=lambda: {"available": 25, "total": 100}))
    monkeypatch.setattr(psutil, "net_io_counters", lambda **k: {"eth0": SimpleNamespace(bytes_recv=0, bytes_sent=0)})
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {"eth0": SimpleNamespace(speed=1000)})
    monkeypatch.setattr(ss, "choose_interface", lambda client: "eth0")
    stats = ss.system_stats({"CLIENT": {"SERVER": "192.0.2.1"}})
    stats.update_stats()
    sent = stats.as_dict()
    assert (sent["cpu_pct"], sent["cpu_pct_usage"], sent["mem_pct_free"], sent["nic"]) == (20.0, 20, 25, "eth0")
    v = hs.from_payload(sent)
    assert (v["cpu_pct"], v["mem_used_pct"], v["nic_speed_mbps"]) == (20.0, 75.0, 1000)

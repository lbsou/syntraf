"""Horloge des sondes : écart au serveur mesuré en continu (échange à 4 horodatages, comme NTP), dérive, alertes."""
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_baseline as bl  # noqa: E402
from lib import st_clock as ck  # noqa: E402


def test_the_four_timestamps_give_the_offset_without_the_network_delay():
    # sonde en retard de 2 s ; 40 ms de trajet dans chaque sens ; 1 ms de traitement au serveur
    t1 = 1000.0                   # envoi (horloge de la sonde)
    t2 = t1 + 2 + 0.040           # réception (horloge du serveur)
    t3 = t2 + 0.001               # réponse (serveur)
    t4 = t3 - 2 + 0.040           # réception (sonde)
    offset, delay = ck.sample(t1, t2, t3, t4)
    assert offset == pytest.approx(2.0) and delay == pytest.approx(0.080)


def exchange(client, tracker, true_offset, at, delay=0.010):
    """Un AWAITING_COMMAND : la sonde horodate, le serveur répond, la sonde note l'arrivée."""
    t1 = at - true_offset
    payload = client.request(t1)
    t2 = at + delay / 2
    t3 = t2 + 0.0005
    tracker.exchange(payload, t2, t3)
    client.replied(t1, t3 - true_offset + delay / 2)


def test_the_server_measures_each_probe_continuously_from_the_command_polls():
    client, tracker = ck.ClientClock(), ck.ClockTracker()
    assert client.request(100.0) == {"T1": 100.0}  # premier échange : rien à rapporter encore
    for i in range(10):
        exchange(client, tracker, true_offset=-0.250, at=1000 + 2 * i)  # sonde en avance de 250 ms
    est = tracker.estimate(now=1020)
    assert est["offset_ms"] == pytest.approx(-250, abs=1) and est["delay_ms"] == pytest.approx(10, abs=1)
    assert est["drift_ppm"] is None  # moins d'une heure d'historique


def test_the_estimate_keeps_the_least_delayed_exchange():
    tracker = ck.ClockTracker()
    tracker.add(1000, offset=0.120, delay=0.300)   # trajet chargé : asymétrie, écart faussé
    tracker.add(1001, offset=0.002, delay=0.004)
    tracker.add(1002, offset=0.090, delay=0.200)
    assert tracker.estimate(now=1003)["offset_ms"] == pytest.approx(2)


def test_a_free_running_clock_shows_its_drift_in_ppm():
    tracker = ck.ClockTracker()
    for minute in range(90):  # la sonde gagne 20 µs par seconde (20 ppm) : l'écart serveur - sonde diminue
        t = 10000 + 60 * minute
        tracker.add(t, offset=0.5 - 20e-6 * (t - 10000), delay=0.005)
    est = tracker.estimate(now=10000 + 60 * 90)
    assert est["drift_ppm"] == pytest.approx(20, abs=0.5)


def test_an_old_server_or_probe_is_simply_not_measured():
    tracker = ck.ClockTracker()
    tracker.exchange("", 1000.0, 1000.001)         # ancienne sonde : AWAITING_COMMAND sans charge
    tracker.exchange({"T1": "x", "PREV_T1": None}, 1001.0, 1001.001)
    assert tracker.estimate(now=1002) is None


def test_the_tracker_lives_on_the_server_side_client_object():
    obj = SimpleNamespace()
    assert ck.tracker(obj) is ck.tracker(obj)


def snap(offset=None, drift=None, status="CONNECTED"):
    return {"clients": [{"uid": "P1", "declared": True, "status": status, "status_since": "x", "metrics_buffer": 0,
                         "clock_offset_ms": offset, "clock_drift_ppm": drift}],
            "databases": [], "threads": [], "queue_length": 0}


def checks(s, settings=None):
    return {c["metric"]: c for c in bl.health_checks(s, settings) if c["subject"] == "P1"}


def test_health_flags_a_probe_whose_clock_is_off_or_drifting():
    c = checks(snap(offset=-1800.0, drift=0.1))
    assert c["probe_clock_offset"]["anomalous"] and "1.8 s" in c["probe_clock_offset"]["explanation"]
    assert not c["probe_clock_drift"]["anomalous"]
    c = checks(snap(offset=3.0, drift=42.0))
    assert not c["probe_clock_offset"]["anomalous"] and c["probe_clock_drift"]["anomalous"]
    assert "3.6 s per day" in c["probe_clock_drift"]["explanation"] and "NTP" in c["probe_clock_drift"]["explanation"]


def test_no_clock_check_without_a_measure_or_for_a_disconnected_probe():
    assert "probe_clock_offset" not in checks(snap())
    assert "probe_clock_offset" not in checks(snap(offset=5000.0, status="DISCONNECTED"))


def test_the_clock_limits_come_from_the_global_settings():
    s = bl.Settings.from_config({"GLOBAL": {"CLOCK_OFFSET_MAX_MS": "50", "CLOCK_DRIFT_MAX_PPM": "5"}})
    assert (s.clock_offset_max_ms, s.clock_drift_max_ppm) == (50.0, 5.0)
    c = checks(snap(offset=80.0, drift=6.0), s)
    assert c["probe_clock_offset"]["anomalous"] and c["probe_clock_drift"]["anomalous"]
    d = bl.Settings.from_config({})
    assert (d.clock_offset_max_ms, d.clock_drift_max_ppm) == (ck.OFFSET_MAX_MS, ck.DRIFT_MAX_PPM)

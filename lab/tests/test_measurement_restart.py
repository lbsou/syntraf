"""Redémarrage d'une mesure (iperf3) : ni fausses pertes ni longue attente.

- Pendant qu'une session iperf3 s'établit avec un pair qui a répondu, le silence est un trou, pas 100 % de pertes
  (l'outil redémarre, le réseau marche) ; après MAX_FAILED_STARTS échecs de suite, ou un pair injoignable, le
  silence redevient une panne (100 %), comme une vraie coupure.
- Une session qui n'a produit aucune mesure dans le délai de grâce est relancée (au lieu de ~30 s bloquée).
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_outage  # noqa: E402

CTX = {"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B", "DSCP": "0"}
UID = st_outage.flow_uid(CTX)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def tracker_with_flow():
    clock = Clock()
    tr = st_outage.SilenceTracker(clock=clock)
    tr.record(UID, 1000.0, 1, CTX)
    return tr, clock


def silent_for(tr, clock, seconds):
    clock.t += seconds
    return tr.fill(1000.0 + (clock.t - 1000.0))


def test_a_silence_is_still_an_outage_by_default():
    tr, clock = tracker_with_flow()
    assert len(silent_for(tr, clock, 20)) >= 15


def test_a_measurement_being_established_leaves_a_hole_not_losses():
    tr, clock = tracker_with_flow()
    tr.establishing(UID)
    assert silent_for(tr, clock, 20) == []
    # première mesure de la nouvelle session : aucune perte rétroactive
    assert tr.record(UID, 1000.0 + 21, 1, CTX) == []


def test_repeated_failed_starts_become_an_outage():
    tr, clock = tracker_with_flow()
    tr.establishing(UID)
    for _ in range(st_outage.MAX_FAILED_STARTS - 1):
        tr.failed_start(UID)
    assert silent_for(tr, clock, 10) == []
    tr.failed_start(UID)
    tr.establishing(UID)  # nouvelle tentative : ne masque plus rien
    assert len(silent_for(tr, clock, 10)) >= 5


def test_an_unreachable_peer_is_an_outage():
    tr, clock = tracker_with_flow()
    tr.establishing(UID)
    tr.unreachable(UID)
    assert len(silent_for(tr, clock, 10)) >= 5


def test_a_measurement_resets_the_failure_count():
    tr, clock = tracker_with_flow()
    tr.establishing(UID)
    for _ in range(st_outage.MAX_FAILED_STARTS - 1):
        tr.failed_start(UID)
    silent_for(tr, clock, 5)
    tr.record(UID, 1000.0 + 6, 1, CTX)
    tr.failed_start(UID)
    tr.establishing(UID)
    assert silent_for(tr, clock, 10) == []


def test_a_hold_does_not_last_forever():
    tr, clock = tracker_with_flow()
    tr.establishing(UID)
    assert silent_for(tr, clock, st_outage.HOLD_MAX_S - 5) == []
    assert len(silent_for(tr, clock, 20)) >= 15


# --------------------------------------------------------------------------- session bloquée (pas de mesure)

def test_a_session_without_any_measurement_after_the_grace_period_is_stalled():
    pytest.importorskip("psutil")
    try:
        from lib import st_process_and_thread as pt
    except (ImportError, SystemExit):
        pytest.skip("dépendances de SYNTRAF absentes")
    import datetime as dt
    start = dt.datetime(2026, 1, 1, 12, 0, 0)

    class Proc:
        starttime, measured_at = start, None

    assert pt.start_grace_s({"GLOBAL": {"IPERF3_CONNECT_TIMEOUT": "5"}}, {"INTERVAL": "1"}) == 9
    assert not pt.stalled(Proc, 9, start + dt.timedelta(seconds=8))
    assert pt.stalled(Proc, 9, start + dt.timedelta(seconds=10))
    Proc.measured_at = 1.0
    assert not pt.stalled(Proc, 9, start + dt.timedelta(seconds=100))


def test_iperf3_output_tells_when_the_peer_answered_and_when_measurements_start(monkeypatch):
    pytest.importorskip("psutil")
    try:
        from lib import st_iperf3_readlog as rl
    except (ImportError, SystemExit):
        pytest.skip("dépendances de SYNTRAF absentes")
    calls = []
    monkeypatch.setattr(rl.SILENCE, "establishing", lambda uid: calls.append(uid))

    class Proc:
        peer_reached, measured_at = False, None

    rl.session_progress("'2026-11-22 23:51:24 '[  5] local 10.99.0.34 port 42664 connected to 172.30.0.31 port 15996",
                        Proc, "A__TO__B__ON__DSCP0")
    assert Proc.peer_reached and calls == ["A__TO__B__ON__DSCP0"] and Proc.measured_at is None
    rl.session_progress("'2026-11-22 23:52:06 '[  6][RX-C]   1.00-2.00   sec  12.3 KBytes  100 Kbits/sec  0.010 ms  0/57 (0%)",
                        Proc, "A__TO__B__ON__DSCP0")
    assert Proc.measured_at is not None


def test_a_session_ending_without_measurement_is_a_failed_start_or_an_unreachable_peer(monkeypatch):
    pytest.importorskip("psutil")
    try:
        from lib import st_iperf3_readlog as rl
    except (ImportError, SystemExit):
        pytest.skip("dépendances de SYNTRAF absentes")
    seen = []
    monkeypatch.setattr(rl.SILENCE, "failed_start", lambda uid: seen.append(("failed", uid)))
    monkeypatch.setattr(rl.SILENCE, "unreachable", lambda uid: seen.append(("unreachable", uid)))
    config = {"LISTENERS": {"L": {"UID_CLIENT": "A", "UID_SERVER": "B", "MESH_GROUP": "G", "DSCP": "0"}},
              "CONNECTORS": {}}

    class Proc:
        peer_reached, measured_at = True, None

    rl.end_of_session(config, "LISTENER", "L", Proc)
    Proc.peer_reached = False
    rl.end_of_session(config, "LISTENER", "L", Proc)
    assert seen == [("failed", "A__TO__B__ON__DSCP0"), ("unreachable", "A__TO__B__ON__DSCP0")]


def test_a_failed_start_keeps_the_hole_even_if_the_session_died_before_saying_it_was_connected():
    tr, clock = tracker_with_flow()
    tr.failed_start(UID)  # pas d'establishing() : la session est morte avant sa ligne « connected to »
    assert silent_for(tr, clock, 10) == []


def test_the_iperf3_error_tells_whether_the_peer_answered(monkeypatch):
    pytest.importorskip("psutil")
    try:
        from lib import st_iperf3_readlog as rl
    except (ImportError, SystemExit):
        pytest.skip("dépendances de SYNTRAF absentes")
    seen = []
    monkeypatch.setattr(rl.SILENCE, "failed_start", lambda uid: seen.append("failed"))
    monkeypatch.setattr(rl.SILENCE, "unreachable", lambda uid: seen.append("unreachable"))
    config = {"LISTENERS": {"L": {"UID_CLIENT": "A", "UID_SERVER": "B", "MESH_GROUP": "G", "DSCP": "0"}},
              "CONNECTORS": {}}

    class Proc:
        peer_reached, measured_at, stall_killed = False, None, False

    rl.end_of_session(config, "LISTENER", "L", Proc, "iperf3: error - unable to read from stream socket")
    rl.end_of_session(config, "LISTENER", "L", Proc, "iperf3: error - unable to connect to server: Connection timed out")
    rl.end_of_session(config, "LISTENER", "L", Proc, "")
    Proc.stall_killed = True
    rl.end_of_session(config, "LISTENER", "L", Proc, "")
    assert seen == ["failed", "unreachable", "unreachable", "failed"]

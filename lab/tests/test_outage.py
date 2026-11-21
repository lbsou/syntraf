"""Tests de la détection du silence d'iperf3 (lib/st_outage.py), sans Docker.

Pendant une coupure, iperf3 n'écrit plus rien : SYNTRAF doit enregistrer des pertes à 100 % pour
chaque intervalle muet, sans doublon avec les vraies mesures quand iperf3 reprend.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib import st_outage  # noqa: E402

CTX = {"MESH_GROUP": "LAB_MESH", "CLIENT": "LAB_C2", "SERVER": "LAB_C1", "DSCP": "0"}
UID = "LAB_C2__TO__LAB_C1__ON__DSCP0"
T0 = 1_800_000_000  # epoch, secondes entières (iperf3 horodate à la seconde)


def tracker():
    return st_outage.SilenceTracker(lag_intervals=3)


def test_no_point_while_iperf3_reports_every_interval():
    tr = tracker()
    for s in range(10):
        tr.record(UID, T0 + s, 1, CTX)
        assert tr.fill(now=T0 + s + 1.9) == []


def test_silence_generates_one_point_per_interval_up_to_lag():
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    pts = tr.fill(now=T0 + 10.5)
    assert [p["time"] for p in pts] == [datetime.fromtimestamp(T0 + s, timezone.utc) for s in range(1, 8)]
    p = pts[0]
    assert p["measurement"] == "SYNTRAF"
    assert p["tags"] == {"MESH_GROUP": "LAB_MESH", "CLIENT": "LAB_C2", "SERVER": "LAB_C1", "UID": UID}
    assert p["fields"] == {"RX_BITRATE": 0.0, "RX_JITTER": 0.0, "RX_PCT_LOSS": 100.0,
                           "RX_PACKET_TOTAL": 0, "RX_PACKET_LOSS": 0}


def test_successive_fills_do_not_duplicate():
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    first = tr.fill(now=T0 + 6)
    second = tr.fill(now=T0 + 8)
    times = [p["time"] for p in first + second]
    assert len(times) == len(set(times)) == 5   # T0+1 .. T0+5


def test_real_line_after_silence_resumes_without_overlap():
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    generated = tr.fill(now=T0 + 20)            # jusqu'à T0+17
    tr.record(UID, T0 + 25, 1, CTX)             # iperf3 reprend
    assert tr.fill(now=T0 + 26.5) == []
    assert max(p["time"] for p in generated) < datetime.fromtimestamp(T0 + 25, timezone.utc)


def test_late_real_line_older_than_generated_does_not_move_back():
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    tr.fill(now=T0 + 10)                        # jusqu'à T0+7
    tr.record(UID, T0 + 5, 1, CTX)              # ligne en retard : ne doit pas faire régénérer 6 et 7
    assert [p["time"] for p in tr.fill(now=T0 + 11)] == [datetime.fromtimestamp(T0 + 8, timezone.utc)]


def test_flow_never_seen_generates_nothing():
    assert tracker().fill(now=T0) == []


def test_inactive_flow_is_skipped_and_forgotten():
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    assert tr.fill(now=T0 + 10, active=lambda uid: False) == []
    assert tr.fill(now=T0 + 20) == []           # oublié : plus rien à combler


def test_interval_of_two_seconds():
    tr = tracker()
    tr.record(UID, T0, 2, CTX)
    assert [p["time"] for p in tr.fill(now=T0 + 12)] == [datetime.fromtimestamp(T0 + s, timezone.utc) for s in (2, 4, 6)]


def test_flow_uid_matches_syntraf_uid_format():
    assert st_outage.flow_uid(CTX) == UID


def test_enqueue_keys_by_hash_and_caps_queue():
    q = {}
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    for p in tr.fill(now=T0 + 10):
        st_outage.enqueue(q, p, max_size=5)
    assert len(q) == 5
    assert all(len(k) == 40 for k in q)         # sha1 hexdigest, comme save_to_server
    kept = sorted(p["time"] for p in q.values())
    assert kept[0] == datetime.fromtimestamp(T0 + 3, timezone.utc)  # les plus anciens sont retirés


def test_gap_seen_by_a_real_line_before_any_fill_is_filled():
    # Nœud figé (docker pause) : au dégel, iperf3 publie une ligne avant que la boucle de surveillance
    # n'ait appelé fill() ; le trou doit quand même être couvert de pertes à 100 %.
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    pts = tr.record(UID, T0 + 60, 1, CTX)
    assert [p["time"] for p in pts] == [datetime.fromtimestamp(T0 + s, timezone.utc) for s in range(1, 60)]
    assert tr.fill(now=T0 + 61) == []


def test_small_irregularity_is_not_an_outage():
    # Une horloge qui saute de 1,5 s ne doit pas produire de fausses pertes.
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    assert tr.record(UID, T0 + 2.5, 1, CTX) == []
    assert tr.record(UID, T0 + 3.5, 1, CTX) == []


def test_gap_partly_filled_then_closed_by_a_real_line_has_no_duplicate():
    tr = tracker()
    tr.record(UID, T0, 1, CTX)
    first = tr.fill(now=T0 + 10)                # T0+1 .. T0+7
    rest = tr.record(UID, T0 + 30, 1, CTX)      # T0+8 .. T0+29
    times = [p["time"] for p in first + rest]
    assert times == [datetime.fromtimestamp(T0 + s, timezone.utc) for s in range(1, 30)]

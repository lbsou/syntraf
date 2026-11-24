"""Lecture de la sortie --json-stream d'iperf3 (lib/st_iperf3_readlog.py), sur des sorties réelles capturées dans
le lab (iperf 3.22.1) : émetteur bidirectionnel (derrière un NAT), récepteur, erreur."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
DATA = Path(__file__).parent / "data"
try:
    from lib import st_iperf3_readlog as rl
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes", allow_module_level=True)


def lines(name):
    return (DATA / name).read_text(encoding="utf-8").splitlines()


class Proc:
    peer_reached, measured_at, bidir_src_port, bidir_local_addr, test_start, last_error = False, None, None, None, None, None


def test_the_start_event_gives_the_return_stream_port_and_the_test_start():
    p = Proc()
    event = rl.json_event(lines("iperf3_json_stream_client_bidir.txt")[0])
    rl.json_start(event, p)
    assert p.bidir_src_port == 59515 and p.bidir_local_addr == "10.99.0.34"
    assert p.test_start == pytest.approx(1795402963.486)


def test_an_interval_gives_the_received_direction_of_a_bidir_client():
    p = Proc()
    ls = lines("iperf3_json_stream_client_bidir.txt")
    rl.json_start(rl.json_event(ls[0]), p)
    m = rl.json_interval(rl.json_event(ls[1]), p)
    assert m["jitter"] == pytest.approx(6.496, abs=1e-3) and m["packet_loss"] == 4 and m["packet_total"] == 58
    assert m["loss"] == pytest.approx(6.897, abs=1e-3) and m["bitrate_kbps"] == pytest.approx(94.16, abs=0.01)
    assert m["utime"] == pytest.approx(1795402963.486 + 1.00017, abs=1e-3)


def test_an_interval_gives_the_received_direction_of_a_listener():
    p = Proc()
    ls = lines("iperf3_json_stream_server.txt")
    rl.json_start(rl.json_event(ls[0]), p)
    m = rl.json_interval(rl.json_event(ls[1]), p)
    assert m["packet_loss"] == 2 and m["packet_total"] == 54 and m["jitter"] == pytest.approx(5.68, abs=1e-2)


def test_an_interval_without_any_packet_is_100_percent_loss():
    p = Proc()
    p.test_start = 1000.0
    event = {"event": "interval", "data": {"sum": {"end": 1.0, "bits_per_second": 0, "jitter_ms": 0.02,
                                                   "lost_packets": 0, "packets": 0, "lost_percent": 0, "sender": False}}}
    assert rl.json_interval(event, p)["loss"] == 100.0


def test_errors_are_kept_for_the_end_of_session():
    p = Proc()
    rl.json_error(rl.json_event(lines("iperf3_json_stream_error.txt")[0]), p)
    assert "busy" in p.last_error
    assert rl.peer_answered(p, "")  # le pair a répondu (occupé), ce n'est pas un pair injoignable


def test_the_listener_learns_the_peer_address_for_the_latency_reflector():
    from lib import st_twamp
    st_twamp.LEARNED.clear()
    p = Proc()
    rl.session_progress(lines("iperf3_json_stream_server.txt")[0], p, "A__TO__B__ON__DSCP0")
    assert "172.30.0.35" in st_twamp.LEARNED and p.peer_reached
    st_twamp.LEARNED.clear()


def test_text_lines_are_not_json():
    assert rl.json_event("'2026-11-22 23:51:24 '[  5] local 10.99.0.34 port 42664 connected to") is None


def test_any_interval_proves_the_session_is_alive_even_for_a_sender_only_connector():
    """Sans cela, le détecteur de session bloquée relançait les émetteurs simples toutes les ~14 s."""
    p = Proc()
    sender_only = '{"event":"interval","data":{"streams":[],"sum":{"start":0,"end":1,"bytes":12644,' \
                  '"bits_per_second":101135,"packets":58,"omitted":false,"sender":true}}}'
    rl.session_progress(sender_only, p, None)
    assert p.measured_at is not None

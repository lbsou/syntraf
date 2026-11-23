"""Latence aller-retour (lib/st_twamp.py) : paquets TWAMP-Light (RFC 5357, mode non authentifié), réflecteur,
mesure depuis la sonde qui initie (celle derrière un NAT), points pour la base, et prise en compte dans le MOS."""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_twamp as tw  # noqa: E402


def test_ntp_timestamps_roundtrip():
    t = 1795400000.123456
    assert abs(tw.from_ntp(tw.to_ntp(t)) - t) < 1e-6


def test_sender_and_reflector_packets():
    pkt = tw.sender_packet(7, 1795400000.5)
    assert len(pkt) == tw.PACKET_SIZE and tw.parse_sender(pkt)["seq"] == 7
    reply = tw.reflect(pkt, received=1795400000.6, sent=1795400000.61, seq=3)
    r = tw.parse_reply(reply)
    assert r["sender_seq"] == 7 and r["seq"] == 3
    assert abs(r["sender_ts"] - 1795400000.5) < 1e-6
    assert abs((r["sent"] - r["received"]) - 0.01) < 1e-6
    assert len(reply) >= 41  # format réflecteur de la RFC 5357 (§4.2.1)


def test_a_reply_never_amplifies():
    assert len(tw.reflect(tw.sender_packet(1, 0.0), 0.0, 0.0, 1)) <= tw.PACKET_SIZE


def test_rtt_excludes_the_reflector_processing_time():
    # 30 ms entre envoi et réception chez l'initiateur, dont 10 ms passés dans le réflecteur
    assert tw.rtt_ms(sent_mono=100.0, received_mono=100.030, reflector_received=50.0, reflector_sent=50.010) == \
        pytest.approx(20.0)


def test_interval_statistics():
    assert tw.stats(5, [20.0, 22.0, 30.0, 21.0]) == {"RTT_MS": 23.25, "RTT_MIN_MS": 20.0, "RTT_MAX_MS": 30.0,
                                                     "LOSS_PCT": 20.0}
    assert tw.stats(5, []) == {"LOSS_PCT": 100.0}


CONFIG = {"CLIENT": {"CLIENT_UID": "STARLINK"},
          "CONNECTORS": {
              "k1": {"UID_CLIENT": "STARLINK", "UID_SERVER": "LAB_C1", "DESTINATION_ADDRESS": "172.30.0.31",
                     "DSCP": "46", "MESH_GROUP": "VOICE", "INTERVAL": "1", "BIDIR": True},
              "k2": {"UID_CLIENT": "STARLINK", "UID_SERVER": "LAB_C3", "DESTINATION_ADDRESS": "0.0.0.0",
                     "DSCP": "0", "MESH_GROUP": "LAB", "INTERVAL": "1", "BIDIR": True}}}


def test_targets_are_the_peers_of_the_connectors():
    targets = tw.targets(CONFIG)
    assert targets == [{"peer": "LAB_C1", "me": "STARLINK", "address": "172.30.0.31", "dscp": 46,
                        "mesh_group": "VOICE", "interval": 1.0}]  # adresse inconnue (0.0.0.0) : rien à mesurer


def test_points_are_tagged_like_a_flow_measured_here():
    p = tw.point(tw.targets(CONFIG)[0], {"RTT_MS": 20.0, "LOSS_PCT": 0.0}, 1795400000)
    assert p["measurement"] == "SYNTRAF_LATENCY"
    assert p["tags"] == {"MESH_GROUP": "VOICE", "CLIENT": "LAB_C1", "SERVER": "STARLINK",
                         "UID": "LAB_C1__TO__STARLINK__ON__DSCP46"}


def test_the_server_accepts_latency_points_from_the_probe_that_measured_them():
    from lib import st_channel_guard as guard
    p = tw.point(tw.targets(CONFIG)[0], {"RTT_MS": 20.0, "LOSS_PCT": 0.0}, 1795400000)
    assert guard.authorized_points([p], "STARLINK") == ([p], 0)
    assert guard.authorized_points([p], "LAB_C1") == ([], 1)


def test_a_real_echo_on_the_loopback():
    reflector = tw.Reflector(0, host="127.0.0.1")
    reflector.start()
    try:
        target = {"peer": "B", "me": "A", "address": "127.0.0.1", "dscp": 46, "mesh_group": "G", "interval": 0.5}
        fields = tw.measure_once(target, reflector.port, count=5)
        assert fields["LOSS_PCT"] == 0 and 0 <= fields["RTT_MIN_MS"] <= fields["RTT_MS"] < 50
    finally:
        reflector.stop()


def test_a_silent_peer_is_100_percent_echo_loss():
    target = {"peer": "B", "me": "A", "address": "127.0.0.1", "dscp": 0, "mesh_group": "G", "interval": 0.3}
    t0 = time.monotonic()
    assert tw.measure_once(target, 9, count=3, timeout=0.3) == {"LOSS_PCT": 100.0}  # port 9 (discard) : muet
    assert time.monotonic() - t0 < 2


# ----------------------------------------------------------------------------------------- MOS et latence

def test_the_mos_uses_the_latest_round_trip_time_of_the_pair():
    from lib import st_quality as q
    q.LATENCY.clear()
    flow = lambda: [{"measurement": "SYNTRAF", "tags": {"MESH_GROUP": "G", "CLIENT": "LAB_C1", "SERVER": "STARLINK"},  # noqa: E731
                     "fields": {"RX_PCT_LOSS": 0.0, "RX_JITTER": 2.0}}]
    without = q.enrich(flow(), {})[0]["fields"]["RX_MOS"]
    latency = {"measurement": "SYNTRAF_LATENCY", "tags": {"CLIENT": "STARLINK", "SERVER": "LAB_C1"},
               "fields": {"RTT_MS": 600.0, "LOSS_PCT": 0.0}}
    q.enrich([latency], {})
    pts = q.enrich(flow(), {})
    assert pts[0]["fields"]["RX_MOS"] < without and pts[0]["fields"]["RX_LATENCY_MS"] == 300.0
    q.LATENCY.clear()


# ------------------------------------------------------------------------------------- sécurité du réflecteur

def test_the_reflector_limits_each_source_and_the_total():
    lim = tw.RateLimiter(per_source=20, total=50)
    now = 1000.0
    assert sum(lim.allow("10.0.0.1", now) for _ in range(100)) == 20  # rafale bornée par source
    assert sum(lim.allow(f"10.0.1.{i}", now) for i in range(100)) == 30  # puis par le total (50)
    assert lim.allow("10.0.0.1", now + 1.0)  # la seconde suivante, à nouveau permis


def test_the_reflector_ignores_malformed_or_oversized_packets():
    assert not tw.acceptable(b"short")
    assert not tw.acceptable(b"\0" * 2000)
    assert tw.acceptable(tw.sender_packet(1, 0.0))


def test_a_flood_from_one_source_gets_few_answers():
    import socket as so
    reflector = tw.Reflector(0, host="127.0.0.1")
    reflector.start()
    s = so.socket(so.AF_INET, so.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        for i in range(300):
            s.sendto(tw.sender_packet(i, 0.0), ("127.0.0.1", reflector.port))
        answers = 0
        try:
            while True:
                s.recvfrom(2048)
                answers += 1
        except so.timeout:
            pass
        assert answers <= tw.RateLimiter().per_source + 5
    finally:
        s.close()
        reflector.stop()


def test_the_reflector_only_answers_known_peers():
    reflector = tw.Reflector(0, host="127.0.0.1")
    reflector.start()
    try:
        target = {"peer": "B", "me": "A", "address": "127.0.0.1", "dscp": 0, "mesh_group": "G", "interval": 0.3}
        reflector.set_allowed({"10.9.9.9"})
        assert tw.measure_once(target, reflector.port, count=3, timeout=0.3) == {"LOSS_PCT": 100.0}
        reflector.set_allowed({"127.0.0.1"})
        assert tw.measure_once(target, reflector.port, count=3, timeout=0.5)["LOSS_PCT"] == 0
    finally:
        reflector.stop()


def test_peers_are_the_connectors_and_the_sources_of_accepted_iperf3_sessions():
    tw.LEARNED.clear()
    tw.learn_from_iperf3("'2026-11-23 00:31:28 'Accepted connection from 172.30.0.35, port 56858")
    tw.learn_from_iperf3("'2026-11-23 00:31:28 '[  5] local 172.30.0.32 port 15910 connected to 172.30.0.35 port 38733")
    assert tw.allowed_peers(CONFIG) == {"172.30.0.31", "172.30.0.35"}
    tw.LEARNED.clear()

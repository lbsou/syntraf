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
    reflector = tw.Reflector(0, host="127.0.0.1", allowed=None)
    reflector.start()
    try:
        target = {"peer": "B", "me": "A", "address": "127.0.0.1", "dscp": 46, "mesh_group": "G", "interval": 0.5}
        fields = tw.measure_once(target, reflector.port, count=5)
        assert fields["LOSS_PCT"] == 0 and 0 <= fields["RTT_MIN_MS"] <= fields["RTT_MS"] < 50
    finally:
        reflector.stop()


def test_the_reply_is_never_larger_than_the_request():
    """Aucune amplification, même avec une requête minimale et le champ DSCP rapporté."""
    assert not tw.acceptable(b"\x00" * 14)  # l'en-tête seul : la réponse ferait 41 octets ou plus
    for size in range(0, 1600, 1):
        pkt = tw.sender_packet(1, time.time(), dscp=46).ljust(size, b"\x00")[:max(size, 14)]
        if tw.acceptable(pkt):
            assert len(tw.reflect(pkt, time.time(), time.time(), 1, received_tos=0xB8)) <= len(pkt), size


def _probe(port, payload=None):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.5)
        s.sendto(payload or tw.sender_packet(1, time.time()), ("127.0.0.1", port))
        try:
            return s.recv(2048)
        except OSError:
            return None


def test_the_reflector_answers_nobody_until_its_peers_are_known():
    closed = tw.Reflector(0, host="127.0.0.1").start()
    peers = tw.Reflector(0, host="127.0.0.1", allowed={"127.0.0.1"}).start()
    try:
        assert _probe(closed.port) is None
        assert _probe(peers.port) is not None
        closed.set_allowed({"127.0.0.1"})
        assert _probe(closed.port) is not None
    finally:
        closed.stop()
        peers.stop()


def test_replies_from_another_address_are_ignored():
    """L'émetteur n'accepte que les réponses du réflecteur visé : une réponse forgée depuis un autre port ne compte pas."""
    import socket
    import threading
    listen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen.bind(("127.0.0.1", 0))
    listen.settimeout(0.2)
    forger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stop = threading.Event()

    def answer_from_elsewhere():
        while not stop.is_set():
            try:
                data, addr = listen.recvfrom(2048)
            except OSError:
                continue
            forger.sendto(tw.reflect(data, time.time(), time.time(), 1), addr)
    t = threading.Thread(target=answer_from_elsewhere, daemon=True)
    t.start()
    try:
        target = {"peer": "B", "me": "A", "address": "127.0.0.1", "dscp": 0, "mesh_group": "G", "interval": 0.3}
        assert tw.measure_once(target, listen.getsockname()[1], count=3, timeout=0.3) == {"LOSS_PCT": 100.0}
    finally:
        stop.set()
        t.join(1)
        listen.close()
        forger.close()


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
    reflector = tw.Reflector(0, host="127.0.0.1", allowed=None)
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
    reflector = tw.Reflector(0, host="127.0.0.1", allowed=None)
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


# ------------------------------------------------------------------------- réordonnancement et doublons

def reply(sender_seq, reflector_seq):
    return {"sender_seq": sender_seq, "seq": reflector_seq}


def test_in_order_echoes_have_no_reordering():
    r = [reply(i, 100 + i) for i in range(10)]
    assert tw.order_stats(r, sent=10) == {"REORDER_FWD_PCT": 0.0, "REORDER_REV_PCT": 0.0, "DUP_FWD": 0, "DUP_REV": 0}


def test_forward_reordering_is_seen_in_the_reflector_arrival_order():
    # le réflecteur a reçu 0 1 3 2 4 (numérotés 100..104 dans cet ordre), réponses revenues dans l'ordre
    r = [reply(0, 100), reply(1, 101), reply(3, 102), reply(2, 103), reply(4, 104)]
    m = tw.order_stats(r, sent=5)
    assert m["REORDER_FWD_PCT"] == 20.0 and m["REORDER_REV_PCT"] == 0.0


def test_reverse_reordering_is_seen_in_our_arrival_order():
    r = [reply(0, 100), reply(2, 102), reply(1, 101), reply(3, 103)]
    m = tw.order_stats(r, sent=4)
    assert m["REORDER_REV_PCT"] == 25.0 and m["REORDER_FWD_PCT"] == 0.0


def test_duplicates_in_each_direction():
    fwd_dup = [reply(0, 100), reply(1, 101), reply(1, 102), reply(2, 103)]  # le réflecteur a reçu 1 deux fois
    rev_dup = [reply(0, 100), reply(1, 101), reply(1, 101), reply(2, 102)]  # nous avons reçu sa réponse 101 deux fois
    assert tw.order_stats(fwd_dup, sent=3)["DUP_FWD"] == 1 and tw.order_stats(fwd_dup, sent=3)["DUP_REV"] == 0
    assert tw.order_stats(rev_dup, sent=3)["DUP_REV"] == 1 and tw.order_stats(rev_dup, sent=3)["DUP_FWD"] == 0


def test_a_measurement_reports_order_and_duplicates():
    reflector = tw.Reflector(0, host="127.0.0.1", allowed=None)
    reflector.start()
    try:
        target = {"peer": "B", "me": "A", "address": "127.0.0.1", "dscp": 46, "mesh_group": "G", "interval": 1}
        f = tw.measure_once(target, reflector.port)
        assert f["LOSS_PCT"] == 0 and f["REORDER_FWD_PCT"] == 0 and f["DUP_REV"] == 0
    finally:
        reflector.stop()


def test_the_echo_train_is_voice_like():
    assert tw.COUNT == 10 and tw.TRAIN_SPACING_S == 0.02 and tw.RateLimiter().per_source >= 2 * tw.COUNT


# -------------------------------------------------------------- marquage DSCP (à la manière de la RFC 7750)

def test_the_sender_says_which_dscp_it_wants_and_the_reflector_reports_the_one_it_received():
    pkt = tw.sender_packet(7, 1795400000.5, dscp=46)
    assert tw.parse_sender(pkt)["dscp"] == 46
    assert tw.parse_sender(tw.sender_packet(7, 0.0))["dscp"] is None  # ancienne sonde : rien d'annoncé
    reply = tw.reflect(pkt, 1.0, 1.0, 3, received_tos=(0 << 2) | 1)  # réécrit en 0, ECN conservé
    assert tw.parse_reply(reply)["received_dscp"] == 0
    assert tw.parse_reply(tw.reflect(pkt, 1.0, 1.0, 3))["received_dscp"] is None  # réflecteur sans IP_RECVTOS
    assert len(reply) <= tw.PACKET_SIZE


def test_the_reply_carries_the_wanted_dscp_so_the_return_trip_is_checked_on_its_own():
    """Le réflecteur répond avec le DSCP voulu par l'émetteur, pas celui reçu : une réécriture à l'aller ne doit pas
    se répercuter (et se cacher) sur le retour."""
    assert tw.reply_tos(tw.parse_sender(tw.sender_packet(1, 0.0, dscp=46)), received_tos=0) == 46 << 2
    assert tw.reply_tos(tw.parse_sender(tw.sender_packet(1, 0.0)), received_tos=34 << 2) == 34 << 2  # ancien émetteur


def test_dscp_statistics_per_direction():
    f = tw.dscp_stats(46, forward=[46, 46, 0, 0], reverse=[46, 46, 46, 46])
    assert f == {"DSCP_SENT": 46, "DSCP_OK_PCT_FWD": 50.0, "DSCP_RECV_FWD": 0, "DSCP_OK_PCT_REV": 100.0,
                 "DSCP_RECV_REV": 46}
    assert tw.dscp_stats(46, forward=[], reverse=[]) == {"DSCP_SENT": 46}  # rien de mesurable (Windows, ancienne sonde)


@pytest.mark.skipif(not hasattr(__import__("socket").socket, "recvmsg"), reason="recvmsg absent (Windows)")
def test_a_real_echo_reports_the_dscp_of_both_directions():
    reflector = tw.Reflector(0, host="127.0.0.1", allowed=None)
    reflector.start()
    try:
        target = {"peer": "B", "me": "A", "address": "127.0.0.1", "dscp": 46, "mesh_group": "G", "interval": 1}
        f = tw.measure_once(target, reflector.port)
        assert f["DSCP_OK_PCT_FWD"] == 100.0 and f["DSCP_RECV_FWD"] == 46
        assert f["DSCP_OK_PCT_REV"] == 100.0 and f["DSCP_RECV_REV"] == 46
    finally:
        reflector.stop()

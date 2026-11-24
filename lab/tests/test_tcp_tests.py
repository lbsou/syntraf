"""Tests TCP courts et récurrents (lib/st_tcp_tests.py) : planification, choix des paires (initiateur derrière un NAT),
arguments d'iperf3, lecture du résultat JSON (sortie réelle capturée dans le lab), ordonnancement un test à la fois."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_tcp_tests as tt  # noqa: E402

DATA = Path(__file__).parent / "data"


def test_frequencies():
    assert tt.parse_every("15m") == 900 and tt.parse_every("1h") == 3600 and tt.parse_every("2d") == 172800
    assert tt.parse_every("30") == 1800  # sans unité : minutes
    assert tt.parse_every("10s") is None and tt.parse_every("abc") is None  # moins d'une minute : refusé


def test_validation():
    ok = {"UID": "WAN_TCP", "MESH_GROUP": "G", "EVERY": "1h", "DURATION": "10", "DIRECTION": "both",
          "PARALLEL": "4", "WINDOW": "256K", "DSCP": "0", "MODE": "fixed"}
    assert tt.field_errors(ok, mesh_groups={"G"}) == {}
    bad = dict(ok, MESH_GROUP="X", EVERY="5s", DURATION="600", DIRECTION="sideways", PARALLEL="99", WINDOW="huge",
               MODE="turbo", CONGESTION="bad cc!", MSS="20")
    assert set(tt.field_errors(bad, mesh_groups={"G"})) == {"MESH_GROUP", "EVERY", "DURATION", "DIRECTION",
                                                            "PARALLEL", "WINDOW", "MODE", "CONGESTION", "MSS"}


FLOWS = [{"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B"}, {"MESH_GROUP": "G", "CLIENT": "B", "SERVER": "A"},
         {"MESH_GROUP": "G", "CLIENT": "NAT1", "SERVER": "A"}, {"MESH_GROUP": "G", "CLIENT": "NAT1", "SERVER": "NAT2"},
         {"MESH_GROUP": "H", "CLIENT": "A", "SERVER": "C"}]
PROBES = {"A": {"address": "10.0.0.1", "nat": False}, "B": {"address": "10.0.0.2", "nat": False},
          "NAT1": {"address": "198.51.100.7", "nat": True}, "NAT2": {"address": "203.0.113.9", "nat": True}}


def test_pairs_put_the_probe_behind_a_nat_on_the_initiating_side():
    pairs = tt.pairs(FLOWS, "G", PROBES)
    assert ("A", "B", "10.0.0.2") in pairs  # deux joignables : un seul test par paire
    assert ("NAT1", "A", "10.0.0.1") in pairs  # le côté NAT initie
    assert not any({"NAT1", "NAT2"} == {p[0], p[1]} for p in pairs)  # deux NAT : impossible
    assert len(pairs) == 2


def test_iperf3_arguments():
    test = {"DURATION": "10", "OMIT": "1", "PARALLEL": "4", "WINDOW": "256K", "MSS": "1400", "CONGESTION": "bbr",
            "DSCP": "46"}
    args = tt.client_args("iperf3", test, "10.0.0.2", 5201, "download", [])
    assert args[:3] == ["iperf3", "-c", "10.0.0.2"]
    for a in (["-t", "10"], ["-O", "1"], ["-P", "4"], ["-w", "256K"], ["-M", "1400"], ["-C", "bbr"], ["-p", "5201"]):
        assert args[args.index(a[0]):args.index(a[0]) + 2] == a
    assert "-R" in args and "-J" in args and "--dscp" in args and "-u" not in args
    assert "-R" not in tt.client_args("iperf3", test, "10.0.0.2", 5201, "upload", [])
    srv = tt.server_args("iperf3", 5201, 40, ["--rsa-private-key-path", "k"])
    # pas de --one-off : l'initiateur peut relancer sans -w si le pair refuse la fenêtre (le serveur est arrêté à la
    # fin de la plage du test)
    assert srv[:2] == ["iperf3", "-s"] and "--one-off" not in srv and "--rsa-private-key-path" in srv


def test_the_json_result_of_a_real_test():
    f = tt.parse_result((DATA / "iperf3_tcp_result.json").read_text(encoding="utf-8"))
    assert f["BITRATE_MBPS"] == pytest.approx(24653.8, abs=1) and f["RETRANSMITS"] == 0
    assert f["RTT_MS"] == pytest.approx(0.087, abs=0.01) and f["CWND_MAX_KB"] > 0 and f["STREAMS"] == 2
    assert f["FAILED"] == 0


def test_a_failed_test_is_recorded_as_failed():
    f = tt.parse_result(json.dumps({"start": {}, "intervals": [], "end": {},
                                    "error": "unable to connect to server: Connection refused"}))
    assert f["FAILED"] == 1 and "BITRATE_MBPS" not in f and "connect" in tt.result_error(
        json.dumps({"error": "unable to connect to server: Connection refused"}))


def test_the_result_point_is_reported_by_the_initiator():
    p = tt.point({"UID": "WAN_TCP", "MESH_GROUP": "G"}, "NAT1", "A", "download", {"BITRATE_MBPS": 50.0}, 1795400000)
    assert p["measurement"] == "SYNTRAF_TCP" and p["tags"]["SERVER"] == "NAT1" and p["tags"]["CLIENT"] == "A"
    assert p["tags"]["DIRECTION"] == "download" and p["tags"]["TEST"] == "WAN_TCP"


# ------------------------------------------------------------------------------------------ ordonnancement

TESTS = [{"UID": "T1", "MESH_GROUP": "G", "EVERY": "1h", "DURATION": "10", "DIRECTION": "both", "ENABLED": True}]


def test_the_scheduler_runs_one_test_at_a_time_and_respects_the_frequency():
    s = tt.Scheduler(start_delay_s=10)
    jobs = s.tick(1000.0, TESTS, lambda t: [("A", "B", "10.0.0.2")])
    assert jobs == []  # premier passage : première échéance dans une période, pas d'avalanche au démarrage
    s.run_now("T1")
    first = s.tick(1001.0, TESTS, lambda t: [("A", "B", "10.0.0.2")])
    assert len(first) == 1 and first[0]["direction"] == "upload" and first[0]["start_at"] == 1011.0
    assert s.tick(1005.0, TESTS, lambda t: [("A", "B", "10.0.0.2")]) == []  # le premier n'est pas fini
    second = s.tick(1001.0 + first[0]["slot_s"] + 1, TESTS, lambda t: [("A", "B", "10.0.0.2")])
    assert len(second) == 1 and second[0]["direction"] == "download"
    later = 1001.0 + 2 * first[0]["slot_s"] + 2
    assert s.tick(later, TESTS, lambda t: [("A", "B", "10.0.0.2")]) == []  # rien avant la prochaine heure
    assert len(s.tick(1000.0 + 3600 + 1, TESTS, lambda t: [("A", "B", "10.0.0.2")])) == 1


def test_a_disabled_test_never_runs():
    s = tt.Scheduler()
    s.run_now("T1")
    assert s.tick(1000.0, [dict(TESTS[0], ENABLED=False)], lambda t: [("A", "B", "10.0.0.2")]) == []


def test_jobs_become_commands_for_both_probes():
    commands = {}
    job = {"test": dict(TESTS[0], DSCP="0"), "initiator": "A", "responder": "B", "address": "10.0.0.2",
           "direction": "upload", "start_at": 2000.0, "slot_s": 40, "run_id": "r1"}
    tt.dispatch(job, commands, port=5201)
    assert commands["B"][0]["ACTION"] == "TCP_TEST" and commands["B"][0]["ROLE"] == "server"
    assert commands["A"][0]["ROLE"] == "client" and commands["A"][0]["ADDRESS"] == "10.0.0.2"
    assert commands["A"][0]["PORT"] == 5201 and commands["A"][0]["START_AT"] > commands["B"][0]["START_AT"]


# ------------------------------------------------------------------- mode auto (principe d'AMPR-NG : BDP × facteur)

def test_auto_window_is_the_bandwidth_delay_product_times_the_factor():
    # 100 Mbit/s × 0.95, RTT 40 ms : BDP = 95e6 × 0.040 / 8 = 475 000 octets ; × 2 = 950 000
    p = tt.auto_params(capacity_bps=100e6, rtt_ms=40.0, factor=2.0, pacing=False)
    assert p["WINDOW"] == "950000" and p["BANDWIDTH"] == "95M" and "PACING_US" not in p
    assert tt.auto_params(100e6, 40.0, factor=1.0)["WINDOW"] == "475000"


def test_auto_pacing_spaces_segments_at_the_link_rate():
    p = tt.auto_params(capacity_bps=100e6, rtt_ms=40.0, factor=2.0, pacing=True, mss=1460)
    assert p["PACING_US"] == 122  # 1460 × 8 / 95 Mbit/s ≈ 122.9 µs


def test_auto_without_capacity_or_rtt_leaves_tcp_to_the_os():
    assert tt.auto_params(None, 40.0) == {} and tt.auto_params(100e6, None) == {}


def test_auto_capacity_comes_from_the_test_or_the_smallest_declared_maximum():
    assert tt.capacity_bps({"BANDWIDTH": "200M"}, "10M", "50M") == 200e6
    assert tt.capacity_bps({}, "10M", "50M") == 10e6
    assert tt.capacity_bps({}, "", None) is None


def test_auto_parameters_go_into_the_client_command():
    commands = {}
    job = {"test": dict(TESTS[0], MODE="auto", DSCP="0"), "initiator": "A", "responder": "B", "address": "10.0.0.2",
           "direction": "upload", "start_at": 2000.0, "slot_s": 40, "run_id": "r1",
           "auto": {"WINDOW": "950000", "BANDWIDTH": "95M"}}
    tt.dispatch(job, commands, port=5201)
    args = tt.client_args("iperf3", commands["A"][0]["TEST"], "10.0.0.2", 5201, "upload", [])
    assert args[args.index("-w") + 1] == "950000" and args[args.index("-b") + 1] == "95M"


def test_the_probe_checks_every_command_before_running_iperf3():
    good_client = {"ROLE": "client", "ADDRESS": "10.0.0.2", "PORT": 5201, "START_AT": 2000.0, "DIRECTION": "upload",
                   "PEER": "LAB_C2", "RUN_ID": "abc123",
                   "TEST": {"UID": "WAN_TCP", "MESH_GROUP": "G", "EVERY": "1h", "DURATION": "5", "PARALLEL": "2",
                            "WINDOW": "950000", "BANDWIDTH": "95M", "PACING_US": 122}}
    good_server = {"ROLE": "server", "PORT": 5201, "START_AT": 1997.0, "IDLE_S": 40, "RUN_ID": "abc123"}
    assert tt.command_problem(good_client) is None and tt.command_problem(good_server) is None
    for bad in (dict(good_client, ROLE="shell"), dict(good_client, PORT=80000), dict(good_client, ADDRESS="-oFoo"),
                dict(good_client, DIRECTION="sideways"), dict(good_server, IDLE_S=100000),
                dict(good_client, TEST=dict(good_client["TEST"], WINDOW="--logfile=/etc/x")),
                dict(good_client, TEST=dict(good_client["TEST"], PACING_US="-1"))):
        assert tt.command_problem(bad), bad


def test_in_download_the_round_trip_and_window_come_from_the_remote_sender():
    """-R : c'est le pair qui envoie ; son RTT et sa fenêtre arrivent par --get-server-output (serveur en -J)."""
    f = tt.parse_result((DATA / "iperf3_tcp_reverse_result.json").read_text(encoding="utf-8"))
    assert f["FAILED"] == 0 and f["RTT_MS"] == pytest.approx(0.103, abs=0.01) and f["CWND_MAX_KB"] > 0
    args = tt.client_args("iperf3", {"DURATION": "5"}, "10.0.0.2", 5201, "download", [])
    assert "--get-server-output" in args and "--get-server-output" not in tt.client_args(
        "iperf3", {"DURATION": "5"}, "10.0.0.2", 5201, "upload", [])
    assert "-J" in tt.server_args("iperf3", 5201, 40, [])


def test_a_window_above_the_os_limit_is_left_to_tcp_autotuning():
    """Linux refuse un -w au-delà de net.core.wmem_max/rmem_max (« socket buffer size not set correctly ») ; fixer la
    fenêtre sous ce plafond serait pire que l'autoréglage (jusqu'à tcp_rmem max) : on n'impose rien et on le signale."""
    test = {"WINDOW": "780000", "BANDWIDTH": "47M"}
    kept, limited = tt.window_within(test, os_max=212992)
    assert "WINDOW" not in kept and kept["BANDWIDTH"] == "47M" and limited
    kept, limited = tt.window_within(test, os_max=4194304)
    assert kept["WINDOW"] == "780000" and not limited
    assert tt.window_within(test, os_max=None) == (test, False)  # plafond inconnu (Windows, macOS) : tel quel
    assert tt.refused_window("socket buffer size not set correctly") and not tt.refused_window("Connection refused")


def test_a_responder_is_stopped_before_the_next_test_opens_the_same_port():
    s = tt.Scheduler(start_delay_s=10)
    tests = [dict(TESTS[0], DIRECTION="upload")]
    pairs = lambda t: [("A", "B", "10.0.0.2"), ("C", "B", "10.0.0.2")]  # noqa: E731 - même répondeur
    s.run_now("T1")
    first = s.tick(1000.0, tests, pairs)[0]
    second = s.tick(1000.0 + first["slot_s"], tests, pairs)[0]
    c1, c2 = {}, {}
    tt.dispatch(first, c1)
    tt.dispatch(second, c2)
    end_first = c1["B"][0]["START_AT"] + c1["B"][0]["IDLE_S"]
    assert end_first < c2["B"][0]["START_AT"]
    assert c1["B"][0]["IDLE_S"] >= int(TESTS[0]["DURATION"]) + 1 + 8  # de quoi relancer une fois sans -w


def test_a_responder_not_listening_yet_gets_a_second_chance():
    assert tt.responder_not_ready("unable to connect to server - server may have stopped running or use a "
                                  "different port, firewall issue, etc.: Connection refused")
    assert not tt.responder_not_ready("unable to connect to server: Connection timed out")
    assert not tt.responder_not_ready("")


class FakeVm:
    def __init__(self):
        lab = {"MESH_GROUP": "G", "TEST": "T1", "DIRECTION": "upload", "SERVER": "NAT1", "CLIENT": "A"}
        self.series = {"tlast_over_time(SYNTRAF_TCP_FAILED[7d])": [{"metric": lab, "value": [0, "1795400000"]}],
                       "last_over_time(SYNTRAF_TCP_FAILED[7d])": [{"metric": lab, "value": [0, "0"]}],
                       "last_over_time(SYNTRAF_TCP_BITRATE_MBPS[7d])": [{"metric": lab, "value": [0, "2.05"]}],
                       "tlast_over_time(SYNTRAF_TCP_BITRATE_MBPS[7d])": [{"metric": lab, "value": [0, "1795400000"]}],
                       # fenêtre d'un test plus ancien : ne doit pas se mêler au dernier
                       "last_over_time(SYNTRAF_TCP_WINDOW_BYTES[7d])": [{"metric": lab, "value": [0, "812487"]}],
                       "tlast_over_time(SYNTRAF_TCP_WINDOW_BYTES[7d])": [{"metric": lab, "value": [0, "1795399000"]}]}

    def query(self, q):
        return self.series.get(q, [])


def test_after_a_server_restart_the_latest_results_come_from_the_database():
    rows = tt.results_from_vm(FakeVm())
    assert len(rows) == 1
    r = rows[0]
    assert (r["server"], r["client"], r["direction"], r["test"]) == ("NAT1", "A", "upload", "T1")
    assert r["BITRATE_MBPS"] == 2.05 and r["FAILED"] == 0 and r["time"].startswith("2026-11-23")
    assert "WINDOW_BYTES" not in r  # valeur d'un autre test

"""Chemin réseau (traceroute façon MTR) : à la demande et à l'ouverture d'une alerte (lib/st_paths.py)."""
import datetime as dt
import json
import socket
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_paths as sp  # noqa: E402


# ------------------------------------------------------------------------------------------------ sonde

def errqueue(origin, icmp_type, code, offender):
    return (struct.pack("=IBBBBII", 113, origin, icmp_type, code, 0, 0, 0)
            + struct.pack("=HH4s8x", socket.AF_INET, 0, socket.inet_aton(offender)))


def test_an_icmp_time_exceeded_names_the_router_of_that_hop():
    assert sp.parse_errqueue([(0, 11, errqueue(2, 11, 0, "10.20.0.1"))]) == ("hop", "10.20.0.1")


def test_port_unreachable_from_the_target_means_the_destination_answered():
    assert sp.parse_errqueue([(0, 11, errqueue(2, 3, 3, "10.0.0.5"))]) == ("dest", "10.0.0.5")


def test_other_unreachable_codes_stop_the_path():
    assert sp.parse_errqueue([(0, 11, errqueue(2, 3, 1, "10.9.9.9"))]) == ("unreach", "10.9.9.9")
    assert sp.parse_errqueue([]) is None


def test_aggregate_reports_loss_and_round_trip_per_hop_like_mtr():
    samples = [(1, "192.168.1.1", 1.0, "hop"), (1, "192.168.1.1", 3.0, "hop"), (1, None, None, None),
               (2, None, None, None), (2, None, None, None), (2, None, None, None),
               (3, "10.0.0.5", 12.0, "dest"), (3, "10.0.0.5", 14.0, "dest"), (3, "10.0.0.5", 13.0, "dest"),
               (4, None, None, None)]  # au-delà de la destination : ignoré
    hops, reached = sp.aggregate(samples)
    assert reached is True
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[0] == {"hop": 1, "address": "192.168.1.1", "sent": 3, "received": 2, "loss_pct": 33.3,
                       "rtt_avg": 2.0, "rtt_min": 1.0, "rtt_max": 3.0, "others": []}
    assert hops[1]["address"] is None and hops[1]["loss_pct"] == 100.0 and hops[1]["rtt_avg"] is None
    assert hops[2]["address"] == "10.0.0.5" and hops[2]["loss_pct"] == 0.0


def test_aggregate_trims_the_silent_tail_when_the_destination_never_answers():
    samples = [(1, "192.168.1.1", 1.0, "hop"), (2, "10.20.0.1", 5.0, "hop")] + \
              [(t, None, None, None) for t in range(3, 31)]
    hops, reached = sp.aggregate(samples)
    assert reached is False and [h["hop"] for h in hops] == [1, 2, 3]  # un saut muet montre où ça s'arrête


TRACERT_FR = """
Détermination de l'itinéraire vers 10.0.0.5 avec un maximum de 30 sauts.

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     8 ms     7 ms     9 ms  10.20.0.1
  3     *        *        *     Délai d'attente de la demande dépassé.
  4    12 ms     *       14 ms  10.0.0.5

Itinéraire déterminé.
"""


def test_windows_tracert_is_read_whatever_its_language():
    samples = sp.parse_tracert(TRACERT_FR, "10.0.0.5")
    hops, reached = sp.aggregate(samples)
    assert reached is True and [h["address"] for h in hops] == ["192.168.1.1", "10.20.0.1", None, "10.0.0.5"]
    assert hops[0]["rtt_avg"] == 0.5 and hops[3]["loss_pct"] == 33.3


MAC_TRACEROUTE = """traceroute to 10.0.0.5 (10.0.0.5), 30 hops max, 52 byte packets
 1  192.168.1.1  1.234 ms  0.987 ms  1.100 ms
 2  * * *
 3  10.0.0.9  5.1 ms 10.0.0.8  6.0 ms *
 4  10.0.0.5  12.0 ms  11.0 ms  13.0 ms
"""


def test_bsd_traceroute_with_several_responders_on_one_hop():
    hops, reached = sp.aggregate(sp.parse_traceroute(MAC_TRACEROUTE, "10.0.0.5"))
    assert reached is True
    assert hops[2]["address"] in ("10.0.0.9", "10.0.0.8") and len(hops[2]["others"]) == 1
    assert hops[2]["received"] == 2 and hops[2]["sent"] == 3


def test_a_probe_refuses_a_trace_command_it_cannot_run_safely():
    ok = {"ID": "p1", "ADDRESS": "10.0.0.5", "PEER": "B", "ROUNDS": 3, "MAX_HOPS": 30}
    assert sp.command_problem(ok) is None
    assert sp.command_problem(dict(ok, ADDRESS="-x; rm -rf /")) == "bad address"
    assert sp.command_problem(dict(ok, MAX_HOPS=500)) == "bad max hops"
    assert sp.command_problem(dict(ok, ROUNDS=0)) == "bad rounds"
    assert sp.command_problem(dict(ok, ID="")) == "bad id"


def test_the_result_travels_as_a_point_reported_by_the_probe():
    p = sp.point("A", {"ID": "p1", "PEER": "B", "ADDRESS": "10.0.0.5"},
                 {"tool": "native", "reached": True, "hops": [{"hop": 1}], "error": None}, 1000)
    assert p["measurement"] == "SYNTRAF_PATH" and p["tags"] == {"SERVER": "A", "CLIENT": "B", "TRACE_ID": "p1"}
    assert json.loads(p["fields"]["RESULT"])["hops"] == [{"hop": 1}]


# ----------------------------------------------------------------------------------------------- serveur

def clients(**status):
    return {uid: SimpleNamespace(status=s, ip_address=f"10.0.0.{i + 1}") for i, (uid, s) in enumerate(status.items())}


def test_an_opened_alert_traces_both_directions_once_per_cooldown(tmp_path):
    store = sp.PathStore(tmp_path / "paths.json")
    info = {"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B", "METRIC": "loss"}
    assert len(sp.on_alert_open(info, 1000, store)) == 2
    assert [(r["source"], r["destination"], r["reason"]) for r in store.list()] == \
        [("B", "A", "alert"), ("A", "B", "alert")]
    assert sp.on_alert_open(dict(info, METRIC="jitter"), 1100, store) == []        # même paire, trop tôt
    assert len(sp.on_alert_open(info, 1000 + sp.AUTO_COOLDOWN_S + 1, store)) == 2   # délai passé


def test_tick_sends_the_trace_to_the_source_probe_with_the_destination_address(tmp_path):
    store = sp.PathStore(tmp_path / "paths.json")
    rid = store.request("A", "B", "manual", now=1000)["id"]
    store.request("C", "B", "manual", now=1000)
    commands = {}
    sp.tick(clients(A="CONNECTED", B="CONNECTED", C="DISCONNECTED"), {}, commands, store, now=1001)
    assert commands == {"A": [{"ACTION": "PATH_TRACE", "ID": rid, "ADDRESS": "10.0.0.2", "PEER": "B",
                               "ROUNDS": sp.ROUNDS, "MAX_HOPS": sp.MAX_HOPS}]}
    by = {r["source"]: r for r in store.list()}
    assert by["A"]["status"] == "running" and by["C"]["status"] == "failed"
    assert "not connected" in by["C"]["error"]


def test_a_destination_that_is_down_is_still_traced_at_its_declared_address(tmp_path):
    store = sp.PathStore(tmp_path / "paths.json")
    store.request("A", "B", "alert", now=1000)
    commands = {}
    cl = clients(A="CONNECTED")
    sp.tick(cl, {"B": {"IP_ADDRESS": "192.0.2.7"}}, commands, store, now=1001)
    assert commands["A"][0]["ADDRESS"] == "192.0.2.7"


def test_receive_files_the_result_and_keeps_a_numeric_summary_for_the_database(tmp_path):
    store = sp.PathStore(tmp_path / "paths.json")
    rid = store.request("A", "B", "alert", now=1000, alert={"METRIC": "loss", "MESH_GROUP": "G"})["id"]
    result = {"tool": "native", "reached": True, "error": None,
              "hops": [{"hop": 1, "address": "10.0.0.254", "rtt_avg": 1.0, "loss_pct": 0.0},
                       {"hop": 2, "address": "10.0.0.2", "rtt_avg": 4.5, "loss_pct": 0.0}]}
    payload = [{"measurement": "SYNTRAF", "tags": {"SERVER": "A"}, "fields": {"X": 1}},
               sp.point("A", {"ID": rid, "PEER": "B"}, result, 1005)]
    kept = sp.receive(payload, store, reporter="A")
    assert kept[0]["measurement"] == "SYNTRAF"
    summary = kept[1]
    assert summary["measurement"] == "SYNTRAF_PATH" and "RESULT" not in summary["fields"]
    assert summary["fields"] == {"HOP_COUNT": 2, "REACHED": 1, "RTT_MS": 4.5}
    assert summary["tags"] == {"SOURCE": "A", "DESTINATION": "B", "REASON": "alert"}
    rec = store.get(rid)
    assert rec["status"] == "done" and rec["hops"][1]["address"] == "10.0.0.2" and rec["reached"] is True
    # Conservé sur disque : un redémarrage du serveur ne perd pas les chemins
    again = sp.PathStore(tmp_path / "paths.json")
    assert again.get(rid)["hops"] == rec["hops"]


def test_a_probe_cannot_file_a_trace_it_was_not_asked_for(tmp_path):
    store = sp.PathStore(tmp_path / "paths.json")
    rid = store.request("A", "B", "manual", now=1000)["id"]
    forged = sp.point("C", {"ID": rid, "PEER": "B"}, {"tool": "x", "reached": False, "hops": []}, 1001)
    sp.receive([forged], store, reporter="C")
    assert store.get(rid)["status"] == "pending"


def test_the_store_keeps_the_most_recent_traces(tmp_path):
    store = sp.PathStore(tmp_path / "paths.json", keep=3)
    for i in range(5):
        store.request("A", "B", "manual", now=1000 + i)
    assert len(store.list()) == 3 and store.list()[0]["requested_at"] == 1004


def test_list_filters_by_pair_in_either_direction(tmp_path):
    store = sp.PathStore(tmp_path / "paths.json")
    store.request("A", "B", "manual", now=1)
    store.request("B", "A", "manual", now=2)
    store.request("A", "C", "manual", now=3)
    assert len(store.list(source="A", destination="B", both=True)) == 2
    assert len(store.list(source="A")) == 2
    assert dt  # (import gardé pour les points)

"""Carte de la topologie en direct (lib/st_live_map.py) : sondes, liens par paire, qualité de chaque sens.
Tourne dans l'image du lab (dépendances de SYNTRAF)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_live_map as lm  # noqa: E402

FLOWS = [{"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B"}, {"MESH_GROUP": "G", "CLIENT": "B", "SERVER": "A"},
         {"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "C"}, {"MESH_GROUP": "H", "CLIENT": "C", "SERVER": "B"}]
CLIENTS = [{"uid": "A", "status": "CONNECTED", "behind_nat": False}, {"uid": "B", "status": "CONNECTED"},
           {"uid": "C", "status": "DISCONNECTED", "behind_nat": True}]
METRICS = {
    "loss": {("A", "B", "G"): 0.0, ("B", "A", "G"): 6.0},
    "jitter": {("A", "B", "G"): 1.5, ("B", "A", "G"): 4.0},
    "mos": {("A", "B", "G"): 4.4, ("B", "A", "G"): 3.7},
    "rtt": {("A", "B"): 40.0},
}


def build(**kw):
    return lm.build(FLOWS, CLIENTS, METRICS, **kw)


def test_nodes_carry_status_and_nat():
    nodes = {n["id"]: n for n in build()["nodes"]}
    assert nodes["A"]["status"] == "CONNECTED" and nodes["C"]["behind_nat"] is True
    assert set(nodes) == {"A", "B", "C"}


def test_one_link_per_pair_with_both_directions():
    links = {tuple(sorted((l["a"], l["b"]))) + (l["mesh_group"],): l for l in build()["links"]}
    ab = links[("A", "B", "G")]
    assert {d["from"] for d in ab["directions"]} == {"A", "B"}
    assert ab["rtt_ms"] == 40.0


def test_a_link_takes_the_worst_direction():
    ab = [l for l in build()["links"] if {l["a"], l["b"]} == {"A", "B"}][0]
    assert ab["loss_pct"] == 6.0 and ab["mos"] == 3.7 and ab["jitter_ms"] == 4.0
    assert ab["grade"]["loss"] == "orange" and ab["grade"]["mos"] == "yellow"


def test_an_expected_flow_without_measurement_is_shown_as_no_data():
    ac = [l for l in build()["links"] if {l["a"], l["b"]} == {"A", "C"}][0]
    assert ac["loss_pct"] is None and ac["grade"]["loss"] == "nodata"


def test_filter_by_mesh_group():
    links = build(mesh_group="H")["links"]
    assert [(l["a"], l["b"]) for l in links] == [("B", "C")] or [(l["a"], l["b"]) for l in links] == [("C", "B")]
    assert {n["id"] for n in build(mesh_group="H")["nodes"]} == {"B", "C"}


def test_grades():
    assert lm.grade("loss", 0.2) == "green" and lm.grade("loss", 25) == "red"
    assert lm.grade("mos", 4.2) == "green" and lm.grade("mos", 2.0) == "red"
    assert lm.grade("rtt", 50) == "green" and lm.grade("rtt", 350) == "red"
    assert lm.grade("rtt", None) == "nodata"


def test_metrics_are_read_from_victoriametrics():
    class FakeVm:
        def query(self, expr):
            if "RX_PCT_LOSS" in expr:
                return [{"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G"}, "value": [0, "2.5"]}]
            if "LATENCY_RTT_MS" in expr:
                return [{"metric": {"CLIENT": "A", "SERVER": "B"}, "value": [0, "33"]}]
            return []

    m = lm.read_metrics(FakeVm())
    assert m["loss"][("A", "B", "G")] == 2.5 and m["rtt"][("A", "B")] == 33.0


def test_victoriametrics_instant_queries():
    pytest.importorskip("toml")
    try:
        from lib.st_vm_admin import VmAdmin
    except (ImportError, SystemExit):
        pytest.skip("dépendances du serveur absentes")
    import json
    calls = []

    def http(method, path, params=None, body=None):
        calls.append((path, params))
        return 200, json.dumps({"status": "success", "data": {"resultType": "vector", "result": [{"value": [0, "1"]}]}})

    assert VmAdmin({"DB_UID": "VM", "DB_SERVER": "h", "DB_PORT": "1"}, http=http).query("up") == [{"value": [0, "1"]}]
    assert calls == [("/api/v1/query", {"query": "up"})]

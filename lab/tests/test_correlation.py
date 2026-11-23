"""Matrice de corrélation des flux (lib/st_correlation.py) : pertes et gigue de chaque paire de flux, sur une fenêtre,
écrites dans la base pour Grafana. Les flux qui perdent ensemble partagent probablement un lien ou un goulot."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_correlation as corr  # noqa: E402


def series(values, start=1000, step=10):
    return {start + i * step: v for i, v in enumerate(values)}


WAVE = [0, 5, 1, 8, 0, 3, 9, 2, 0, 6, 1, 7, 0, 4, 8, 2, 0, 5, 1, 9, 3, 0, 6, 2]


def test_pearson():
    assert corr.pearson([1, 2, 3, 4], [2, 4, 6, 8]) == pytest.approx(1)
    assert corr.pearson([1, 2, 3, 4], [8, 6, 4, 2]) == pytest.approx(-1)
    assert corr.pearson([1, 1, 1, 1], [1, 2, 3, 4]) is None  # série constante : indéfinie


def test_flows_that_lose_together_correlate():
    flows = {"A→B": series(WAVE), "C→B": series([v * 2 + 1 for v in WAVE]),
             "B→A": series(list(reversed(WAVE))), "A→C": series([0] * len(WAVE))}
    result = {(a, b): r for a, b, r in corr.correlate(flows)}
    assert result[("A→B", "C→B")] == pytest.approx(1)
    assert result[("C→B", "A→B")] == pytest.approx(1)  # les deux sens, pour une matrice complète
    assert result[("A→B", "A→B")] == 1  # diagonale
    assert -1 <= result[("A→B", "B→A")] < 0.5
    assert not any("A→C" in pair for pair in result)  # constant (aucune perte) : rien à corréler


def test_only_common_timestamps_count_and_short_series_are_ignored():
    a = series(WAVE * 2)
    b = {t: v for t, v in series([v * 3 for v in WAVE * 2]).items() if t % 20 == 0}  # un point sur deux (24)
    assert {(x, y) for x, y, _ in corr.correlate({"A": a, "B": b})} >= {("A", "B")}
    short = series(WAVE[:corr.MIN_SAMPLES - 1])
    assert not [p for p in corr.correlate({"A": a, "S": short}) if "S" in p[:2]]


def test_beyond_the_limit_the_most_variable_flows_are_kept(monkeypatch):
    monkeypatch.setattr(corr, "MAX_FLOWS", 2)
    flows = {"calm": series([v * 0.01 for v in WAVE]), "wild": series([v * 10 for v in WAVE]),
             "mid": series(WAVE)}
    names = {a for a, _, _ in corr.correlate(flows)}
    assert names == {"wild", "mid"}


def test_query_results_become_named_flows():
    result = [{"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G1"}, "values": [[1000, "1.5"], [1010, "2"]]},
              {"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G2"}, "values": [[1000, "3"]]},
              {"metric": {"CLIENT": "C", "SERVER": "B", "MESH_GROUP": "G1"}, "values": [[1000, "NaN"]]}]
    flows = corr.flows_from_query(result)
    assert flows["A→B · G1"] == {1000: 1.5, 1010: 2.0} and flows["A→B · G2"] == {1000: 3.0}
    assert flows["C→B · G1"] == {}  # NaN écarté


def test_flow_names_stay_short_with_a_single_group():
    result = [{"metric": {"CLIENT": "A", "SERVER": "B", "MESH_GROUP": "G1"}, "values": [[1000, "1"]]}]
    assert list(corr.flows_from_query(result)) == ["A→B"]


def test_points_for_the_database():
    points = corr.points([("A", "B", 0.5)], "LOSS", now=None)
    assert points[0]["measurement"] == "SYNTRAF_CORRELATION"
    assert points[0]["tags"] == {"FLOW_A": "A", "FLOW_B": "B"} and points[0]["fields"] == {"LOSS": 0.5}


def test_the_publisher_reads_victoriametrics_and_writes_both_metrics():
    class FakeVm:
        def __init__(self):
            self.queries = []

        def query_range(self, query, start, end, step):
            self.queries.append(query)
            return [{"metric": {"CLIENT": c, "SERVER": "B", "MESH_GROUP": "G1"},
                     "values": [[1000 + i * 10, str(v * k)] for i, v in enumerate(WAVE)]}
                    for c, k in (("A", 1), ("C", 2))]

    written = []
    vm = FakeVm()
    n = corr.publish(vm, lambda pts: written.extend(pts), now=2000)
    assert any("SYNTRAF_RX_PCT_LOSS" in q for q in vm.queries) and any("SYNTRAF_RX_JITTER" in q for q in vm.queries)
    assert {k for p in written for k in p["fields"]} == {"LOSS", "JITTER"} and n == len(written)


def test_victoriametrics_range_queries():
    pytest.importorskip("toml")
    try:
        from lib.st_vm_admin import VmAdmin
    except (ImportError, SystemExit):
        pytest.skip("dépendances du serveur absentes")
    import json
    calls = []

    def http(method, path, params=None, body=None):
        calls.append((path, params))
        return 200, json.dumps({"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {}, "values": []}]}})

    vm = VmAdmin({"DB_UID": "VM", "DB_SERVER": "127.0.0.1", "DB_PORT": "8428"}, http=http)
    assert vm.query_range("up", 1, 2, "10s") == [{"metric": {}, "values": []}]
    assert calls == [("/api/v1/query_range", {"query": "up", "start": 1, "end": 2, "step": "10s"})]

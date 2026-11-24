"""Banc d'essai des alertes (lab/bench_alerts.py) : appariement des alertes aux pannes injectées et rapport."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("bench_alerts", Path(__file__).resolve().parents[1] / "bench_alerts.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def test_an_alert_matches_the_fault_by_metric_and_by_the_faulty_node():
    a = {"METRIC": "loss", "CLIENT": "LAB_C2", "SERVER": "LAB_C1"}
    assert bench.matches(a, "LAB_C2", {"loss", "mos"}, "from")
    assert not bench.matches(a, "LAB_C2", {"rtt"}, "from")
    assert not bench.matches(a, "LAB_C1", {"loss"}, "from") and bench.matches(a, "LAB_C1", {"loss"}, "to")


def test_the_report_counts_detections_and_false_alarms():
    results = [{"scenario": "loss", "node": "LAB_C2", "fault": {"loss_pct": 5}, "detected": True, "delay_s": 190,
                "closed_after_rest": True},
               {"scenario": "rtt", "node": "LAB_C3", "fault": {"delay_ms": 60}, "detected": False, "delay_s": None,
                "closed_after_rest": True}]
    text = bench.report(results, [{"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B", "METRIC": "jitter",
                                   "explanation": "x"}], "robust")
    assert "Détections : 1/2 ; fausses alertes : 1" in text and "190 s" in text and "**non**" in text

"""Tableaux de bord Grafana générés (lab/grafana/build_dashboards.py) : couleurs des panneaux."""
import importlib.util
from pathlib import Path

GRAFANA = Path(__file__).resolve().parents[1] / "grafana"
spec = importlib.util.spec_from_file_location("build_dashboards", GRAFANA / "build_dashboards.py")
bd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bd)

RED = {"mode": "shades", "fixedColor": "red"}


def panels():
    for dash in (bd.series_dashboard(), bd.matrix_dashboard(), bd.hubs_dashboard()):
        yield from (p for p in dash["panels"] if p["type"] == "timeseries")


def is_loss(panel):
    return any("LOSS" in t["expr"] for t in panel["targets"])


def test_loss_curves_are_red():
    loss = [p for p in panels() if is_loss(p)]
    assert len(loss) >= 3
    for p in loss:
        assert p["fieldConfig"]["defaults"].get("color") == RED, p["title"]


def test_other_curves_keep_their_colors():
    for p in panels():
        if not is_loss(p):
            assert p["fieldConfig"]["defaults"].get("color") != RED, p["title"]


def test_the_provisioned_dashboards_are_up_to_date():
    for name, dash in (("syntraf.json", bd.series_dashboard()), ("syntraf-matrix.json", bd.matrix_dashboard()),
                       ("syntraf-hubs.json", bd.hubs_dashboard()),
                       ("syntraf-correlation.json", bd.correlation_dashboard()),
                       ("syntraf-quality.json", bd.quality_dashboard())):
        import json
        assert json.loads((GRAFANA / "dashboards" / name).read_text(encoding="utf-8")) == dash, name


def test_the_correlation_dashboard_shows_loss_and_jitter_matrices():
    tables = [p for p in bd.correlation_dashboard()["panels"] if p["type"] == "table"]
    assert [("LOSS" in t["targets"][0]["expr"], "JITTER" in t["targets"][0]["expr"]) for t in tables] == [(True, False), (False, True)]
    for t in tables:
        grouping = [x for x in t["transformations"] if x["id"] == "groupingToMatrix"][0]["options"]
        assert (grouping["rowField"], grouping["columnField"]) == ("FLOW_A", "FLOW_B")


def test_the_quality_dashboard_shows_mos_and_bursts():
    exprs = [t["expr"] for p in bd.quality_dashboard()["panels"] for t in p.get("targets", [])]
    assert any("SYNTRAF_RX_MOS" in e for e in exprs)
    assert {m for m in ("BURST_RATIO", "LONGEST_S", "HEAVY_SHARE") if any(m in e for e in exprs)} == {
        "BURST_RATIO", "LONGEST_S", "HEAVY_SHARE"}

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
                       ("syntraf-quality.json", bd.quality_dashboard()),
                       ("syntraf-tcp.json", bd.tcp_dashboard()), ("syntraf-health.json", bd.health_dashboard())):
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


def test_the_tcp_dashboard_shows_throughput_retransmits_and_failures():
    d = bd.tcp_dashboard()
    exprs = [t["expr"] for p in d["panels"] for t in p.get("targets", [])]
    for m in ("SYNTRAF_TCP_BITRATE_MBPS", "SYNTRAF_TCP_RETRANSMITS", "SYNTRAF_TCP_RTT_MS", "SYNTRAF_TCP_FAILED"):
        assert any(m in e for e in exprs), m
    assert {v["name"] for v in d["templating"]["list"]} >= {"test", "direction"}
    series = [p for p in d["panels"] if p["type"] == "timeseries"]
    assert all(p["fieldConfig"]["defaults"]["custom"]["showPoints"] == "always" for p in series)  # un point par test


# ------------------------------------------------------------------------------------------- lisibilité

def all_dashboards():
    return [bd.series_dashboard(), bd.matrix_dashboard(), bd.quality_dashboard(), bd.tcp_dashboard(),
            bd.hubs_dashboard(), bd.correlation_dashboard(), bd.health_dashboard()]


def test_dashboards_are_numbered_and_linked_in_reading_order_including_tcp_tests():
    dashes = all_dashboards()
    assert [d["title"].split(" · ")[0] for d in dashes] == ["1", "2", "3", "4", "5", "6", "7"]
    for d in dashes:
        links = d["links"]
        assert [l["url"] for l in links] == [f"/d/{x['uid']}" for x in dashes]
        assert all(l["keepTime"] and l["includeVars"] for l in links)
        assert any("TCP" in l["title"] for l in links)


def test_panel_titles_are_short():
    for d in all_dashboards():
        for p in d["panels"]:
            assert len(p.get("title", "")) <= 40, (d["title"], p["title"])


def test_filters_say_source_and_destination_not_client_and_server():
    for d in [bd.series_dashboard(), bd.matrix_dashboard(), bd.quality_dashboard()]:
        labels = {v["name"]: v["label"] for v in d["templating"]["list"]}
        assert labels == {"mesh_group": "Groupe", "client": "Source", "server": "Destination"}
    tcp = {v["name"]: v["label"] for v in bd.tcp_dashboard()["templating"]["list"]}
    assert tcp["server"] == "Initiateur" and tcp["client"] == "Pair" and tcp["direction"] == "Sens"


def test_dashboards_are_split_into_titled_sections():
    for d in all_dashboards()[:4]:
        rows = [p for p in d["panels"] if p["type"] == "row"]
        assert len(rows) >= 2 and all(r["title"] for r in rows), d["title"]


def test_panels_never_overlap():
    for d in all_dashboards():
        boxes = [(p["gridPos"], p.get("title")) for p in d["panels"]]
        for i, (a, ta) in enumerate(boxes):
            assert a["x"] + a["w"] <= 24
            for b, tb in boxes[i + 1:]:
                overlap = a["x"] < b["x"] + b["w"] and b["x"] < a["x"] + a["w"] and \
                    a["y"] < b["y"] + b["h"] and b["y"] < a["y"] + a["h"]
                assert not overlap, (d["title"], ta, tb)


def test_matrices_fit_six_probes_and_empty_cells_stay_neutral():
    for d in all_dashboards():
        for p in d["panels"]:
            if any(t["id"] == "groupingToMatrix" for t in p.get("transformations", [])):
                assert p["gridPos"]["h"] >= 10, p["title"]
                maps = p["fieldConfig"]["defaults"]["mappings"]
                assert any(m["type"] == "special" and m["options"]["match"] == "null" and
                           m["options"]["result"]["color"] == "transparent" for m in maps), p["title"]


def test_the_round_trip_matrix_is_symmetric():
    rtt = next(p for p in bd.quality_dashboard()["panels"] if p["title"].startswith("RTT"))
    assert "label_replace" in rtt["targets"][0]["expr"]  # le sens non mesuré reprend la valeur de la paire


def test_tcp_results_read_in_the_direction_of_the_data():
    tcp = bd.tcp_dashboard()
    rate = next(p for p in tcp["panels"] if p["type"] == "timeseries" and "BITRATE" in p["targets"][0]["expr"])
    assert rate["targets"][0]["legendFormat"].startswith("{{SRC}} → {{DST}}")
    assert rate["fieldConfig"]["defaults"]["custom"]["scaleDistribution"]["type"] == "log"
    latest = [p for p in tcp["panels"] if any(t["id"] == "groupingToMatrix" for t in p.get("transformations", []))]
    assert latest and all(m["transformations"][-1]["options"]["rowField"] == "SRC" for m in latest)
    assert tcp["annotations"]["list"][0]["enable"] is False  # 24 h de changements masquaient les points


def test_the_overview_shows_the_latest_tcp_tests_and_no_wall_of_tiny_tiles():
    overview = bd.series_dashboard()
    assert any("SYNTRAF_TCP_BITRATE_MBPS" in t["expr"] for p in overview["panels"] for t in p.get("targets", []))
    assert not any(p["type"] == "stat" for p in overview["panels"])


def test_matrices_are_sorted_and_narrow_enough_for_six_columns():
    for d in all_dashboards():
        for p in d["panels"]:
            g = next((t for t in p.get("transformations", []) if t["id"] == "groupingToMatrix"), None)
            if g is None:
                continue
            row, column = g["options"]["rowField"], g["options"]["columnField"]
            # colonnes dans l'ordre alphabétique (ordre des séries), lignes triées par la table
            assert p["targets"][0]["expr"].startswith(f'sort_by_label(') and f'"{column}", "{row}")' in p["targets"][0]["expr"]
            assert p["options"]["sortBy"][0]["desc"] is False
            assert p["fieldConfig"]["defaults"]["custom"]["minWidth"] <= 80, p["title"]


def test_a_pair_of_probes_both_behind_a_nat_says_why_it_has_no_value():
    """Deux sondes derrière un NAT ne se joignent pas : leur case dit « NAT ↔ NAT » au lieu de rester vide."""
    count = 0
    for d in all_dashboards()[:4]:
        for p in d["panels"]:
            g = next((t for t in p.get("transformations", []) if t["id"] == "groupingToMatrix"), None)
            if g is None:
                continue
            count += 1
            assert "SYNTRAF_FLOW_NAT_PAIR" in p["targets"][0]["expr"], (d["title"], p["title"])
            maps = p["fieldConfig"]["defaults"]["mappings"]
            note = [m for m in maps if m["type"] == "value" and str(bd.NAT_PAIR) in m["options"]]
            assert note and note[0]["options"][str(bd.NAT_PAIR)]["text"] == "NAT ↔ NAT"
            assert note[0]["options"][str(bd.NAT_PAIR)]["color"] == "transparent"
    assert count >= 15
    hubs = [p for p in bd.hubs_dashboard()["panels"] if p.get("transformations")]
    assert not any("SYNTRAF_FLOW_NAT_PAIR" in p["targets"][0]["expr"] for p in hubs)  # spokes × hubs seulement


def test_the_quality_dashboard_checks_the_dscp_of_each_direction():
    d = bd.quality_dashboard()
    rows = [p["title"] for p in d["panels"] if p["type"] == "row"]
    assert "Marquage DSCP" in rows
    exprs = " ".join(t["expr"] for p in d["panels"] for t in p.get("targets", []))
    for m in ("SYNTRAF_LATENCY_DSCP_OK_PCT_FWD", "SYNTRAF_LATENCY_DSCP_OK_PCT_REV",
              "SYNTRAF_LATENCY_DSCP_RECV_FWD", "SYNTRAF_LATENCY_DSCP_RECV_REV"):
        assert m in exprs, m


def test_a_rewritten_group_is_never_hidden_by_another_group_on_the_same_pair():
    """Deux groupes peuvent relier les mêmes sondes : la part conservée affichée est la plus mauvaise des deux."""
    ok = next(p for p in bd.quality_dashboard()["panels"] if p.get("title", "").startswith("DSCP conservé"))
    assert ok["targets"][0]["expr"].count("min by (CLIENT, SERVER)") >= 1


def test_the_dscp_matrix_only_shows_a_value_where_the_marking_was_rewritten():
    """« 34 reçu » à côté de « 100 % conservé » (paire reliée par deux groupes, DSCP 0 et 34) n'avait pas de sens :
    la matrice dit « intact », ou la valeur réécrite là où le marquage a changé."""
    d = bd.quality_dashboard()
    titles = [p.get("title") for p in d["panels"]]
    assert "DSCP reçu" not in titles
    m = next(p for p in d["panels"] if p.get("title") == "DSCP réécrit en")
    assert "< 100" in m["targets"][0]["expr"] and f"{bd.DSCP_INTACT}" in m["targets"][0]["expr"]
    note = [x for x in m["fieldConfig"]["defaults"]["mappings"]
            if x["type"] == "value" and str(bd.DSCP_INTACT) in x["options"]]
    assert note and note[0]["options"][str(bd.DSCP_INTACT)]["text"] == "intact"
    assert m["fieldConfig"]["defaults"]["thresholds"]["steps"][0]["color"] == "red"  # toute valeur affichée = réécrite


def test_alerts_are_visible_in_grafana():
    overview = bd.series_dashboard()
    rows = [p["title"] for p in overview["panels"] if p["type"] == "row"]
    assert rows[0] == "Alertes"  # en premier : ce qui demande une action
    exprs = " ".join(t["expr"] for p in overview["panels"] for t in p.get("targets", []))
    assert "SYNTRAF_BASELINE_ALERT" in exprs
    for d in all_dashboards():
        names = [a["name"] for a in d["annotations"]["list"]]
        assert "Alertes" in names, d["title"]
        alert = next(a for a in d["annotations"]["list"] if a["name"] == "Alertes")
        assert "SYNTRAF_ALERT_EVENT" in alert["expr"] and alert["enable"] is True


def test_the_health_of_syntraf_itself_has_its_own_dashboard():
    d = bd.health_dashboard()
    exprs = " ".join(t["expr"] for p in d["panels"] for t in p.get("targets", []))
    for m in ("syntraf_client_connected", "syntraf_client_buffered_points", "syntraf_database_up",
              "syntraf_database_backlog", "syntraf_thread_up", "syntraf_queue_length", 'up{job="syntraf"}'):
        assert m in exprs, m


def test_restarts_updates_and_rollbacks_are_annotations_on_every_dashboard():
    for d in all_dashboards():
        a = next((x for x in d["annotations"]["list"] if x["name"] == "Redémarrages et mises à jour"), None)
        assert a is not None and "SYNTRAF_LIFECYCLE_EVENT" in a["expr"] and a["enable"] is True, d["title"]


def test_maintenance_windows_show_as_regions_in_grafana():
    for d in all_dashboards():
        a = next((x for x in d["annotations"]["list"] if x["name"] == "Maintenance"), None)
        assert a is not None and "SYNTRAF_MAINTENANCE_ACTIVE" in a["expr"], d["title"]

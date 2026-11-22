"""Flux attendus et événements de configuration écrits dans la base (lib/st_flow_catalog.py), et tableaux de bord
Grafana qui s'en servent (lab/grafana/build_dashboards.py). Sans dépendance : tourne dans lab/.venv.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "lab" / "grafana"))
from lib import st_flow_catalog as fc  # noqa: E402

try:
    import build_dashboards as bd  # noqa: E402
except ImportError:  # pragma: no cover
    bd = None


def listener(sender, receiver, group="G1", dscp="0"):
    return {"UID_CLIENT": sender, "UID_SERVER": receiver, "MESH_GROUP": group, "DSCP": dscp}


CONFIG = {"MESH_GROUP": [{"UID": "G1", "TOPOLOGY": "DUAL_HUB", "HUBS": ["H1", "H2"]}, {"UID": "G2"}]}
GENERATED = {
    "H1": {"LISTENERS": {"a": listener("S1", "H1"), "b": listener("H2", "H1")}, "CONNECTORS": {}, "CLIENT": {}},
    "S1": {"LISTENERS": {"c": listener("H1", "S1")},
           "CONNECTORS": {"d": dict(listener("S1", "X9", "G2"), BIDIR=True)}},
}


def test_expected_flows_come_from_the_listeners_with_their_roles():
    flows = {f["UID"]: f for f in fc.expected_flows(CONFIG, GENERATED)}
    assert set(flows) == {"S1__TO__H1__ON__DSCP0", "H2__TO__H1__ON__DSCP0", "H1__TO__S1__ON__DSCP0",
                          "X9__TO__S1__ON__DSCP0"}  # le connecteur bidirectionnel mesure aussi le retour
    f = flows["S1__TO__H1__ON__DSCP0"]
    assert (f["CLIENT"], f["SERVER"], f["MESH_GROUP"], f["TOPOLOGY"]) == ("S1", "H1", "G1", "DUAL_HUB")
    assert (f["CLIENT_ROLE"], f["SERVER_ROLE"]) == ("spoke", "hub")
    assert flows["H2__TO__H1__ON__DSCP0"]["CLIENT_ROLE"] == "hub"
    assert flows["X9__TO__S1__ON__DSCP0"]["CLIENT_ROLE"] == "member"  # G2 : maillage complet


def test_expected_points_are_one_gauge_per_flow():
    now = datetime(2026, 11, 22, tzinfo=timezone.utc)
    [p] = fc.expected_points([fc.expected_flows(CONFIG, GENERATED)[0]], now)
    assert p["measurement"] == "SYNTRAF_FLOW" and p["fields"] == {"EXPECTED": 1} and p["time"] == now
    assert {"MESH_GROUP", "CLIENT", "SERVER", "UID", "TOPOLOGY", "CLIENT_ROLE", "SERVER_ROLE"} <= set(p["tags"])


def test_config_change_event_point():
    entry = {"time": "2026-11-22T01:00:00+00:00", "action": "UPDATE_MESH_GROUP", "actor": "10.0.0.5",
             "summary": "Mesh group 'G1' updated\nsecond line " + "x" * 300}
    p = fc.event_point(entry)
    assert p["measurement"] == "SYNTRAF_CONFIG" and p["fields"] == {"CHANGE": 1}
    assert p["tags"]["ACTION"] == "UPDATE_MESH_GROUP" and p["tags"]["ACTOR"] == "10.0.0.5"
    assert "\n" not in p["tags"]["SUMMARY"] and len(p["tags"]["SUMMARY"]) <= 200
    assert p["time"] == datetime(2026, 11, 22, 1, tzinfo=timezone.utc)


class FakeDb:
    def __init__(self, fail=False):
        self.batches, self.fail = [], fail

    def save_metrics_to_database_with_buffer(self, payload, address, client_uid):
        if self.fail:
            raise OSError("down")
        self.batches.append(payload)
        return "OK"


def test_publish_writes_to_every_database_and_survives_a_failing_one():
    good, bad = FakeDb(), FakeDb(fail=True)
    assert fc.publish_expected(CONFIG, GENERATED, [bad, good]) == 4
    assert len(good.batches[0]) == 4 + 2  # les flux, et les paramètres de chaque groupe (même publication)
    assert {p["measurement"] for p in good.batches[0]} == {"SYNTRAF_FLOW", "SYNTRAF_GROUP"}


def test_publication_is_throttled_unless_forced():
    db = FakeDb()
    pub = fc.Publisher(period_s=30)
    assert pub.maybe(CONFIG, GENERATED, [db], now=100.0) is True
    assert pub.maybe(CONFIG, GENERATED, [db], now=110.0) is False
    assert pub.maybe(CONFIG, GENERATED, [db], now=131.0) is True


def test_audit_entries_are_announced_to_listeners(tmp_path):
    pytest.importorskip("toml")
    from lib import st_config_store as store
    seen = []
    store.set_listener("test", seen.append)
    store.set_listener("broken", lambda e: 1 / 0)  # un écouteur défaillant n'empêche pas l'écriture
    try:
        path = str(tmp_path / "config.toml")
        store.save(path, {"A": 1}, "x", "ACT", "one")
        store.log_event(path, "x", "EVT", "two")
    finally:
        store.set_listener("test", None)
        store.set_listener("broken", None)
    assert [e["action"] for e in seen] == ["ACT", "EVT"]


def test_group_points_carry_the_effective_parameters():
    config = {"MESH_GROUP": [
        {"UID": "G1", "TOPOLOGY": "DUAL_HUB", "HUBS": ["H1", "H2"], "BANDWIDTH": "100K", "DSCP": "46",
         "PACKET_SIZE": "218", "INTERVAL": "1", "IPERF3_PROFILE": "LAB_PROFILE"},
        {"UID": "G2", "DISABLED": True, "BANDWIDTH": "1M", "DSCP": "0", "PACKET_SIZE": "1400", "INTERVAL": "1"}]}
    now = datetime(2026, 11, 22, tzinfo=timezone.utc)
    [p] = fc.group_points(config, fc.expected_flows(config, GENERATED), now)  # groupe désactivé : rien
    assert p["measurement"] == "SYNTRAF_GROUP" and p["time"] == now
    assert p["tags"] == {"MESH_GROUP": "G1", "TOPOLOGY": "DUAL_HUB", "HUBS": "H1, H2", "PROFILE": "LAB_PROFILE",
                         "BANDWIDTH": "100 Kbps", "DSCP": "46", "PACKET_SIZE": "218 B", "INTERVAL": "1 s",
                         "PPS": "57", "MEMBERS": "3", "FLOWS": "3"}
    f = p["fields"]
    assert (f["INFO"], f["BANDWIDTH_KBPS"], f["PACKET_SIZE"], f["DSCP"], f["INTERVAL"], f["FLOWS"]) == (1, 100.0, 218, 46, 1, 3)
    assert round(f["PPS"], 1) == 57.3  # 100 000 bit/s ÷ (218 octets × 8)


def test_bandwidth_texts_are_parsed():
    assert [fc.bandwidth_bps(t) for t in ("100K", "2M", "1G", "64000", "", "x")] == [1e5, 2e6, 1e9, 64000, 0, 0]


@pytest.mark.skipif(bd is None, reason="générateur des tableaux de bord introuvable")
def test_dashboards_show_the_group_parameters_and_the_expected_bitrate():
    for dash in (bd.series_dashboard(), bd.matrix_dashboard(), bd.hubs_dashboard()):
        banner = dash["panels"][0]
        assert banner["type"] == "table" and "SYNTRAF_GROUP_INFO" in banner["targets"][0]["expr"]
    bitrate = next(p for p in bd.series_dashboard()["panels"] if p["title"].startswith("Débit"))
    assert any("SYNTRAF_GROUP_BANDWIDTH_KBPS" in t["expr"] for t in bitrate["targets"])


@pytest.mark.skipif(bd is None, reason="générateur des tableaux de bord introuvable")
def test_dashboards_use_expected_flows_annotations_and_a_hubs_view():
    matrix = bd.matrix_dashboard()
    exprs = [t["expr"] for p in matrix["panels"] if "SYNTRAF_GROUP_INFO" not in p["targets"][0]["expr"]
             for t in p["targets"]]
    assert all("SYNTRAF_FLOW_EXPECTED" in e for e in exprs)
    assert matrix["annotations"]["list"][0]["expr"].startswith("last_over_time(SYNTRAF_CONFIG_CHANGE")
    hubs = bd.hubs_dashboard()
    assert hubs["uid"] == "syntraf-hubs"
    joined = " ".join(t["expr"] for p in hubs["panels"] for t in p["targets"])
    assert 'CLIENT_ROLE="spoke"' in joined and 'SERVER_ROLE="hub"' in joined
    series = bd.series_dashboard()
    silence = next(p for p in series["panels"] if p["type"] == "stat")
    assert "SYNTRAF_FLOW_EXPECTED" in silence["targets"][0]["expr"]

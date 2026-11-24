"""Baseline par flux et par métrique, alertes hors baseline (lib/st_baseline.py) : statistiques robustes, saisonnalité,
marges minimales, sens du « pire », apprentissage, hystérésis."""
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_baseline as bl  # noqa: E402

DAY = 86400
NOW = datetime(2026, 11, 23, 10, 30).timestamp()  # lundi 10 h 30, heure du serveur


def flat(value, days=7, step=300, end=NOW):
    return [(end - days * DAY + i * step, value) for i in range(int(days * DAY / step))]


def test_robust_statistics_ignore_outliers():
    median, spread = bl.robust([1, 1, 1, 1, 1, 1, 1, 1, 1, 100])
    assert median == 1 and spread == 0
    median, spread = bl.robust([10, 11, 9, 10, 12, 8, 10])
    assert median == 10 and spread == pytest.approx(1.4826, rel=1e-3)


def test_no_baseline_before_a_day_of_history():
    d = bl.RobustDetector()
    assert d.baseline(flat(1.0, days=0.5), NOW) is None
    assert d.baseline(flat(1.0, days=2), NOW).median == 1.0


def test_the_baseline_follows_the_hour_of_the_day_once_there_are_three_days():
    # 20 ms la journée (8 h-18 h), 5 ms la nuit : à 10 h 30, la norme est celle de la journée
    pts = [(t, 20.0 if 8 <= datetime.fromtimestamp(t).hour < 18 else 5.0) for t, _ in flat(0, days=7)]
    b = bl.RobustDetector().baseline(pts, NOW)
    assert b.seasonal and b.median == 20.0
    assert not bl.RobustDetector().baseline(pts[-2 * 288:], NOW).seasonal  # 2 jours : pas encore par heure


def test_a_value_is_out_of_baseline_only_in_the_bad_direction_and_beyond_the_minimum_margin():
    d = bl.RobustDetector()
    loss = bl.METRICS["loss"]
    base = d.baseline(flat(0.0), NOW)
    assert not bl.judge(loss, base, 0.5).anomalous  # sous la marge de 1 point : pas une alerte
    v = bl.judge(loss, base, 3.0)
    assert v.anomalous and "3" in v.explanation and "0" in v.explanation
    mos = bl.METRICS["mos"]
    base = d.baseline(flat(4.4), NOW)
    assert not bl.judge(mos, base, 4.5).anomalous  # meilleur que d'habitude : jamais une alerte
    assert bl.judge(mos, base, 3.6).anomalous
    rtt = bl.METRICS["rtt"]
    base = d.baseline(flat(67.0), NOW)  # satellite : 67 ms est sa norme
    assert not bl.judge(rtt, base, 70.0).anomalous and bl.judge(rtt, base, 120.0).anomalous


def test_sensitivity_widens_the_band_for_noisy_flows():
    noisy = [(t, 5.0 + (i % 5)) for i, (t, _) in enumerate(flat(0))]  # 5 à 9 ms
    b = bl.RobustDetector().baseline(noisy, NOW)
    jitter = bl.METRICS["jitter"]
    assert not bl.judge(jitter, b, 12.0, k=4).anomalous
    assert bl.judge(jitter, b, 20.0, k=4).anomalous


def test_an_alert_opens_after_a_few_minutes_and_closes_once_clearly_back():
    book = bl.AlertBook(open_after=3, close_after=3)
    key = ("G", "A", "B", "loss")
    bad, good, edge = bl.Verdict(True, 3.0, "pertes"), bl.Verdict(False, 0.1, "ok"), bl.Verdict(False, 0.8, "presque")
    assert book.update(key, bad, 0) == [] and book.update(key, bad, 60) == []
    assert book.update(key, bad, 120) == ["open"] and len(book.open()) == 1
    for t in (180, 240, 300, 360):  # revenu sous le seuil, mais pas franchement : reste ouverte
        assert book.update(key, edge, t) == []
    assert book.update(key, good, 420) == [] and book.update(key, good, 480) == []
    assert book.update(key, good, 540) == ["close"] and book.open() == []
    assert book.recent()[0]["closed_at"] == 540 and book.recent()[0]["opened_at"] == 120


def test_a_brief_spike_never_alerts():
    book = bl.AlertBook(open_after=3, close_after=3)
    key = ("G", "A", "B", "loss")
    for t, v in enumerate([True, True, False, True, False]):
        assert book.update(key, bl.Verdict(v, 3.0 if v else 0.1, ""), t * 60) == []


def test_history_restarts_after_a_change_of_the_group_parameters():
    pts = flat(10.0, days=7)
    since = NOW - 0.5 * DAY
    assert bl.RobustDetector().baseline(bl.since(pts, since), NOW) is None  # réapprend


def test_detectors_are_interchangeable():
    assert "robust" in bl.DETECTORS and isinstance(bl.detector("robust"), bl.RobustDetector)
    with pytest.raises(KeyError):
        bl.detector("crystal-ball")


class FakeVm:
    """Historique de 7 jours sans pertes pour A → B (groupe G), 12 h seulement pour C → D (groupe NEW, changé)."""

    def __init__(self, now_loss):
        self.now_loss = now_loss

    def query_range(self, q, start, end, step):
        if "SYNTRAF_RX_PCT_LOSS" not in q:
            return []
        return [{"metric": {"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B"},
                 "values": [[t, "0"] for t in range(int(start), int(end), step)]},
                {"metric": {"MESH_GROUP": "NEW", "CLIENT": "C", "SERVER": "D"},
                 "values": [[t, "0"] for t in range(int(start), int(end), step)]}]

    def query(self, q):
        if "tlast_change_over_time" in q:
            return [{"metric": {"MESH_GROUP": "NEW"}, "value": [0, str(NOW - 12 * 3600)]}]
        if "SYNTRAF_RX_PCT_LOSS" in q:
            return [{"metric": {"MESH_GROUP": "G", "CLIENT": "A", "SERVER": "B"}, "value": [0, str(self.now_loss)]},
                    {"metric": {"MESH_GROUP": "NEW", "CLIENT": "C", "SERVER": "D"}, "value": [0, "50"]}]
        return []


def test_evaluation_opens_an_alert_only_for_a_flow_with_a_baseline():
    book, written = bl.AlertBook(), []
    vm = FakeVm(now_loss=4.0)
    for i in range(3):
        status = bl.evaluate(vm, now=NOW + 60 * i, book=book, specs=[bl.METRICS["loss"]], write=written.extend)
    assert status["watched"] == 1 and status["learning"] == 1  # C → D : groupe changé il y a 12 h, réapprend
    alerts = book.open()
    assert len(alerts) == 1 and alerts[0]["CLIENT"] == "A" and alerts[0]["METRIC"] == "loss"
    assert "4" in alerts[0]["explanation"]
    assert written and written[0]["measurement"] == "SYNTRAF_BASELINE" and written[0]["fields"]["CURRENT"] == 4.0


def test_a_flow_that_disappears_closes_its_alert():
    book = bl.AlertBook(open_after=1)
    bl.evaluate(FakeVm(now_loss=4.0), now=NOW, book=book, specs=[bl.METRICS["loss"]])
    assert book.open()
    book.forget(set())
    assert not book.open() and book.recent()[0]["closed_at"] is not None


def test_adding_a_member_to_a_group_does_not_restart_the_learning():
    """Le nombre de membres et de flux sont des étiquettes des points du groupe : un nouveau membre crée de nouvelles
    séries. Seule une valeur qui change (débit, taille, DSCP, intervalle) relance l'apprentissage."""
    seen = []

    class Vm:
        def query(self, q):
            seen.append(q)
            return []
    bl.group_resets(Vm(), NOW)
    assert "max by (MESH_GROUP, __name__)" in seen[0] and ":" in seen[0].split("[")[-1]  # sous-requête regroupée


# ------------------------------------------------------------------------------------- réglages (fine tuning)

CONFIG = {"GLOBAL": {"BASELINE_SENSITIVITY": "3", "BASELINE_MARGIN_LOSS": "2", "BASELINE_MARGIN_RTT": "20",
                     "BASELINE_OPEN_AFTER": "5", "BASELINE_CLOSE_AFTER": "10"},
          "MESH_GROUP": [{"UID": "VOICE", "IPERF3_PROFILE": "G711"}, {"UID": "OPS"}],
          "IPERF3_PROFILE": [{"UID": "G711", "BASELINE_SENSITIVITY": "2"}]}


def test_settings_come_from_the_global_section_and_a_profile_can_be_stricter_for_its_groups():
    s = bl.Settings.from_config(CONFIG)
    assert s.k_for("VOICE") == 2.0 and s.k_for("OPS") == 3.0 and s.k_for("UNKNOWN") == 3.0
    assert s.margin("loss") == 2.0 and s.margin("rtt") == 20.0 and s.margin("jitter") == bl.METRICS["jitter"].abs_margin
    assert (s.open_after, s.close_after) == (5, 10)
    d = bl.Settings.from_config({})
    assert d.k_for("X") == bl.DEFAULT_K and (d.open_after, d.close_after) == (bl.OPEN_AFTER, bl.CLOSE_AFTER)
    assert bl.Settings.from_config({"GLOBAL": {"BASELINE_SENSITIVITY": "abc"}}).k_for("X") == bl.DEFAULT_K


def test_the_minimum_margin_of_a_metric_can_be_raised():
    base = bl.RobustDetector().baseline(flat(0.0), NOW)
    loss = bl.METRICS["loss"]
    assert bl.judge(loss, base, 1.5).anomalous
    assert not bl.judge(loss, base, 1.5, margin=2.0).anomalous  # « pas d'alerte de pertes sous 2 % »


def test_evaluation_applies_the_delays_and_the_sensitivity_of_each_group():
    book = bl.AlertBook()
    settings = bl.Settings.from_config({"GLOBAL": {"BASELINE_OPEN_AFTER": "1"}})
    bl.evaluate(FakeVm(now_loss=4.0), now=NOW, book=book, specs=[bl.METRICS["loss"]], settings=settings)
    assert len(book.open()) == 1  # ouverte dès la première minute
    lenient = bl.Settings.from_config({"GLOBAL": {"BASELINE_OPEN_AFTER": "1", "BASELINE_MARGIN_LOSS": "10"}})
    book2 = bl.AlertBook()
    bl.evaluate(FakeVm(now_loss=4.0), now=NOW, book=book2, specs=[bl.METRICS["loss"]], settings=lenient)
    assert book2.open() == []


def test_alert_state_and_events_are_written_for_grafana():
    book, written = bl.AlertBook(open_after=1), []
    bl.evaluate(FakeVm(now_loss=4.0), now=NOW, book=book, specs=[bl.METRICS["loss"]], write=written.extend)
    state = [p for p in written if p["measurement"] == "SYNTRAF_BASELINE"]
    assert state[0]["fields"]["ALERT"] == 1  # SYNTRAF_BASELINE_ALERT, à chaque évaluation
    events = [p for p in written if p["measurement"] == "SYNTRAF_ALERT"]
    assert len(events) == 1 and events[0]["fields"] == {"EVENT": 1}
    tags = events[0]["tags"]
    assert tags["ACTION"] == "OPENED" and tags["METRIC"] == "loss" and tags["FLOW"] == "A → B" and tags["SUMMARY"]


# ------------------------------------------------------------------------- santé de SYNTRAF lui-même

SNAP = {"clients": [{"uid": "A", "status": "CONNECTED", "metrics_buffer": 12, "declared": True},
                    {"uid": "B", "status": "DISCONNECTED", "status_since": "2026-11-23T10:00:00", "declared": True,
                     "metrics_buffer": None},
                    {"uid": "C", "status": "CONNECTED", "metrics_buffer": 5000, "declared": True},
                    {"uid": "OLD", "status": "DISCONNECTED", "declared": False, "metrics_buffer": None}],
        "databases": [{"uid": "VM", "status": "ONLINE", "backlog": 50000}, {"uid": "VM2", "status": "OFFLINE",
                                                                             "backlog": 0}],
        "threads": [{"name": "SERVER", "type": "SERVER", "alive": False}, {"name": "WEBUI", "type": "WEBUI",
                                                                           "alive": True}],
        "queue_length": 20000}


def test_health_checks_find_what_is_wrong_with_syntraf_itself():
    found = {(c["metric"], c["subject"]) for c in bl.health_checks(SNAP) if c["anomalous"]}
    assert found == {("probe_disconnected", "B"), ("probe_backlog", "C"), ("database_down", "VM2"),
                     ("database_backlog", "VM"), ("thread_dead", "SERVER"), ("server_queue", "server")}
    ok = {(c["metric"], c["subject"]) for c in bl.health_checks(SNAP) if not c["anomalous"]}
    assert ("probe_disconnected", "A") in ok and not any(s == "OLD" for _, s in found | ok)  # non déclaré : ignoré


def test_health_alerts_open_after_the_delay_and_live_in_their_own_book():
    book = bl.AlertBook(open_after=2)
    written = []
    for i in range(2):
        bl.evaluate_health(SNAP, now=NOW + 60 * i, book=book, write=written.extend)
    opened = {(a["METRIC"], a["SUBJECT"]) for a in book.open()}
    assert ("probe_disconnected", "B") in opened and len(opened) == 6
    assert any(p["measurement"] == "SYNTRAF_ALERT" and p["tags"]["METRIC"] == "probe_disconnected" for p in written)
    summary = bl.summary(bl.AlertBook(), health_book=book)
    assert len(summary["open"]) == 6 and all(a["KIND"] == "health" for a in summary["open"])


# ---------------------------------------------------------------------------------- fenêtres de maintenance

def test_no_alert_opens_for_a_flow_in_maintenance():
    from lib import st_maintenance as mt
    windows = [{"UID": "WORK_ON_A", "TARGET_TYPE": "node", "TARGET": "A", "MODE": "once",
                "START": "2026-11-23T10:00", "END": "2026-11-23T12:00"}]
    book = bl.AlertBook(open_after=1)
    status = bl.evaluate(FakeVm(now_loss=4.0), now=NOW, book=book, specs=[bl.METRICS["loss"]],
                         maintenance=mt.Maintenance(windows, NOW))
    assert book.open() == [] and status["in_maintenance"] == 1


def test_a_probe_in_maintenance_raises_no_health_alert_and_the_window_is_published():
    from lib import st_maintenance as mt
    windows = [{"UID": "B_REBOOT", "TARGET_TYPE": "node", "TARGET": "B", "MODE": "once",
                "START": "2026-11-23T10:00", "END": "2026-11-23T12:00"}]
    book, written = bl.AlertBook(open_after=1), []
    bl.evaluate_health(SNAP, now=NOW, book=book, write=written.extend, maintenance=mt.Maintenance(windows, NOW))
    assert ("probe_disconnected", "B") not in {(a["METRIC"], a["SUBJECT"]) for a in book.open()}
    active = [p for p in written if p["measurement"] == "SYNTRAF_MAINTENANCE"]
    assert active and active[0]["tags"]["UID"] == "B_REBOOT" and active[0]["fields"] == {"ACTIVE": 1}


def test_listeners_hear_each_opened_alert_once_and_a_failing_listener_changes_nothing():
    book, heard = bl.AlertBook(), []
    vm = FakeVm(now_loss=4.0)

    def boom(info, now):
        raise RuntimeError("listener down")
    bl.OPEN_LISTENERS[:] = [boom, lambda info, now: heard.append((info["CLIENT"], info["SERVER"], info["METRIC"], now))]
    try:
        for i in range(5):
            bl.evaluate(vm, now=NOW + 60 * i, book=book, specs=[bl.METRICS["loss"]])
    finally:
        bl.OPEN_LISTENERS.clear()
    assert heard == [("A", "B", "loss", NOW + 120)] and len(book.open()) == 1

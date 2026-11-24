"""Fenêtres de maintenance par sonde ou par mesh group (lib/st_maintenance.py) : alertes suspendues."""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_maintenance as mt  # noqa: E402

SUN_3AM = datetime(2026, 11, 22, 3, 0).timestamp()   # dimanche 3 h, heure du serveur
SUN_5AM = datetime(2026, 11, 22, 5, 0).timestamp()
MON_3AM = datetime(2026, 11, 23, 3, 0).timestamp()

WINDOWS = [{"UID": "SAT_UPGRADE", "TARGET_TYPE": "node", "TARGET": "STARLINK", "MODE": "once",
            "START": "2026-11-23T10:00", "END": "2026-11-23T12:00"},
           {"UID": "SUNDAY_NIGHT", "TARGET_TYPE": "mesh_group", "TARGET": "VOICE", "MODE": "weekly",
            "DAYS": ["sun"], "FROM": "02:00", "TO": "04:00"},
           {"UID": "OFF", "TARGET_TYPE": "node", "TARGET": "A", "MODE": "weekly", "DAYS": ["mon"], "FROM": "00:00",
            "TO": "23:59", "ENABLED": False}]


def test_a_weekly_window_is_active_only_on_its_days_and_hours():
    w = WINDOWS[1]
    assert mt.active(w, SUN_3AM) and not mt.active(w, SUN_5AM) and not mt.active(w, MON_3AM)


def test_a_one_off_window_and_a_disabled_one():
    assert mt.active(WINDOWS[0], datetime(2026, 11, 23, 11, 0).timestamp())
    assert not mt.active(WINDOWS[0], datetime(2026, 11, 23, 12, 1).timestamp())
    assert not mt.active(WINDOWS[2], MON_3AM)


def test_a_window_over_midnight():
    w = {"UID": "NIGHT", "TARGET_TYPE": "node", "TARGET": "A", "MODE": "weekly", "DAYS": ["sat"],
         "FROM": "23:00", "TO": "01:00"}
    assert mt.active(w, datetime(2026, 11, 21, 23, 30).timestamp())   # samedi 23 h 30
    assert mt.active(w, datetime(2026, 11, 22, 0, 30).timestamp())    # dimanche 0 h 30 : suite de samedi soir
    assert not mt.active(w, datetime(2026, 11, 22, 23, 30).timestamp())


def test_a_flow_is_in_maintenance_if_one_end_is_or_its_group_is():
    now = SUN_3AM
    m = mt.Maintenance(WINDOWS, now)
    assert m.covers_flow("VOICE", "A", "B") and not m.covers_flow("DATA", "A", "B")
    m2 = mt.Maintenance(WINDOWS, datetime(2026, 11, 23, 11, 0).timestamp())
    assert m2.covers_flow("DATA", "STARLINK", "B") and m2.covers_flow("DATA", "B", "STARLINK")
    assert m2.covers_node("STARLINK") and not m2.covers_node("B")
    assert m2.active_uids() == ["SAT_UPGRADE"]


def test_validation():
    ok = dict(WINDOWS[1])
    assert mt.field_errors(ok, nodes={"STARLINK"}, groups={"VOICE"}) == {}
    bad = dict(ok, TARGET="NOPE", DAYS=["funday"], FROM="25:00")
    assert set(mt.field_errors(bad, nodes={"STARLINK"}, groups={"VOICE"})) == {"TARGET", "DAYS", "FROM"}
    once = dict(WINDOWS[0], END="2026-11-23T09:00")  # fin avant le début
    assert "END" in mt.field_errors(once, nodes={"STARLINK"}, groups=set())

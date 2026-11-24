"""Connexions coupées avant toute authentification (lib/st_preauth.py) : une sonde qui ne reconnaît pas la clé du
serveur (serveur réinstallé) raccroche avant de s'identifier ; le serveur ne voyait que « CONNECTION RESET BY PEER »."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_preauth as pa  # noqa: E402


def test_a_single_drop_is_not_reported():
    d = pa.PreauthDrops()
    assert d.record("10.0.0.7", 1000) is False
    assert d.recent(1001) == []


def test_repeated_drops_are_reported_once_then_every_ten_minutes():
    d = pa.PreauthDrops()
    warns = [d.record("10.0.0.7", 1000 + 10 * i) for i in range(5)]
    assert warns == [False, False, True, False, False]  # au 3e, puis plus avant WARN_EVERY_S
    [r] = d.recent(1050)
    assert r["IP_ADDRESS"] == "10.0.0.7" and r["ATTEMPTS"] == 5 and r["LAST_SEEN"].endswith("+00:00")
    assert d.record("10.0.0.7", 1000 + pa.WARN_EVERY_S + 30) is True  # toujours là 10 minutes plus tard


def test_an_address_that_authenticates_is_forgotten():
    d = pa.PreauthDrops()
    for i in range(4):
        d.record("10.0.0.7", 1000 + i)
    d.forget("10.0.0.7")
    assert d.recent(1010) == []


def test_old_drops_age_out():
    d = pa.PreauthDrops()
    for i in range(4):
        d.record("10.0.0.7", 1000 + i)
    assert d.recent(1000 + pa.WINDOW_S + 10) == []


def test_the_hint_names_the_fix():
    text = pa.hint("10.0.0.7")
    assert "10.0.0.7" in text and "--token" in text and "syntraf_server_pin" in text

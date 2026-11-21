"""Identifiants iperf3 du serveur conservés d'un démarrage à l'autre (lib/st_iperf3_credentials.py).

Régénérés à chaque démarrage, ils obligeaient chaque client à relancer tous ses iperf3 après un
redémarrage du serveur (S7 : trou de mesures sur les flux relancés).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib.st_iperf3_credentials import load_or_create  # noqa: E402

CREDS = {"username": "u", "password": "p", "private_pem": "PRIV", "public_pem": "PUB"}


def test_first_start_generates_and_saves(tmp_path):
    calls = []
    assert load_or_create(tmp_path, lambda: calls.append(1) or dict(CREDS)) == CREDS
    assert calls == [1]


def test_next_start_reuses_saved_credentials(tmp_path):
    load_or_create(tmp_path, lambda: dict(CREDS))
    assert load_or_create(tmp_path, lambda: {"username": "other"}) == CREDS


def test_corrupted_file_is_regenerated(tmp_path):
    load_or_create(tmp_path, lambda: dict(CREDS))
    next(tmp_path.iterdir()).write_text("{pas du json", encoding="utf-8")
    fresh = dict(CREDS, password="new")
    assert load_or_create(tmp_path, lambda: dict(fresh)) == fresh


def test_incomplete_file_is_regenerated(tmp_path):
    load_or_create(tmp_path, lambda: {"username": "u"})
    assert load_or_create(tmp_path, lambda: dict(CREDS)) == CREDS

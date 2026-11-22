"""Valeurs par défaut de la validation de configuration (lib/st_conf_validation.py) : une clé facultative absente
prend sa valeur par défaut sans avertissement ; une valeur invalide est signalée et remplacée.
Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from lib import st_conf_validation as cv
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


def warnings_of(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def database(**over):
    return dict({"DB_UID": "VM_LAB", "DB_ENGINE": "VictoriaMetrics", "DB_SERVER": "10.0.0.10", "DB_PORT": "8428",
                 "DB_SERVER_USE_SSL": False}, **over)


def test_db_mode_is_not_asked_of_victoriametrics(caplog):
    cfg = {"DATABASE": [database()]}
    with caplog.at_level(logging.DEBUG):
        assert cv.config_validation_database(cfg) is not False  # validation menée jusqu'au bout
    assert not [w for w in warnings_of(caplog) if "DB_MODE" in w]
    assert "DB_MODE" not in cfg["DATABASE"][0]


def test_influxdb_without_db_mode_takes_oss_quietly(caplog):
    cfg = {"DATABASE": [database(DB_ENGINE="InfluxDB2", DB_ORG="org", DB_BUCKET="b", DB_TOKEN="t")]}
    with caplog.at_level(logging.DEBUG):
        cv.config_validation_database(cfg)
    assert cfg["DATABASE"][0]["DB_MODE"] == "OSS"
    assert not [w for w in warnings_of(caplog) if "DB_MODE" in w]


def test_an_invalid_influxdb_db_mode_is_reported(caplog):
    cfg = {"DATABASE": [database(DB_ENGINE="InfluxDB2", DB_ORG="org", DB_BUCKET="b", DB_TOKEN="t", DB_MODE="X")]}
    with caplog.at_level(logging.DEBUG):
        cv.config_validation_database(cfg)
    assert cfg["DATABASE"][0]["DB_MODE"] == "OSS"
    assert [w for w in warnings_of(caplog) if "DB_MODE" in w]


@pytest.mark.parametrize("given, expected, warned", [(None, "10", False), ("30", "30", False),
                                                      ("0", "10", True), ("abc", "10", True)])
def test_time_skew_threshold_default_and_invalid_values(caplog, given, expected, warned):
    g = {} if given is None else {"IPERF3_TIME_SKEW_THRESHOLD": given}
    with caplog.at_level(logging.DEBUG):
        cv.validate_time_skew_threshold(g)
    assert g["IPERF3_TIME_SKEW_THRESHOLD"] == expected
    assert bool([w for w in warnings_of(caplog) if "IPERF3_TIME_SKEW_THRESHOLD" in w]) is warned

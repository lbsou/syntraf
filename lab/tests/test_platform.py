"""Portabilité de la sonde (Windows, Linux, macOS) : ce qui dépend du système. Tourne sur l'hôte et dans le lab."""
import signal
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


@pytest.mark.parametrize("name", ["SIGTERM", "SIGINT", "SIGBREAK"])
def test_every_stop_signal_stops_syntraf_cleanly(name, monkeypatch):
    if not hasattr(signal, name):
        pytest.skip(f"{name} does not exist on this system")
    pytest.importorskip("psutil")
    from lib import st_clean_close
    monkeypatch.setattr(st_clean_close, "print_sys", lambda *a, **k: None, raising=False)
    with pytest.raises(SystemExit):
        st_clean_close.handler(getattr(signal, name), None)


def test_local_timezone_has_a_name():
    from lib.st_global import local_timezone_name
    assert local_timezone_name()


# ---------------------------------------------------------------------------------- options de l'iperf3 installé

STOCK_HELP = """Usage: iperf3 [-s|-c host] [options]
  --forceflush              force flushing output at every interval
  --timestamps<=format>     emit a timestamp at the start of each output line
  --bidir                   run in bidirectional mode."""
KEEPALIVE_AUTH_HELP = STOCK_HELP + """
  --cntl-ka[=#/#/#]         use control connection TCP keepalive - KEEPIDLE/KEEPINTV/KEEPCNT
  --rsa-private-key-path    path to the RSA private key used to decrypt authentication credentials
  --authorized-users-path   path to the configuration file containing user credentials
  --username                username for authentication
  --rsa-public-key-path     path to the RSA public key used to encrypt authentication credentials"""


def st_iperf():
    pytest.importorskip("psutil")
    pytest.importorskip("cryptography")
    from lib import st_iperf as mod
    return mod


def test_iperf3_features_are_read_from_its_help():
    mod = st_iperf()
    assert mod.parse_iperf3_features(STOCK_HELP) == set()
    assert mod.parse_iperf3_features(KEEPALIVE_AUTH_HELP) == {"cntl-ka", "auth"}


def test_keepalive_is_only_asked_of_an_iperf3_that_knows_it(monkeypatch):
    mod = st_iperf()
    monkeypatch.setattr(mod, "iperf3_features", lambda binary: set())
    assert mod.keepalive_args("iperf3") == []
    monkeypatch.setattr(mod, "iperf3_features", lambda binary: {"cntl-ka"})
    assert mod.keepalive_args("iperf3") == ["--cntl-ka=10/1/5"]


def test_an_iperf3_that_cannot_be_read_keeps_the_former_arguments(tmp_path):
    mod = st_iperf()
    assert mod.iperf3_features(str(tmp_path / "missing-iperf3")) == {"cntl-ka", "auth"}


def test_logging_starts_without_the_optional_log_size_settings(tmp_path):
    from types import SimpleNamespace
    pytest.importorskip("toml")
    from lib.st_logging import log_init
    from lib.st_conf_validation import validate_purge_logs
    config = {"GLOBAL": {"LOG_TO": "file", "LOG_LEVEL": "INFO"}}
    validate_purge_logs(config)
    log_init(SimpleNamespace(log_dir=str(tmp_path), config_file=str(tmp_path / "c.toml")), config)


def test_the_default_log_file_size_is_twenty_megabytes():
    from lib.st_global import DefaultValues
    assert DefaultValues.DEFAULT_LOG_MAX_SIZE_PER_FILE_MB == 20


# ---------------------------------------------------------------------------------- validation de GLOBAL et iperf3

def validation(monkeypatch, tmp_path, has_auth):
    pytest.importorskip("toml")
    pytest.importorskip("cryptography")
    from lib import st_conf_validation as v
    monkeypatch.setattr(v.DefaultValues, "DEFAULT_IPERF3_RSA_KEY_DIRECTORY", str(tmp_path / "rsa"))
    monkeypatch.setattr(v, "is_iperf3_support_timestamp", lambda c, p: True)
    monkeypatch.setattr(v, "is_iperf3_support_ssl", lambda c, p: has_auth)
    monkeypatch.setattr(v, "is_iperf3_support_skew_threshold", lambda c, p: has_auth)
    binary = tmp_path / "iperf3.exe"
    binary.write_text("fake")
    return v, str(binary)


def test_a_server_without_iperf3_gets_every_global_default(monkeypatch, tmp_path):
    v, _ = validation(monkeypatch, tmp_path, True)
    config = {"GLOBAL": {"IPERF3_BINARY_PATH": "DISABLE"}}
    assert v.config_validation_global(config)
    assert config["GLOBAL"]["IPERF3_RSA_KEY_DIRECTORY"] and config["GLOBAL"]["IPERF3_AUTH"] is True
    assert config["GLOBAL"]["IPERF3_TIME_SKEW_THRESHOLD"]


def test_an_iperf3_without_authentication_is_accepted_when_authentication_is_off(monkeypatch, tmp_path):
    v, binary = validation(monkeypatch, tmp_path, False)
    assert v.config_validation_global({"GLOBAL": {"IPERF3_BINARY_PATH": binary, "IPERF3_AUTH": False}})
    assert not v.config_validation_global({"GLOBAL": {"IPERF3_BINARY_PATH": binary, "IPERF3_AUTH": True}})


def test_iperf3_waits_five_seconds_to_connect_unless_set_otherwise():
    """Un SYN perdu n'est retransmis qu'après 1 s : avec 1 s d'attente, un lien à pertes échouait d'office."""
    mod = st_iperf()
    assert mod.connect_timeout_ms({"GLOBAL": {}}) == "5000"
    assert mod.connect_timeout_ms({"GLOBAL": {"IPERF3_CONNECT_TIMEOUT": "8"}}) == "8000"
    assert mod.connect_timeout_ms({"GLOBAL": {"IPERF3_CONNECT_TIMEOUT": "abc"}}) == "5000"


def test_the_connect_timeout_is_validated_with_a_default(monkeypatch, tmp_path):
    v, _ = validation(monkeypatch, tmp_path, True)
    for given, kept in ((None, "5"), ("0", "5"), ("61", "5"), ("12", "12")):
        g = {"IPERF3_BINARY_PATH": "DISABLE"}
        if given is not None:
            g["IPERF3_CONNECT_TIMEOUT"] = given
        assert v.config_validation_global({"GLOBAL": g})
        assert g["IPERF3_CONNECT_TIMEOUT"] == kept, given


def test_latency_settings_get_defaults(monkeypatch, tmp_path):
    v, _ = validation(monkeypatch, tmp_path, True)
    g = {"IPERF3_BINARY_PATH": "DISABLE"}
    assert v.config_validation_global({"GLOBAL": g})
    assert g["LATENCY"] is True and g["LATENCY_PORT"] == "8620"
    g = {"IPERF3_BINARY_PATH": "DISABLE", "LATENCY_PORT": "0", "LATENCY": "nope"}
    assert v.config_validation_global({"GLOBAL": g})
    assert g["LATENCY"] is True and g["LATENCY_PORT"] == "8620"

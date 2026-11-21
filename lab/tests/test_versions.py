import pytest

import labctl


def test_set_env_value_rewrites_only_target_key(tmp_path):
    f = tmp_path / "lab.env"
    f.write_text("A=1\nIPERF3_REF=3.18\n# c\nB=2\n")
    labctl.set_env_value(f, "IPERF3_REF", "3.19")
    assert f.read_text() == "A=1\nIPERF3_REF=3.19\n# c\nB=2\n"


def test_set_env_value_unknown_key_fails(tmp_path):
    f = tmp_path / "lab.env"
    f.write_text("A=1\n")
    with pytest.raises(KeyError):
        labctl.set_env_value(f, "NOPE", "x")


def test_version_keys_cover_components():
    assert labctl.VERSION_KEYS == {"iperf3": "IPERF3_REF", "python": "PYTHON_VERSION",
                                   "victoriametrics": "VM_VERSION", "grafana": "GRAFANA_VERSION"}

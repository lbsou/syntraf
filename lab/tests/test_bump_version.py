"""Incrément de version à chaque commit (hook .githooks/pre-commit → tools/bump_version.py)."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load():
    spec = importlib.util.spec_from_file_location("bump_version", ROOT / "tools" / "bump_version.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.mark.parametrize("old, part, new", [("0.45", "patch", "0.45.1"), ("0.45.1", "patch", "0.45.2"),
                                            ("0.45.9", "patch", "0.45.10"), ("0.45.3", "minor", "0.46.0"),
                                            ("0.45", "minor", "0.46.0"), ("0.45.3", "major", "1.0.0")])
def test_next_version(old, part, new):
    assert load().next_version(old, part) == new


def test_bump_rewrites_only_the_version_line(tmp_path):
    f = tmp_path / "st_global.py"
    f.write_text('class DefaultValues:\n    SYNTRAF_VERSION = "0.45"\n    OTHER = "0.45"\n', encoding="utf-8")
    assert load().bump(f) == ("0.45", "0.45.1")
    assert f.read_text(encoding="utf-8") == 'class DefaultValues:\n    SYNTRAF_VERSION = "0.45.1"\n    OTHER = "0.45"\n'

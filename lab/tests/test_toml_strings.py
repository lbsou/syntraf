"""Écriture TOML des textes libres (lib/st_toml.py) : toml 0.10.2 écrit mal « \\x » et les caractères de contrôle,
ce qui rendait config.toml illisible (ex. une description « C:\\Users\\xavier »)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
except ImportError:
    pytest.skip("toml absent (lancer dans l'image du lab)", allow_module_level=True)
from lib import st_toml  # noqa: E402

TRICKY = [r"C:\Users\xavier", r"path \x", "\\", "a\\\\b", "x\x01y", "e\x7f", "tab\tand\r\nlines",
          'q"uote', "l'apostrophe", "Québec 🛰️", "\b\f", ""]


@pytest.mark.parametrize("text", TRICKY)
def test_a_string_reads_back_identical(text):
    assert toml.loads(st_toml.dumps({"D": text}))["D"] == text


def test_strings_inside_arrays_of_tables_and_lists_read_back_identical():
    cfg = {"GLOBAL": {"X": r"C:\x"},
           "SERVER_CLIENT": [{"UID": "A", "DESCRIPTION": r"C:\Users\xavier", "MESH_GROUP_UID_LIST": [r"g\x1", "h"],
                              "BEHIND_NAT": True}]}
    assert toml.loads(st_toml.dumps(cfg)) == cfg

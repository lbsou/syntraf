import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# pytest_plugins n'est pas pris en compte dans un conftest qui n'est pas à la racine :
# on importe directement fixtures et hooks.
from lab_fixtures import fault_guard, lab_up, metrics, window  # noqa: E402,F401
from verdict import pytest_addoption, pytest_configure  # noqa: E402,F401

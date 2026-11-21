"""cc_client.asjson() alimente l'API GET_SYSTEM_STATS de la page de statut des clients."""
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib.st_obj_cc_client import cc_client  # noqa: E402


def test_asjson_serializes_datetime_status_since():
    c = cc_client(status="CONNECTED", status_since=datetime(2026, 11, 21, 2, 53, 37),
                  status_explanation="", bool_dynamic_client=False, client_uid="LAB_C1")
    data = json.loads(c.asjson())
    assert data["status"] == "CONNECTED"
    assert data["status_since"] == "2026-11-21 02:53:37"

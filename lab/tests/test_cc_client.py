"""Objet client côté serveur (lib/st_obj_cc_client.py) : chaque client a ses propres statistiques système."""
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib.st_obj_cc_client import cc_client  # noqa: E402


def new(uid):
    return cc_client(status="CONNECTED", status_since=datetime.now(), status_explanation="", bool_dynamic_client=True,
                     client_uid=uid)


def test_a_client_added_while_the_server_runs_has_its_own_statistics():
    """Un client déclaré à chaud (sans init_client_obj_dict) écrivait dans un dictionnaire partagé par la classe,
    que asjson() ne renvoyait pas : la page Clients plantait sur lui et ne dessinait plus les suivants."""
    a, b = new("LTE_5G"), new("OTHER")
    a.system_stats.setdefault("cpu_pct_usage", []).append(("t", 5))
    assert b.system_stats == {} and a.get_thread_status() is not b.get_thread_status()
    assert json.loads(a.asjson())["system_stats"] == {"cpu_pct_usage": [["t", 5]]}
    assert json.loads(b.asjson())["system_stats"] == {}

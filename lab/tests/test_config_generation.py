"""Génération de la config des clients (st_conf_validation), utilisée par la webui quand un mesh group change.

Ces tests demandent les dépendances de SYNTRAF : ils tournent dans l'image du lab (voir run_in_image ci-dessous)
et sont ignorés dans lab/.venv.
  docker run --rm -v <dépôt>:/src -w /src --entrypoint sh syntraf-lab:latest -c \
      "pip install -q pytest && python -m pytest -q lab/tests/test_config_generation.py"
"""
import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from lib import st_conf_validation as v  # noqa: E402
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


def config(**group):
    cfg = {"SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15100"}, "GLOBAL": {},
           "MESH_GROUP": [dict({"UID": "GROUP1", "BANDWIDTH": "100K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}, **group)],
           "SERVER_CLIENT": [{"UID": u, "IP_ADDRESS": ip, "MESH_GROUP_UID_LIST": ["GROUP1"]}
                             for u, ip in (("NODE_A", "10.0.0.1"), ("NODE_B", "10.0.0.2"))]}
    assert v.validate_group(cfg, "MESH_GROUP")
    return cfg


def edges(generated):
    return {uid: (len(c.get('LISTENERS') or {}), len(c.get('CONNECTORS') or {})) for uid, c in generated.items()}


def test_disabling_the_only_group_empties_the_clients_config():
    generated = {}
    cfg = config()
    v.generate_client_config_mesh(cfg, generated)
    assert edges(generated) == {"NODE_A": (1, 1), "NODE_B": (1, 1)}
    cfg["MESH_GROUP"][0]["DISABLED"] = True
    v.generate_client_config_mesh(cfg, generated)
    assert edges(generated) == {"NODE_A": (0, 0), "NODE_B": (0, 0)}


def test_revalidating_an_edited_group_recomputes_pacing():
    # Ce que fait la webui : on repart du groupe tel qu'écrit dans le fichier, puis validate_group.
    raw = {"UID": "GROUP1", "BANDWIDTH": "120K", "DSCP": "0", "PACKET_SIZE": "218", "INTERVAL": "1"}
    cfg = {"MESH_GROUP": [copy.deepcopy(raw)]}
    assert v.validate_group(cfg, "MESH_GROUP")
    assert cfg["MESH_GROUP"][0]["PACKET_PACING"] == int(1_000_000 / int(120_000 / 8 / 218))

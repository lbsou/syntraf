"""Certificat autosigné du client : s'il existe déjà, il est réutilisé, même si le fichier de configuration a perdu
ses chemins (config remise à zéro). Sinon le client changerait de clé, et un client épinglé devrait être
ré-approuvé. Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib import st_conf_validation as v
    from lib.st_global import DefaultValues
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


def start(tmp_path, template):
    """Un démarrage : config écrite depuis le gabarit (comme après une remise à zéro), puis validation du certificat."""
    config_file = tmp_path / "config.toml"
    config_file.write_text(toml.dumps(template))
    config = toml.loads(config_file.read_text())
    assert v.config_validation_certificate(config, "CLIENT", types.SimpleNamespace(config_file=str(config_file))) \
        is not False
    return config, toml.loads(config_file.read_text())


def test_existing_self_signed_key_is_reused_after_a_config_reset(tmp_path, monkeypatch):
    monkeypatch.setattr(DefaultValues, "SYNTRAF_ROOT_DIR", str(tmp_path))
    template = {"CLIENT": {"CLIENT_UID": "NODE_A", "SERVER": "10.0.0.1", "TOKEN": "shared"}}
    first, _ = start(tmp_path, template)
    second, on_disk = start(tmp_path, template)
    assert first["CLIENT"]["PUBLIC_KEY"] and second["CLIENT"]["PUBLIC_KEY"] == first["CLIENT"]["PUBLIC_KEY"]
    assert on_disk["CLIENT"]["PUBLIC_KEY"] == first["CLIENT"]["PUBLIC_KEY"]
    assert Path(on_disk["CLIENT"]["CLIENT_X509_CERTIFICATE"]).is_file()

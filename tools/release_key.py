#!/usr/bin/env python3
"""Clé de signature des releases de SYNTRAF (Ed25519).

    python tools/release_key.py create            # une fois : crée la clé privée, affiche la clé publique
    python tools/release_key.py public            # réaffiche la clé publique

La clé privée reste sur la machine qui publie les releases (défaut : ~/.syntraf/release_signing_key.pem, lisible
par son seul propriétaire ; autre chemin : SYNTRAF_SIGNING_KEY). Elle signe le manifeste de chaque release au
moment de la construire (packaging/build_packages.py). La clé publique est inscrite dans lib/st_github_update.py :
un serveur SYNTRAF n'installe depuis GitHub qu'une release signée par elle. Sauvegardez la clé privée : sans
elle, plus aucune mise à jour automatique n'est possible (il faudrait publier une nouvelle clé publique par une
installation manuelle).
"""
import os
import sys
from pathlib import Path

DEFAULT = Path.home() / ".syntraf" / "release_signing_key.pem"


def key_path():
    return Path(os.environ.get("SYNTRAF_SIGNING_KEY") or DEFAULT)


def load_private():
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(key_path().read_bytes(), password=None)


def public_pem(private):
    from cryptography.hazmat.primitives import serialization
    return private.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def create():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    path = key_path()
    if path.exists():
        sys.exit(f"{path} existe déjà : rien n'est remplacé (une nouvelle clé rendrait les serveurs installés "
                 f"incapables de vérifier les prochaines releases)")
    path.parent.mkdir(parents=True, exist_ok=True)
    key = ed25519.Ed25519PrivateKey.generate()
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    if os.name == "nt":  # lisible du seul utilisateur courant
        os.system(f'icacls "{path}" /inheritance:r /grant:r "%USERNAME%:F" >NUL')
    print(f"clé privée : {path} (à sauvegarder, jamais dans le dépôt)")
    print(public_pem(key))


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("create", "public"):
        sys.exit(__doc__)
    if sys.argv[1] == "create":
        create()
    else:
        print(public_pem(load_private()))

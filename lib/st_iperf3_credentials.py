"""
Identifiants iperf3 du serveur (utilisateur, mot de passe, paire RSA) conservés d'un démarrage à l'autre.

Ils étaient régénérés au hasard à chaque démarrage du serveur : avec IPERF3_AUTH, chaque client devait
alors relancer tous ses iperf3, d'où un trou de mesures après chaque redémarrage du serveur. Ils sont
désormais enregistrés (droits 0600) à côté de la clé TLS du serveur, déjà conservée sur disque.

Bibliothèque standard uniquement.
"""
import json
import os
from pathlib import Path

FILENAME = "iperf3_server_credentials.json"
KEYS = ("username", "password", "private_pem", "public_pem")


def load_or_create(directory, generate) -> dict:
    """Identifiants enregistrés dans directory ; sinon generate() (dict KEYS), enregistrés puis renvoyés."""
    path = Path(directory) / FILENAME
    try:
        creds = json.loads(path.read_text(encoding="utf-8"))
        if all(isinstance(creds.get(k), str) and creds[k] for k in KEYS):
            return {k: creds[k] for k in KEYS}
    except (OSError, ValueError):
        pass
    creds = generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(creds, f)
    return creds

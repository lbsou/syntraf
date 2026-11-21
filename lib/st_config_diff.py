"""
Application sélective de la config reçue du serveur à la (re)connexion d'un client.

Avant : chaque reconnexion au serveur fermait tous les iperf3 du client, même quand rien n'avait
changé ; une simple coupure du canal de contrôle interrompait donc toutes les mesures.
Désormais seuls les listeners et connecteurs supprimés, renommés ou modifiés sont relancés ; tous
le sont si les identifiants iperf3 ont changé alors que l'authentification iperf3 est active.

Bibliothèque standard uniquement.
"""

CREDENTIAL_KEYS = ("IPERF3_USERNAME", "IPERF3_PASSWORD", "IPERF3_HASH")


def _changed(old: dict, new: dict) -> list:
    return [key for key, value in old.items() if new.get(key) != value]


def edges_to_restart(old_config: dict, new_config: dict) -> tuple:
    """(clés de listeners, clés de connecteurs) de old_config à arrêter avant d'appliquer new_config."""
    old_listeners = old_config.get('LISTENERS') or {}
    old_connectors = old_config.get('CONNECTORS') or {}
    auth = (old_config.get('GLOBAL') or {}).get('IPERF3_AUTH') or (new_config.get('GLOBAL') or {}).get('IPERF3_AUTH')
    old_client, new_client = old_config.get('CLIENT') or {}, new_config.get('CLIENT') or {}
    if auth and any(old_client.get(k) != new_client.get(k) for k in CREDENTIAL_KEYS if k in new_client):
        return list(old_listeners), list(old_connectors)
    return (_changed(old_listeners, new_config.get('LISTENERS') or {}),
            _changed(old_connectors, new_config.get('CONNECTORS') or {}))


def reuse_keys(old_edges: dict, new_edges: dict) -> dict:
    """new_edges, où chaque entrée nouvelle au contenu identique à une ancienne entrée disparue garde l'ancienne clé.

    La clé d'un connecteur contient un hash de l'IP de destination : celle d'un client dynamique, mise à jour
    par DIFFCONFIG sans changer la clé, ne correspond plus à la clé régénérée par le serveur. Sans cela, le
    connecteur, pourtant identique, serait arrêté et relancé à chaque reconnexion.
    """
    old_edges = old_edges or {}
    spare = {k: v for k, v in old_edges.items() if k not in new_edges}
    result = {}
    for key, value in new_edges.items():
        if key not in old_edges:
            match = next((k for k, v in spare.items() if v == value), None)
            if match is not None:
                del spare[match]
                key = match
        result[key] = value
    return result

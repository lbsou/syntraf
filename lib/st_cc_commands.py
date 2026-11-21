"""
File des commandes que le serveur envoie aux clients par le canal de contrôle.

dict_of_commands_for_network_clients : {client_uid: [action, ...]}, partagé entre les threads du
serveur (un par client) et la webui. Chaque action est un dict avec au moins la clé "ACTION".

Deux règles, qui corrigent la course au démarrage (une mise à jour d'IP perdue laissait un flux
muet pour toujours) :
  - on ajoute à la file d'un client, on ne la remplace jamais ;
  - le serveur remet une seule action par AWAITING_COMMAND, car le client ne lit qu'une réponse.

Bibliothèque standard uniquement.
"""


def queue_client_ip_update(_config, commands, client_uid, ip_address) -> list:
    """Annonce la nouvelle IP de client_uid à tous les autres clients ; renvoie les UID notifiés.

    Un client qui fixe lui-même l'IP de destination de client_uid (OVERRIDE_DST_NODE_IP) est ignoré.
    """
    notified = []
    for server_client in _config.get('SERVER_CLIENT', []):
        uid = server_client['UID']
        if uid == client_uid:
            continue
        if client_uid in (server_client.get('OVERRIDE_DST_NODE_IP') or ()):
            continue
        commands.setdefault(uid, []).append(
            {"ACTION": "UPDATED_CONFIG", "ELEMENT": "CLIENT_IP", "CLIENT_UID": client_uid, "IP_ADDRESS": ip_address})
        notified.append(uid)
    return notified


def next_command(commands, client_uid):
    """Retire et renvoie la plus ancienne action en attente pour client_uid, ou None."""
    pending = commands.get(client_uid)
    if not pending:
        return None
    return pending.pop(0)

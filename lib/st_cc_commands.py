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


def queue_client_ip_update(_config, commands, client_uid, ip_address, address_for=None) -> list:
    """Annonce la nouvelle IP de client_uid à tous les autres clients ; renvoie les UID notifiés.

    Un client qui fixe lui-même l'IP de destination de client_uid (OVERRIDE_DST_NODE_IP) est ignoré.
    address_for(client) : l'adresse propre à ce pair (lib/st_addresses.py, un pair du même réseau passe par l'adresse
    interne) ; sinon ip_address pour tous.
    """
    notified = []
    for server_client in _config.get('SERVER_CLIENT', []):
        uid = server_client['UID']
        if uid == client_uid:
            continue
        if client_uid in (server_client.get('OVERRIDE_DST_NODE_IP') or ()):
            continue
        address = address_for(server_client) if address_for else ip_address
        commands.setdefault(uid, []).append(
            {"ACTION": "UPDATED_CONFIG", "ELEMENT": "CLIENT_IP", "CLIENT_UID": client_uid, "IP_ADDRESS": address})
        notified.append(uid)
    return notified


def next_command(commands, client_uid):
    """Retire et renvoie la plus ancienne action en attente pour client_uid, ou None."""
    pending = commands.get(client_uid)
    if not pending:
        return None
    return pending.pop(0)


def dynamic_client_uids(_config) -> set:
    """Clients déclarés sans IP (0.0.0.0) dans la config : leur IP n'est connue que lorsqu'ils sont connectés."""
    return {c['UID'] for c in _config.get('SERVER_CLIENT', []) if c.get('IP_ADDRESS') == "0.0.0.0"}


class ForgetScheduler:
    """Oubli différé de l'IP d'un client dynamique déconnecté.

    Oublier l'IP fait arrêter aux autres clients leurs connecteurs vers lui ; après une courte panne, il revient
    presque toujours avec la même IP, et ces connecteurs auraient repris seuls en quelques secondes. On n'oublie
    donc qu'au terme d'un délai de grâce, si le client n'est pas revenu entre-temps.
    """

    def __init__(self):
        self._tokens = {}
        self._next = 0

    def schedule(self, uid) -> int:
        self._next += 1
        self._tokens[uid] = self._next
        return self._next

    def cancel(self, uid) -> None:
        self._tokens.pop(uid, None)

    def should_forget(self, uid, token) -> bool:
        """True une seule fois, et seulement si aucune reconnexion ni nouvelle déconnexion n'a eu lieu depuis."""
        if self._tokens.get(uid) == token:
            del self._tokens[uid]
            return True
        return False

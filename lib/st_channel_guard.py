"""Règles de sécurité du canal de contrôle (port 6531). Bibliothèque standard uniquement.

- Avant une authentification réussie, seule la commande AUTH est acceptée, dans un message court, et l'ensemble
  (poignée de main TLS comprise) doit aboutir avant AUTH_DEADLINE_S : sinon la connexion est fermée.
- Après, un message reste borné (MAX_MESSAGE_BYTES) : la taille annoncée sur 4 octets n'est plus crue sur parole.
- Les connexions simultanées sont limitées, au total et par adresse.
- Un client n'écrit que les mesures dont il est le récepteur (étiquette SERVER = son nom) : il ne peut pas
  fabriquer les séries d'un autre nœud.
- Un texte venu du réseau (nom de client...) est nettoyé avant d'entrer dans un journal : il ne peut pas y forger
  de fausses lignes.
"""
import re
import threading

PREAUTH_COMMANDS = frozenset({"AUTH"})
MAX_PREAUTH_BYTES = 64 * 1024
# Un client resté longtemps sans serveur envoie d'un coup les mesures qu'il a gardées (jusqu'à 86 400 points)
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
AUTH_DEADLINE_S = 30
MAX_CONNECTIONS = 1000
MAX_CONNECTIONS_PER_IP = 50
CLIENT_MEASUREMENTS = frozenset({"SYNTRAF", "SYNTRAF_LATENCY", "SYNTRAF_TCP"})  # mesures, latence, tests TCP
CLEAN_MAX = 120


def allowed(command, authenticated):
    return authenticated or command in PREAUTH_COMMANDS


def max_message_bytes(authenticated):
    return MAX_MESSAGE_BYTES if authenticated else MAX_PREAUTH_BYTES


def authorized_points(points, uid):
    """(points gardés, nombre rejetés) : seuls les points SYNTRAF dont l'étiquette SERVER est uid."""
    if not isinstance(points, list):
        return [], 1
    kept = [p for p in points if isinstance(p, dict) and p.get("measurement") in CLIENT_MEASUREMENTS
            and isinstance(p.get("tags"), dict) and p["tags"].get("SERVER") == uid]
    return kept, len(points) - len(kept)


def clean(text, limit=CLEAN_MAX):
    """Texte venu du réseau, sûr pour un journal : caractères de contrôle remplacés, longueur bornée."""
    text = re.sub(r"[\x00-\x1f\x7f]", "?", str(text))
    return text if len(text) <= limit else text[:limit] + "…"


class ConnectionLimiter:
    def __init__(self, max_total=MAX_CONNECTIONS, max_per_ip=MAX_CONNECTIONS_PER_IP):
        self.max_total, self.max_per_ip = max_total, max_per_ip
        self._by_ip = {}
        self._total = 0
        self._lock = threading.Lock()

    def acquire(self, ip):
        with self._lock:
            if self._total >= self.max_total or self._by_ip.get(ip, 0) >= self.max_per_ip:
                return False
            self._total += 1
            self._by_ip[ip] = self._by_ip.get(ip, 0) + 1
            return True

    def release(self, ip):
        with self._lock:
            if self._by_ip.get(ip):
                self._by_ip[ip] -= 1
                self._total -= 1
                if not self._by_ip[ip]:
                    del self._by_ip[ip]

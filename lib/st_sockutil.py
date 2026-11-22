"""
Lecture fiable et bornée sur le canal de contrôle. Bibliothèque standard uniquement.

sock_rcv lisait la taille puis le message par recv() successifs ; si le pair fermait la connexion
au milieu, recv() renvoyait b'' indéfiniment et le thread tournait à vide sans jamais se terminer.
La taille annoncée (4 octets) est désormais bornée, et une échéance empêche un pair d'occuper un fil
indéfiniment en n'envoyant qu'un octet de temps en temps.
"""
import socket
import struct
import time


class ProtocolViolation(Exception):
    """Message trop long, taille invalide ou échéance dépassée : la connexion doit être fermée."""


def recv_exact(sock, n: int, deadline=None):
    """Lit exactement n octets ; renvoie None si la connexion se ferme avant. deadline : time.monotonic()."""
    data = bytearray()
    while len(data) < n:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolViolation("deadline exceeded")
            sock.settimeout(min(remaining, sock.gettimeout() or remaining))
        try:
            chunk = sock.recv(min(n - len(data), 1 << 20))
        except socket.timeout:
            if deadline is not None and time.monotonic() >= deadline:
                raise ProtocolViolation("deadline exceeded")
            raise
        if not chunk:
            return None
        data += chunk
    return bytes(data)


def recv_message(sock, max_bytes: int, deadline=None):
    """Un message préfixé par sa taille (4 octets, gros-boutiste) ; None si la connexion se ferme."""
    size = recv_exact(sock, 4, deadline)
    if size is None:
        return None
    length = struct.unpack(">l", size)[0]
    if length < 0 or length > max_bytes:
        raise ProtocolViolation(f"message of {length} bytes (limit {max_bytes})")
    return recv_exact(sock, length, deadline)

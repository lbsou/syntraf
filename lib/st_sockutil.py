"""
Lecture fiable sur le canal de contrôle. Bibliothèque standard uniquement.

sock_rcv lisait la taille puis le message par recv() successifs ; si le pair fermait la connexion
au milieu, recv() renvoyait b'' indéfiniment et le thread tournait à vide sans jamais se terminer.
"""


def recv_exact(sock, n: int):
    """Lit exactement n octets ; renvoie None si la connexion se ferme avant."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return bytes(data)

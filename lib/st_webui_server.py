"""Serveur de l'interface web en HTTPS.

Une requête http:// sur le port HTTPS (navigateur, lien sans « s ») faisait échouer la poignée de main TLS : traceback
complète « ssl.SSLError: [SSL: HTTP_REQUEST] » dans le journal à chaque tentative, et rien pour l'utilisateur. Elle
reçoit maintenant une redirection vers https://, à la même adresse et au même chemin. Toute autre poignée de main
ratée (scanner, client qui abandonne) ne laisse qu'une ligne de débogage.
"""
import logging
import re
import socket
import ssl

from gevent.pywsgi import WSGIServer

log = logging.getLogger("syntraf." + __name__)

HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI", b"PATC")
HOST_RE = re.compile(rb"^(?:[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$")
PATH_RE = re.compile(rb"^/[\x21-\x7e]*$")
PEEK_TIMEOUT_S = 10
HEAD_MAX = 8192


def looks_like_http(first):
    """Les premiers octets d'une connexion : une requête HTTP en clair, et non une poignée de main TLS (0x16)."""
    return bytes(first[:4]) in HTTP_METHODS


def _response(status, body, location=None):
    head = [b"HTTP/1.1 " + status]
    if location:
        head.append(b"Location: " + location)
    head += [b"Content-Type: text/plain; charset=utf-8", b"Content-Length: %d" % len(body), b"Connection: close"]
    return b"\r\n".join(head) + b"\r\n\r\n" + body


def redirect_response(head):
    """Réponse à une requête HTTP en clair : 301 vers https://<Host><chemin>, ou 400 si l'en-tête Host est invalide
    (rien de la requête n'entre dans la réponse sans avoir été vérifié : pas d'injection d'en-têtes)."""
    lines = bytes(head).split(b"\r\n")
    parts = lines[0].split(b" ")
    path = parts[1] if len(parts) == 3 and PATH_RE.match(parts[1]) else b"/"
    host = next((line[5:].strip() for line in lines[1:] if line[:5].lower() == b"host:"), b"")
    if not HOST_RE.match(host):
        return _response(b"400 Bad Request", b"This server speaks HTTPS only: use https:// instead.\n")
    location = b"https://" + host + path
    return _response(b"301 Moved Permanently", b"This server speaks HTTPS: " + location + b"\n", location)


class HttpsOnlyServer(WSGIServer):
    """WSGIServer TLS qui redirige le HTTP en clair et ne trace pas les poignées de main ratées."""

    def wrap_socket_and_handle(self, client_socket, address):
        try:
            client_socket.settimeout(PEEK_TIMEOUT_S)
            first = client_socket.recv(4, socket.MSG_PEEK)
            client_socket.settimeout(None)
        except OSError:
            return None
        if looks_like_http(first):
            return self._redirect(client_socket, address)
        try:
            return super().wrap_socket_and_handle(client_socket, address)
        except (ssl.SSLError, OSError) as exc:
            log.debug(f"TLS HANDSHAKE FROM {address[0]} FAILED: {exc}")
            return None

    @staticmethod
    def _redirect(client_socket, address):
        head = b""
        try:
            client_socket.settimeout(PEEK_TIMEOUT_S)
            while b"\r\n\r\n" not in head and len(head) < HEAD_MAX:
                chunk = client_socket.recv(2048)
                if not chunk:
                    break
                head += chunk
            client_socket.sendall(redirect_response(head))
            log.debug(f"PLAIN HTTP REQUEST FROM {address[0]} ON THE HTTPS PORT: REDIRECTED TO HTTPS")
        except OSError:
            pass
        return None

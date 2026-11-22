"""Clients derrière un NAT : détection et maintien de la correspondance NAT du flux de retour.

Un client déclaré BEHIND_NAT n'ouvre aucun port d'écoute : il lance iperf3 --bidir vers chaque pair, et la même
session mesure les deux sens. Le flux de retour (pair → client) arrive sur un port UDP que le client a ouvert en
sortie ; beaucoup de NAT n'entretiennent une correspondance qu'avec le trafic sortant (RFC 4787, REQ-6) : sans
paquet sortant depuis ce port, elle expire (souvent 30 s à 2 min) et le flux de retour est coupé. Un datagramme
vide, envoyé régulièrement depuis ce port vers le pair, la garde ouverte.
"""
import socket
import struct

KEEPALIVE_INTERVAL_S = 15


def nat_detected(observed_ip, local_addresses):
    """True si l'adresse vue par le serveur n'est aucune des adresses du client (il est derrière un NAT) ;
    None si le client n'a pas donné ses adresses (version antérieure)."""
    if not local_addresses:
        return None
    return observed_ip not in set(local_addresses)


def local_ipv4_addresses():
    """Adresses IPv4 des interfaces du client, envoyées au serveur à l'authentification."""
    try:
        import psutil
        return sorted({a.address for addrs in psutil.net_if_addrs().values() for a in addrs
                       if a.family == socket.AF_INET})
    except Exception:  # noqa: BLE001 - simple indication pour le serveur
        return []


def udp_keepalive(src_port, dst_port):
    """En-tête UDP d'un datagramme vide (8 octets, somme de contrôle 0 : facultative en IPv4)."""
    return struct.pack("!HHHH", src_port, dst_port, 8, 0)


def send_keepalive(src_ip, src_port, dst_ip, dst_port):
    """Envoie le datagramme depuis le port du flux de retour, déjà pris par iperf3 : socket brute (Linux, root ou
    CAP_NET_RAW) ; le noyau ajoute l'en-tête IP. Lève OSError si ce n'est pas permis."""
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    try:
        if src_ip:
            s.bind((src_ip, 0))
        s.sendto(udp_keepalive(src_port, dst_port), (dst_ip, 0))
    finally:
        s.close()

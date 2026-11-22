"""Identité des deux bouts du canal de contrôle (port 6531).

- Le client vérifie le serveur : empreinte SHA-256 de sa clé publique (SubjectPublicKeyInfo), donnée dans la
  configuration (CLIENT.SERVER_CERT_SHA256) ou épinglée à la première connexion (fichier à côté de la
  configuration, 0600). Ensuite, un autre serveur est refusé : un homme du milieu ne peut ni voler les jetons ni
  pousser une release. Un certificat renouvelé avec la même clé reste accepté.
- Les releases sont signées par la clé du serveur ; le client vérifie la signature avec la clé épinglée avant
  d'installer quoi que ce soit.
- Le client prouve qu'il détient sa clé privée : AUTH porte une signature de (nom, heure, nonce, empreinte du
  serveur). Elle ne vaut que pour ce serveur, quelques minutes, une seule fois.
"""
import base64
import hashlib
import os
import secrets
import threading
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

PROOF_WINDOW_S = 300


class IdentityError(Exception):
    pass


def pem_to_der(pem):
    if isinstance(pem, str):
        pem = pem.encode()
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


def _spki_der(cert_der):
    cert = x509.load_der_x509_certificate(cert_der)
    return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def spki_sha256(cert_der):
    """Empreinte de la clé publique d'un certificat (DER) : « sha256:<hex> »."""
    return "sha256:" + hashlib.sha256(_spki_der(cert_der)).hexdigest()


def public_key_pem_of_cert(cert_pem_or_der):
    data = cert_pem_or_der.encode() if isinstance(cert_pem_or_der, str) else cert_pem_or_der
    cert = (x509.load_pem_x509_certificate(data) if data.lstrip().startswith(b"-----")
            else x509.load_der_x509_certificate(data))
    return cert.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _normalize(fp):
    fp = (fp or "").strip().lower().replace(":", "")
    return "sha256:" + fp[len("sha256"):] if fp.startswith("sha256") else ("sha256:" + fp if fp else "")


class ServerPin:
    """Empreinte du serveur attendue : configurée, sinon épinglée à la première connexion."""

    def __init__(self, path, configured=""):
        self.path, self.configured = path, _normalize(configured)

    def expected(self):
        if self.configured:
            return self.configured
        try:
            with open(self.path, encoding="utf-8") as f:
                return _normalize(f.read())
        except FileNotFoundError:
            return ""

    def check(self, cert_der):
        """'OK', 'PINNED' (première connexion, empreinte enregistrée) ; IdentityError si ce n'est pas le serveur."""
        actual = spki_sha256(cert_der)
        expected = self.expected()
        if expected:
            if not secrets.compare_digest(actual, expected):
                raise IdentityError(f"SERVER KEY {actual} IS NOT THE EXPECTED {expected}")
            return "OK"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(actual + "\n")
        return "PINNED"


def _load_private(key_pem):
    return serialization.load_pem_private_key(key_pem.encode() if isinstance(key_pem, str) else key_pem,
                                              password=None)


def _sign(key_pem, message):
    key = _load_private(key_pem)
    data = message.encode()
    if isinstance(key, rsa.RSAPrivateKey):
        sig = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                       hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
    else:
        sig = key.sign(data)  # Ed25519
    return base64.b64encode(sig).decode()


def _public_pem_bytes(public_pem):
    """Clé publique PEM ; accepte aussi la forme qu'envoient les clients, repr() d'un bytes (« b'-----BEGIN… »),
    héritée de la configuration (l'empreinte épinglée est calculée sur cette chaîne : elle ne change pas)."""
    if isinstance(public_pem, bytes):
        return public_pem
    text = str(public_pem or "").strip()
    if text[:2] in ("b'", 'b"'):
        import ast
        value = ast.literal_eval(text)
        return value if isinstance(value, bytes) else str(value).encode()
    return text.encode()


def _verify(public_pem, message, signature):
    try:
        key = serialization.load_pem_public_key(_public_pem_bytes(public_pem))
        sig, data = base64.b64decode(signature or "", validate=True), message.encode()
        if not sig:
            return False
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
                       hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(sig, data)
        return True
    except (InvalidSignature, ValueError, TypeError, SyntaxError):
        return False


# --------------------------------------------------------------------------------------------- releases

def _release_message(rid, sha256, size):
    return f"SYNTRAF-RELEASE|{rid}|{sha256}|{int(size)}"


def sign_release(server_key_pem, rid, sha256, size):
    return _sign(server_key_pem, _release_message(rid, sha256, size))


def verify_release(server_public_pem, rid, sha256, size, signature):
    return _verify(server_public_pem, _release_message(rid, sha256, size), signature)


# ---------------------------------------------------------------------------------- preuve du client

def _proof_message(uid, server_fp, stamp, nonce):
    return f"SYNTRAF-AUTH|{uid}|{_normalize(server_fp)}|{int(stamp)}|{nonce}"


def auth_proof(client_key_pem, uid, server_fp, now=None):
    stamp, nonce = int(now if now is not None else time.time()), secrets.token_hex(16)
    return {"TIME": stamp, "NONCE": nonce, "SIGNATURE": _sign(client_key_pem, _proof_message(uid, server_fp, stamp,
                                                                                             nonce))}


class NonceCache:
    """Nonces déjà vus pendant la fenêtre de validité : une preuve ne sert qu'une fois."""

    def __init__(self):
        self._seen, self._lock = {}, threading.Lock()

    def use(self, nonce):
        now = time.monotonic()
        with self._lock:
            for n, t in list(self._seen.items()):
                if now - t > 2 * PROOF_WINDOW_S:
                    del self._seen[n]
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


def check_auth_proof(client_public_pem, uid, server_fp, proof, nonces):
    if not isinstance(proof, dict):
        return False
    try:
        stamp = int(proof.get("TIME"))
    except (TypeError, ValueError):
        return False
    nonce = str(proof.get("NONCE") or "")
    if abs(time.time() - stamp) > PROOF_WINDOW_S or not (16 <= len(nonce) <= 128):
        return False
    if not _verify(client_public_pem, _proof_message(uid, server_fp, stamp, nonce), proof.get("SIGNATURE")):
        return False
    return nonces.use(nonce)

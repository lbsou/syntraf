"""Certificats signés par une autorité (CA d'entreprise ou publique) pour l'interface web (HTTPS) et le canal de
contrôle (port 6531).

1. create_csr : une requête de signature (CSR) avec le nom et les noms alternatifs (DNS, IP) ; la clé privée est
   neuve, ou la clé actuelle (canal de contrôle : la clé reste celle que les sondes ont épinglée). La clé en
   attente est gardée à côté (0600) ; elle ne quitte jamais le serveur.
2. install : le certificat retourné (et sa chaîne) est contrôlé — il porte la clé de la requête, il est valide,
   chaque certificat de la chaîne est émis par le suivant — puis installé : <crypto>/<SERVICE>_X509_CA/.
"""
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import shutil

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from lib.st_files import open_private

SERVICES = ("webui", "control")
KEY_TYPES = {"rsa2048": ("rsa", 2048), "rsa3072": ("rsa", 3072), "rsa4096": ("rsa", 4096), "ec256": ("ec", 256),
             "ec384": ("ec", 384)}
NAME_RE = re.compile(r"^[A-Za-z0-9*.-]{1,253}$")


class CertError(Exception):
    pass


def _check_service(service):
    if service not in SERVICES:
        raise CertError(f"Unknown service '{service}'")


def _new_key(kind):
    family, size = KEY_TYPES.get(kind or "rsa3072", (None, None))
    if family == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=size)
    if family == "ec":
        return ec.generate_private_key(ec.SECP256R1() if size == 256 else ec.SECP384R1())
    raise CertError(f"Unknown key type '{kind}'")


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _spki(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _split_names(names):
    dns, ips = [], []
    for n in names or []:
        n = str(n).strip()
        if not n:
            continue
        try:
            ips.append(ipaddress.ip_address(n))
        except ValueError:
            if not NAME_RE.match(n):
                raise CertError(f"Invalid name '{n}'")
            dns.append(n)
    return dns, ips


def _load_chain(pem_text):
    try:
        certs = x509.load_pem_x509_certificates(pem_text.encode() if isinstance(pem_text, str) else pem_text)
    except (ValueError, TypeError):
        certs = []
    if not certs:
        raise CertError("No certificate found: paste the PEM text (-----BEGIN CERTIFICATE-----...)")
    return certs


def _name(n):
    return n.rfc4514_string()


def describe(pem_text):
    """Résumé d'un certificat (le premier d'une chaîne PEM) pour l'interface."""
    certs = _load_chain(pem_text)
    c = certs[0]
    now = dt.datetime.now(dt.timezone.utc)
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName) + [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        names = []
    return {"SUBJECT": _name(c.subject), "ISSUER": _name(c.issuer), "NAMES": names,
            "NOT_BEFORE": c.not_valid_before_utc.isoformat(), "NOT_AFTER": c.not_valid_after_utc.isoformat(),
            "DAYS_LEFT": (c.not_valid_after_utc - now).days, "SELF_SIGNED": c.issuer == c.subject,
            "CHAIN": len(certs), "SERIAL": format(c.serial_number, "x"),
            "KEY_SHA256": "sha256:" + hashlib.sha256(_spki(c.public_key())).hexdigest()}


def _check_chain(certs):
    for child, parent in zip(certs, certs[1:]):
        try:
            child.verify_directly_issued_by(parent)
        except Exception as exc:  # noqa: BLE001 - signature, nom d'émetteur ou algorithme
            raise CertError(f"The chain is not in order: '{_name(child.subject)}' is not issued by '{_name(parent.subject)}' ({type(exc).__name__})")  # noqa: E501


class CertStore:
    def __init__(self, directory):
        self.directory = directory

    def _dir(self, service):
        _check_service(service)
        return os.path.join(self.directory, f"{service.upper()}_X509_CA")

    def pending_key_path(self, service):
        return os.path.join(self._dir(service), "pending_private_key.pem")

    def installed_paths(self, service):
        d = self._dir(service)
        return os.path.join(d, "certificate.pem"), os.path.join(d, "private_key.pem")

    # ------------------------------------------------------------------------------------- requête
    def create_csr(self, service, common_name, names, organization="", country="", key_type="rsa3072",
                   reuse_key=None):
        common_name = str(common_name or "").strip()
        if not common_name or not NAME_RE.match(common_name):
            raise CertError("A common name is needed (the server's DNS name)")
        country = str(country or "").strip().upper()
        if country and not re.fullmatch(r"[A-Z]{2}", country):
            raise CertError("Country: two letters (e.g. CA, FR)")
        dns, ips = _split_names(list(names or []))
        if common_name not in dns and not _is_ip(common_name):
            dns.insert(0, common_name)  # les navigateurs ne lisent que les noms alternatifs
        if reuse_key:
            with open(reuse_key, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            key = _new_key(key_type)
        attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
        if organization:
            attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, str(organization).strip()[:64]))
        if country:
            attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
        builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(attrs))
        alt = [x509.DNSName(n) for n in dns] + [x509.IPAddress(i) for i in ips]
        if alt:
            builder = builder.add_extension(x509.SubjectAlternativeName(alt), critical=False)
        csr = builder.sign(key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        d = self._dir(service)
        os.makedirs(d, exist_ok=True)
        with open_private(self.pending_key_path(service), "wb") as f:
            f.write(_key_pem(key))
        with open(os.path.join(d, "pending_request.csr"), "w", encoding="utf-8") as f:
            f.write(csr_pem)
        with open(os.path.join(d, "pending.json"), "w", encoding="utf-8") as f:
            json.dump({"created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                       "common_name": common_name, "reused_key": bool(reuse_key)}, f)
        return csr_pem

    def pending(self, service):
        d = self._dir(service)
        try:
            with open(os.path.join(d, "pending_request.csr"), encoding="utf-8") as f:
                csr = f.read()
            with open(os.path.join(d, "pending.json"), encoding="utf-8") as f:
                meta = json.load(f)
        except FileNotFoundError:
            return None
        return {"CSR": csr, "CREATED": meta.get("created"), "COMMON_NAME": meta.get("common_name"),
                "REUSED_KEY": meta.get("reused_key")}

    def cancel(self, service):
        d = self._dir(service)
        for name in ("pending_request.csr", "pending.json", "pending_private_key.pem"):
            try:
                os.remove(os.path.join(d, name))
            except FileNotFoundError:
                pass

    # ------------------------------------------------------------------------------------ installation
    def check(self, service, pem_text):
        """Contrôle le certificat retourné ; renvoie (chaîne, clé en attente PEM)."""
        if self.pending(service) is None:
            raise CertError("No certificate request in progress for this service: generate one first")
        certs = _load_chain(pem_text)
        with open(self.pending_key_path(service), "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if _spki(certs[0].public_key()) != _spki(key.public_key()):
            raise CertError("This certificate is not for the key of the request (another request, or the wrong file)")
        now = dt.datetime.now(dt.timezone.utc)
        if certs[0].not_valid_after_utc <= now:
            raise CertError(f"This certificate expired on {certs[0].not_valid_after_utc:%Y-%m-%d}")
        if certs[0].not_valid_before_utc > now + dt.timedelta(minutes=5):
            raise CertError(f"This certificate is valid only from {certs[0].not_valid_before_utc:%Y-%m-%d %H:%M} UTC")
        _check_chain(certs)
        return certs, _key_pem(key)

    def install(self, service, pem_text):
        certs, key_pem = self.check(service, pem_text)
        cert_file, key_file = self.installed_paths(service)
        for path in (cert_file, key_file):  # l'ancien certificat installé est gardé (.previous)
            if os.path.exists(path):
                shutil.copy2(path, path + ".previous")
        with open_private(key_file, "wb") as f:
            f.write(key_pem)
        with open(cert_file, "wb") as f:
            f.write(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))
        self.cancel(service)
        with open(cert_file, encoding="utf-8") as f:
            return describe(f.read())


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False

# SYNTRAF GLOBAL IMPORT
from lib.st_global import CompilationOptions, DefaultValues
from lib.st_read_toml import read_toml, write_toml

# SYNTRAF SERVER IMPORT
#if not CompilationOptions.client_only:
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from passlib.hash import sha256_crypt

# BUILTIN IMPORT
from datetime import datetime, timedelta
import socket
import logging
import os
import random
import string
import sys

server_log = logging.getLogger("syntraf." + __name__)


# Use by flask to save password to database
def sha256_with_salt_create_hash(password):
    return sha256_crypt.hash(password)


def sha256_with_salt_verify_hash(password, hash):
    return sha256_crypt.verify(password, hash)


def gen_iperf3_password_hash(username, password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # {$user}$password
    # ie : {mario}rossi
    future_hash = "{" + username + "}" + password
    digest.update(future_hash.encode('utf-8'))
    return digest.finalize().hex()


def gen_user_pass_iperf3(log, _config):
    try:
        username_char = string.ascii_letters + string.digits
        password_characters = string.ascii_letters + string.digits + string.punctuation
        username = ''.join(random.sample(username_char, 20))
        #password = ''.join(random.sample(password_characters, 30))
        password = ''.join(random.sample(username_char, 20))
        _config['SERVER']['IPERF3_USERNAME'] = username
        _config['SERVER']['IPERF3_PASSWORD'] = password
    except Exception as exc:
        log.error(f"gen_user_pass_iperf3:{type(exc).__name__}:{exc}", exc_info=True)


def gen_rsa_iperf3(log, _config):
    try:
        path = _config['GLOBAL']['IPERF3_RSA_KEY_DIRECTORY']
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=DefaultValues.DEFAULT_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(os.path.join(path, 'private_key_iperf.pem'), 'wb') as f:
            f.write(private_pem)

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(os.path.join(path, 'public_key_iperf.pem'), 'wb') as f:
            f.write(public_pem)

        _config['SERVER']['RSA_KEY_LISTENERS'] = private_pem
        _config['SERVER']['RSA_KEY_CONNECTORS'] = public_pem

    except Exception as exc:
        log.error(f"gen_cert:{type(exc).__name__}:{exc}", exc_info=True)


def gen_cert(log, path, suffix_filename, parameters, config, type_of_service):
    public_key_pem = ""

    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=DefaultValues.DEFAULT_KEY_SIZE,
            backend=default_backend()
        )

        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        with open(os.path.join(path, "private_key_" + suffix_filename + ".pem"), "wb") as f:
            # Write our private key to disk, will override existing certificate
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"ZZ"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"EARTH"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"EARTH"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OSS"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"SYNTRAF"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 5 years
            datetime.utcnow() + timedelta(days=1825)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(socket.gethostname())]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), default_backend())
        # Write our certificate to disk, will override existing certificate
        with open(os.path.join(path, "certificate_" + suffix_filename + ".pem"), "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        log.info(f"SELF-SIGNED X509 CERTIFICATE (certificate_{suffix_filename}.pem) AND PRIVATE KEY (private_key_{suffix_filename}.pem) WRITTEN IN '{path}'")

    except Exception as exc:
        log.error(f"gen_cert:{type(exc).__name__}:{exc}", exc_info=True)

    #if type_of_service == "CLIENT":
    if not (write_public_key_to_config_file(config, str(public_key_pem), parameters, log, type_of_service)):
        sys.exit()
    if not (write_private_key_path_to_config_file(config, os.path.join(path, "private_key_" + suffix_filename + ".pem"), parameters, log, type_of_service)):
        sys.exit()
    if not (write_certificate_path_to_config_file(config, os.path.join(path, "certificate_" + suffix_filename + ".pem"), parameters, log, type_of_service)):
        sys.exit()


def write_public_key_to_config_file(config, public_key_pem, parameters, log, type_of_service):
    try:
        #if not isinstance(config[type_of_service.upper()], dict):

        config_temp = read_toml(parameters.config_file)
        if not type_of_service.upper() in config_temp:
            config_temp[type_of_service.upper()] = {}
        config_temp[type_of_service]['PUBLIC_KEY'] = public_key_pem
        write_toml(config_temp, parameters.config_file)

        # Make sure we mirror the change in the running conf
        if not type_of_service.upper() in config:
            config[type_of_service.upper()] = {}
        config[type_of_service]['PUBLIC_KEY'] = public_key_pem

    except Exception as exc:
        log.error(f"gen_cert:{type(exc).__name__}:{exc}", exc_info=True)
        return False
    return True


def write_private_key_path_to_config_file(config, private_key_path, parameters, log, type_of_service):
    try:
        if not isinstance(config[type_of_service.upper()], dict):
            config[type_of_service.upper()] = {}
        config_temp = read_toml(parameters.config_file)
        config_temp[type_of_service][f'{type_of_service.upper()}_X509_PRIVATE_KEY'] = private_key_path
        write_toml(config_temp, parameters.config_file)
        config[type_of_service][f'{type_of_service.upper()}_X509_PRIVATE_KEY'] = private_key_path
    except Exception as exc:
        log.error(f"gen_cert:{type(exc).__name__}:{exc}", exc_info=True)
        return False
    return True

def write_certificate_path_to_config_file(config, certificate_path, parameters, log, type_of_service):
    try:
        config_temp = read_toml(parameters.config_file)
        config_temp[type_of_service][f'{type_of_service.upper()}_X509_CERTIFICATE'] = certificate_path
        write_toml(config_temp, parameters.config_file)
        config[type_of_service][f'{type_of_service.upper()}_X509_CERTIFICATE'] = certificate_path
    except Exception as exc:
        log.error(f"gen_cert:{type(exc).__name__}:{exc}", exc_info=True)
        return False
    return True
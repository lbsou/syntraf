"""Identité sur le canal de contrôle (lib/st_identity.py) : empreinte de la clé du serveur, épinglage côté client,
signature des releases et preuve de possession de la clé du client. Tourne dans l'image du lab (cryptography).
"""
import os
import stat
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from lib import st_identity as idt
    from lib.st_crypto import ensure_self_signed
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


@pytest.fixture
def server_cert(tmp_path):
    cert, key = ensure_self_signed(str(tmp_path / "srv"), "server")
    return Path(cert).read_bytes(), Path(key).read_text()


@pytest.fixture
def client_key(tmp_path):
    cert, key = ensure_self_signed(str(tmp_path / "cli"), "client")
    return Path(key).read_text(), idt.public_key_pem_of_cert(Path(cert).read_bytes())


# ---------------------------------------------------------------------------------- épinglage

def test_fingerprint_is_the_sha256_of_the_public_key(server_cert):
    pem, _ = server_cert
    fp = idt.spki_sha256(idt.pem_to_der(pem))
    assert fp.startswith("sha256:") and len(fp) == len("sha256:") + 64


def test_the_first_server_is_pinned_then_another_is_refused(tmp_path, server_cert):
    pem, _ = server_cert
    der = idt.pem_to_der(pem)
    pin = idt.ServerPin(str(tmp_path / "pin"))
    assert pin.check(der) == "PINNED"
    assert pin.check(der) == "OK"
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(tmp_path / "pin").st_mode) == 0o600
    other, _ = ensure_self_signed(str(tmp_path / "other"), "server")
    with pytest.raises(idt.IdentityError):
        pin.check(idt.pem_to_der(Path(other).read_bytes()))


def test_a_configured_fingerprint_wins_and_is_never_overwritten(tmp_path, server_cert):
    pem, _ = server_cert
    der = idt.pem_to_der(pem)
    pin = idt.ServerPin(str(tmp_path / "pin"), configured="sha256:" + "0" * 64)
    with pytest.raises(idt.IdentityError):
        pin.check(der)
    good = idt.ServerPin(str(tmp_path / "pin2"), configured=idt.spki_sha256(der))
    assert good.check(der) == "OK" and not (tmp_path / "pin2").exists()


# ---------------------------------------------------------------------------------- releases signées

def test_a_release_signature_is_checked_with_the_server_key(server_cert):
    pem, key = server_cert
    sig = idt.sign_release(key, "0.45+abc", "f" * 64, 1234)
    pub = idt.public_key_pem_of_cert(pem)
    assert idt.verify_release(pub, "0.45+abc", "f" * 64, 1234, sig)
    assert not idt.verify_release(pub, "0.45+abc", "e" * 64, 1234, sig)   # autre archive
    assert not idt.verify_release(pub, "0.45+abc", "f" * 64, 1234, "")    # pas de signature


# ---------------------------------------------------------------------------------- preuve du client

def test_a_client_proves_it_holds_its_key(client_key, server_cert):
    key, pub = client_key
    server_fp = idt.spki_sha256(idt.pem_to_der(server_cert[0]))
    proof = idt.auth_proof(key, "NODE_A", server_fp)
    seen = idt.NonceCache()
    assert idt.check_auth_proof(pub, "NODE_A", server_fp, proof, seen) is True
    assert idt.check_auth_proof(pub, "NODE_A", server_fp, proof, seen) is False       # rejouée
    assert idt.check_auth_proof(pub, "NODE_B", server_fp, idt.auth_proof(key, "NODE_A", server_fp), seen) is False
    other_fp = "sha256:" + "1" * 64
    assert idt.check_auth_proof(pub, "NODE_A", other_fp, idt.auth_proof(key, "NODE_A", server_fp), seen) is False


def test_an_old_proof_is_refused(client_key, server_cert):
    key, pub = client_key
    server_fp = idt.spki_sha256(idt.pem_to_der(server_cert[0]))
    old = idt.auth_proof(key, "NODE_A", server_fp, now=time.time() - idt.PROOF_WINDOW_S - 60)
    assert idt.check_auth_proof(pub, "NODE_A", server_fp, old, idt.NonceCache()) is False


def test_a_proof_signed_by_another_key_is_refused(tmp_path, client_key, server_cert):
    _, pub = client_key
    other_cert, other_key = ensure_self_signed(str(tmp_path / "x"), "client")
    server_fp = idt.spki_sha256(idt.pem_to_der(server_cert[0]))
    proof = idt.auth_proof(Path(other_key).read_text(), "NODE_A", server_fp)
    assert idt.check_auth_proof(pub, "NODE_A", server_fp, proof, idt.NonceCache()) is False


def test_the_public_key_form_sent_by_real_clients_is_understood(client_key, server_cert):
    # La configuration des clients garde str(bytes) : « b'-----BEGIN PUBLIC KEY-----\n…' »
    key, pub = client_key
    presented = str(pub.encode())
    server_fp = idt.spki_sha256(idt.pem_to_der(server_cert[0]))
    assert idt.check_auth_proof(presented, "NODE_A", server_fp, idt.auth_proof(key, "NODE_A", server_fp),
                                idt.NonceCache()) is True

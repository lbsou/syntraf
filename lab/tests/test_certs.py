"""Certificats signés par une autorité (lib/st_certs.py) : requête de signature (CSR), contrôle du certificat
retourné (clé, validité, chaîne), installation. Tourne dans l'image du lab (cryptography).
"""
import datetime as dt
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from lib import st_certs
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)


# ---------------------------------------------------------------------------------- une petite autorité de test

class CA:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
        now = dt.datetime.now(dt.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                     .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
                     .not_valid_after(now + dt.timedelta(days=3650))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                     .sign(self.key, hashes.SHA256()))

    def sign(self, csr_pem, days=365, not_before=None):
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        now = dt.datetime.now(dt.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.cert.subject)
             .public_key(csr.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(not_before or now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=days)))
        for ext in csr.extensions:
            b = b.add_extension(ext.value, critical=ext.critical)
        leaf = b.sign(self.key, hashes.SHA256())
        return (leaf.public_bytes(serialization.Encoding.PEM) + self.cert.public_bytes(serialization.Encoding.PEM)).decode()


@pytest.fixture
def store(tmp_path):
    return st_certs.CertStore(str(tmp_path / "crypto"))


def test_a_csr_carries_the_names_and_a_new_private_key(store):
    csr_pem = store.create_csr("webui", common_name="syntraf.example.org",
                               names=["syntraf.example.org", "syntraf", "10.0.0.5"], organization="ACME")
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "syntraf.example.org"
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["syntraf.example.org", "syntraf"]
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["10.0.0.5"]
    key_file = store.pending_key_path("webui")
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    assert store.pending("webui")["CSR"] == csr_pem


def test_a_csr_can_reuse_the_current_key(store, tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    current = tmp_path / "current.key"
    current.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    csr_pem = store.create_csr("control", common_name="syntraf", names=[], reuse_key=str(current))
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    assert csr.public_key().public_numbers() == key.public_key().public_numbers()


def test_the_signed_certificate_is_checked_and_installed(store):
    ca = CA()
    csr_pem = store.create_csr("webui", common_name="syntraf.example.org", names=["syntraf.example.org"])
    info = store.install("webui", ca.sign(csr_pem))
    assert info["SUBJECT"].endswith("syntraf.example.org") and info["ISSUER"].endswith("Test Root CA")
    assert info["CHAIN"] == 2 and not info["SELF_SIGNED"]
    cert_file, key_file = store.installed_paths("webui")
    assert Path(cert_file).read_text().count("BEGIN CERTIFICATE") == 2 and os.path.isfile(key_file)
    assert store.pending("webui") is None


def test_a_certificate_for_another_key_is_refused(store):
    ca = CA()
    other = st_certs.CertStore(store.directory + "_other")
    csr_other = other.create_csr("webui", common_name="x", names=[])
    store.create_csr("webui", common_name="syntraf", names=[])
    with pytest.raises(st_certs.CertError) as err:
        store.install("webui", ca.sign(csr_other))
    assert "key" in str(err.value).lower()


def test_expired_garbage_and_missing_request_are_refused(store):
    ca = CA()
    with pytest.raises(st_certs.CertError):
        store.install("webui", "not a certificate")
    with pytest.raises(st_certs.CertError):  # pas de requête en cours
        store.install("webui", ca.sign(st_certs.CertStore(store.directory + "_x").create_csr("webui", "x", [])))
    csr = store.create_csr("webui", common_name="syntraf", names=[])
    with pytest.raises(st_certs.CertError):
        store.install("webui", ca.sign(csr, days=-1, not_before=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=10)))


def test_a_chain_in_the_wrong_order_or_unrelated_is_refused(store):
    ca, stranger = CA(), CA()
    csr = store.create_csr("webui", common_name="syntraf", names=[])
    signed = ca.sign(csr)
    leaf_only = signed.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    bad_chain = leaf_only + stranger.cert.public_bytes(serialization.Encoding.PEM).decode()
    with pytest.raises(st_certs.CertError):
        store.install("webui", bad_chain)


def test_describe_reports_a_self_signed_certificate(store):
    ca = CA()
    info = st_certs.describe(ca.cert.public_bytes(serialization.Encoding.PEM).decode())
    assert info["SELF_SIGNED"] and info["DAYS_LEFT"] > 3000 and info["KEY_SHA256"].startswith("sha256:")


# ---------------------------------------------------------------------------------- opérations (config, audit)

@pytest.fixture
def state(tmp_path):
    import toml
    from lib.st_crypto import ensure_self_signed
    cert, key = ensure_self_signed(str(tmp_path / "crypto" / "SERVER_X509_SELFSIGNED_DIRECTORY"), "server")
    cfg = {"SERVER": {"BIND_ADDRESS": "0.0.0.0", "SERVER_PORT": "6531", "MESH_LISTENERS_PORT_RANGE": "15000-15100",
                      "TOKEN": {"t": "secret"}}, "GLOBAL": {}, "MESH_GROUP": [], "SERVER_CLIENT": []}
    path = tmp_path / "config.toml"
    path.write_text(toml.dumps(cfg))
    live = toml.loads(path.read_text())
    live["SERVER"].update(SERVER_X509_CERTIFICATE=cert, SERVER_X509_PRIVATE_KEY=key)  # en service : autosigné
    return {"config": live, "config_file_path": str(path), "_dict_by_node_generated_config": {},
            "_dict_by_group_of_generated_tuple_for_map": {}, "dict_of_clients": {},
            "dict_of_commands_for_network_clients": {}, "dynamic_uids": set(), "crypto_dir": str(tmp_path / "crypto")}


def test_control_channel_request_keeps_the_pinned_key_by_default(state):
    from lib import st_mesh_group_ops as ops
    overview = ops.certificates(state)
    current_fp = overview["control"]["CURRENT"]["KEY_SHA256"]
    r = ops.certificate_request(state, "control", {"COMMON_NAME": "syntraf.example.org"}, actor="admin")
    csr = x509.load_pem_x509_csr(r["CSR"].encode())
    import hashlib
    assert "sha256:" + hashlib.sha256(csr.public_key().public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest() == current_fp


def test_installing_a_signed_certificate_updates_the_configuration(state):
    import toml
    from lib import st_mesh_group_ops as ops
    ca = CA()
    r = ops.certificate_request(state, "webui", {"COMMON_NAME": "syntraf.example.org", "KEY": "ec256"}, actor="admin")
    preview = ops.install_certificate(state, "webui", {"PEM": ca.sign(r["CSR"])}, actor="admin", dry_run=True)
    assert preview["certificate"]["ISSUER"].endswith("Test Root CA")
    disk = toml.load(state["config_file_path"])
    assert "WEBUI_X509_CERTIFICATE" not in disk["SERVER"]  # aperçu : rien d'écrit
    result = ops.install_certificate(state, "webui", {"PEM": ca.sign(r["CSR"])}, actor="admin")
    disk = toml.load(state["config_file_path"])
    assert disk["SERVER"]["WEBUI_TLS"] is True and os.path.isfile(disk["SERVER"]["WEBUI_X509_CERTIFICATE"])
    assert "SERVER.WEBUI_X509_CERTIFICATE" in result["restart_required"]


def test_a_new_control_key_needs_an_explicit_confirmation(state):
    from lib import st_mesh_group_ops as ops
    ca = CA()
    r = ops.certificate_request(state, "control", {"COMMON_NAME": "syntraf", "KEY": "rsa2048"}, actor="admin")
    with pytest.raises(ops.OpError) as err:
        ops.install_certificate(state, "control", {"PEM": ca.sign(r["CSR"])}, actor="admin")
    assert err.value.status == 409 and "pinned" in err.value.message
    result = ops.install_certificate(state, "control", {"PEM": ca.sign(r["CSR"]), "CONFIRM_NEW_KEY": True},
                                     actor="admin")
    assert "SERVER.SERVER_X509_CERTIFICATE" in result["restart_required"]


def test_certificate_errors_are_field_errors(state):
    from lib import st_mesh_group_ops as ops
    ops.certificate_request(state, "webui", {"COMMON_NAME": "syntraf"}, actor="admin")
    with pytest.raises(ops.OpError) as err:
        ops.install_certificate(state, "webui", {"PEM": "garbage"}, actor="admin")
    assert err.value.status == 400 and "PEM" in err.value.fields

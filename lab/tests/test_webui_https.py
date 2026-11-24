"""Interface web en HTTPS : une requête http:// sur le même port est redirigée vers https:// (avant : traceback
« ssl.SSLError: [SSL: HTTP_REQUEST] » dans le journal à chaque tentative, et rien pour l'utilisateur).
Tourne dans l'image du lab (gevent)."""
import socket
import ssl
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
gevent = pytest.importorskip("gevent")
from lib import st_webui_server as ws  # noqa: E402


def test_the_redirect_keeps_host_port_and_path():
    head = b"GET /alerts.html?x=1 HTTP/1.1\r\nHost: tcn00qubc03351:5000\r\nUser-Agent: x\r\n\r\n"
    answer = ws.redirect_response(head)
    assert answer.startswith(b"HTTP/1.1 301 ")
    assert b"\r\nLocation: https://tcn00qubc03351:5000/alerts.html?x=1\r\n" in answer


def test_a_forged_host_or_path_cannot_inject_headers():
    answer = ws.redirect_response(b"GET /a\r\nSet-Cookie: x HTTP/1.1\r\nHost: evil\r\nX: y\r\n\r\n")
    assert b"Set-Cookie" not in answer
    answer = ws.redirect_response(b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n")
    assert answer.startswith(b"HTTP/1.1 400 ")


def test_plain_http_looks_like_http():
    assert ws.looks_like_http(b"GET ") and ws.looks_like_http(b"POST") and ws.looks_like_http(b"HEAD")
    assert not ws.looks_like_http(b"\x16\x03\x01\x02")  # ClientHello TLS


def _self_signed(tmp_path):
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    c, k = tmp_path / "c.pem", tmp_path / "k.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return str(c), str(k)


def test_the_server_redirects_http_and_still_serves_https(tmp_path):
    cert, key = _self_signed(tmp_path)

    def app(environ, start_response):
        start_response("200 OK", [("Content-Type", "text/plain")])
        return [b"ok"]
    srv = ws.HttpsOnlyServer(("127.0.0.1", 0), app, certfile=cert, keyfile=key, log=None)
    srv.start()
    port = srv.server_port
    try:
        def http_get():
            with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
                s.sendall(f"GET /home.html HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
                return s.recv(4096)

        def https_get():
            ctx = ssl._create_unverified_context()
            with ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=5)) as s:
                s.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while chunk := s.recv(4096):  # jusqu'à la fermeture : en-têtes et corps arrivent séparément
                    data += chunk
                return data
        plain = gevent.get_hub().threadpool.spawn(http_get).get(timeout=10)
        tls = gevent.get_hub().threadpool.spawn(https_get).get(timeout=10)
        assert plain.startswith(b"HTTP/1.1 301 ") and f"Location: https://127.0.0.1:{port}/home.html".encode() in plain
        assert tls.startswith(b"HTTP/1.1 200 ") and tls.endswith(b"ok")
    finally:
        srv.stop()

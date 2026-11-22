"""Renvoi des journaux vers un collecteur syslog, en RFC 5424 ou en CEF (lib/st_syslog.py).
Module sans dépendance : tourne dans lab/.venv.
"""
import datetime as dt
import logging
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib import st_syslog as sl  # noqa: E402

WHEN = dt.datetime(2026, 11, 21, 18, 45, 0, 123000, tzinfo=dt.timezone(dt.timedelta(hours=-5)))


def entry(**over):
    return dict({"time": WHEN, "level": "WARNING", "node": "LAB_C2", "module": "st_mesh", "where": "handle,1008",
                 "type": "control", "message": "SOCKET TIMEOUT: 172.30.0.32"}, **over)


# ---------------------------------------------------------------------------------- formats

def test_rfc5424_line():
    line = sl.format_rfc5424(entry(), facility="local0")
    # PRI = 16 (local0) × 8 + 4 (warning) = 132
    assert line == ("<132>1 2026-11-21T18:45:00.123000-05:00 LAB_C2 syntraf - control - "
                    "st_mesh (handle,1008) - SOCKET TIMEOUT: 172.30.0.32")


def test_rfc5424_severity_and_facility():
    assert sl.format_rfc5424(entry(level="CRITICAL"), facility="user").startswith("<10>1 ")   # 1×8 + 2
    assert sl.format_rfc5424(entry(level="DEBUG"), facility="local7").startswith("<191>1 ")  # 23×8 + 7


def test_rfc5424_header_fields_never_contain_spaces():
    line = sl.format_rfc5424(entry(node="my host", type=""), facility="local0")
    assert " my_host syntraf - - - " in line


def test_cef_line():
    line = sl.format_cef(entry(), facility="local0", version="0.45")
    header, cef = line.split(" - - - ", 1)
    assert header == "<132>1 2026-11-21T18:45:00.123000-05:00 LAB_C2 syntraf"
    assert cef == ("CEF:0|SYNTRAF|SYNTRAF|0.45|control|SOCKET TIMEOUT: 172.30.0.32|6|"
                   "rt=1795304700123 dvchost=LAB_C2 cs1Label=module cs1=st_mesh (handle,1008) "
                   "cs2Label=level cs2=WARNING msg=SOCKET TIMEOUT: 172.30.0.32")


def test_cef_severity_scale():
    assert [sl.cef_severity(l) for l in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")] == [1, 3, 6, 8, 10]


def test_cef_escaping():
    line = sl.format_cef(entry(message="a|b=c\\d\nsecond line"), facility="local0", version="0.45")
    cef = line.split(" - - - ", 1)[1]
    assert "|a\\|b=c\\\\d second line|" in cef               # en-tête : | et \ échappés, une seule ligne
    assert "msg=a|b\\=c\\\\d\\nsecond line" in cef            # extension : = et \ échappés, saut de ligne \n


def test_tcp_frames_use_octet_counting():
    assert sl.frame("<132>1 é", "tcp") == "9 <132>1 é".encode("utf-8")  # longueur en octets (é = 2)
    assert sl.frame("x", "udp") == b"x"


# ---------------------------------------------------------------------------------- réglages

def test_settings_from_global_section():
    s = sl.Settings.from_global({"SYSLOG_HOST": "siem.local", "SYSLOG_PROTOCOL": "TLS", "SYSLOG_FORMAT": "CEF",
                                 "SYSLOG_LEVEL": "error", "SYSLOG_INCLUDE_CLIENTS": False})
    assert (s.host, s.port, s.protocol, s.format, s.level, s.include_clients) == \
           ("siem.local", 6514, "tls", "cef", "ERROR", False)
    assert sl.Settings.from_global({}).enabled is False
    assert sl.Settings.from_global({"SYSLOG_HOST": "h"}).port == 514


def test_settings_errors():
    errors = sl.setting_errors({"SYSLOG_HOST": "h", "SYSLOG_PORT": "70000", "SYSLOG_PROTOCOL": "ftp",
                                "SYSLOG_FORMAT": "json", "SYSLOG_LEVEL": "LOUD", "SYSLOG_FACILITY": "local9",
                                "SYSLOG_TLS_CA": "/no/such/ca.pem"})
    assert set(errors) == {"SYSLOG_PORT", "SYSLOG_PROTOCOL", "SYSLOG_FORMAT", "SYSLOG_LEVEL", "SYSLOG_FACILITY",
                           "SYSLOG_TLS_CA"}
    assert sl.setting_errors({"SYSLOG_HOST": "bad host!"}) == {"SYSLOG_HOST": sl.MESSAGES["SYSLOG_HOST"]}
    assert sl.setting_errors({}) == {}  # sans hôte : renvoi désactivé, rien d'autre n'est exigé


# ---------------------------------------------------------------------------------- envoi

def udp_collector():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    s.settimeout(5)
    return s


def wait_for(predicate, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_udp_delivery_and_level_filter():
    coll = udp_collector()
    fwd = sl.Forwarder()
    try:
        fwd.configure(sl.Settings(host="127.0.0.1", port=coll.getsockname()[1], protocol="udp", level="WARNING"))
        fwd.submit(entry(level="INFO", message="filtered out"))
        fwd.submit(entry(message="kept"))
        data = coll.recv(4096).decode()
        assert data.endswith("kept") and data.startswith("<132>1 ")
        assert wait_for(lambda: fwd.status()["sent"] == 1)
    finally:
        fwd.stop()
        coll.close()


def test_tcp_delivery_is_framed():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    fwd = sl.Forwarder()
    try:
        fwd.version = "0.45"
        fwd.configure(sl.Settings(host="127.0.0.1", port=srv.getsockname()[1], protocol="tcp", format="cef"))
        fwd.submit(entry())
        conn, _ = srv.accept()
        conn.settimeout(5)
        data = b""
        while b"msg=" not in data or not data.endswith(b"172.30.0.32"):
            data += conn.recv(4096)
        length, message = data.split(b" ", 1)
        assert int(length) == len(message) and b"CEF:0|SYNTRAF|SYNTRAF|0.45|" in message
        conn.close()
    finally:
        fwd.stop()
        srv.close()


def test_unreachable_collector_drops_and_never_blocks():
    fwd = sl.Forwarder(capacity=3)
    try:
        fwd.configure(sl.Settings(host="127.0.0.1", port=1, protocol="tcp"))  # rien n'écoute
        started = time.time()
        for i in range(10):
            fwd.submit(entry(message=f"m{i}"))
        assert time.time() - started < 0.5
        assert wait_for(lambda: fwd.status()["last_error"])
        assert fwd.status()["dropped"] >= 7 and fwd.status()["connected"] is False
    finally:
        fwd.stop()


@pytest.fixture
def tls_material(tmp_path):
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                        "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
                        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], capture_output=True)
    if r.returncode:
        pytest.skip("openssl unavailable")
    return key, cert


def test_tls_delivery_with_a_pinned_ca(tls_material):
    key, cert = tls_material
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    received = []

    def serve():
        conn, _ = srv.accept()
        with ctx.wrap_socket(conn, server_side=True) as tls:
            tls.settimeout(5)
            received.append(tls.recv(4096))

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    fwd = sl.Forwarder()
    try:
        fwd.configure(sl.Settings(host="127.0.0.1", port=srv.getsockname()[1], protocol="tls", tls_ca=str(cert)))
        fwd.submit(entry())
        t.join(5)
        assert received and received[0].endswith(b"SOCKET TIMEOUT: 172.30.0.32")
    finally:
        fwd.stop()
        srv.close()


def test_tls_refuses_an_unknown_certificate(tls_material):
    key, cert = tls_material
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(str(cert), str(key))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)

    def serve():
        try:
            conn, _ = srv.accept()
            ctx.wrap_socket(conn, server_side=True)
        except (OSError, ssl.SSLError):
            pass

    threading.Thread(target=serve, daemon=True).start()
    fwd = sl.Forwarder()
    try:
        fwd.configure(sl.Settings(host="127.0.0.1", port=srv.getsockname()[1], protocol="tls"))  # CA du système
        fwd.submit(entry())
        assert wait_for(lambda: "CERTIFICATE" in (fwd.status()["last_error"] or "").upper())
        assert fwd.status()["sent"] == 0
    finally:
        fwd.stop()
        srv.close()


# ---------------------------------------------------------------------------------- sources

def test_server_records_become_entries(monkeypatch):
    fwd = sl.Forwarder()
    fwd.settings = sl.Settings(host="h")
    got = []
    monkeypatch.setattr(fwd, "submit", got.append)
    handler = sl.SyslogHandler(fwd, node="syntraf-server")
    log = logging.getLogger("syntraf.test.syslog")
    log.propagate = False
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    log.error("DATABASE 'VM' IS NOW OFFLINE")
    logging.getLogger("syntraf.lib.st_syslog").addHandler(handler)
    logging.getLogger("syntraf.lib.st_syslog").error("collector down")  # jamais renvoyé : pas de boucle
    assert len(got) == 1
    e = got[0]
    assert (e["node"], e["level"], e["module"], e["message"]) == \
           ("syntraf-server", "ERROR", "test_syslog", "DATABASE 'VM' IS NOW OFFLINE")
    assert e["time"].utcoffset() is not None


def test_client_lines_are_forwarded_with_the_client_as_host(monkeypatch):
    fwd = sl.Forwarder()
    fwd.settings = sl.Settings(host="h", include_clients=True)
    got = []
    monkeypatch.setattr(fwd, "submit", got.append)
    fwd.forward_client_lines("LAB_C2", [
        " 2026-11-21 18:45:00-0500 - WARNING - st_outage (record,89) - LAB_C3__TO__LAB_C2 - OUTAGE\n",
        "Traceback line that continues the previous entry\n",
    ])
    assert len(got) == 1
    assert (got[0]["node"], got[0]["type"], got[0]["level"]) == ("LAB_C2", "measurement", "WARNING")
    assert got[0]["time"] == WHEN.replace(microsecond=0)
    fwd.settings = sl.Settings(host="h", include_clients=False)
    fwd.forward_client_lines("LAB_C2", [" 2026-11-21 18:45:00-0500 - ERROR - st_mesh (a,1) - x\n"])
    assert len(got) == 1

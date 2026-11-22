"""Règles de sécurité du canal de contrôle (port 6531, lib/st_channel_guard.py et lib/st_sockutil.py).
Sans dépendance : tourne dans lab/.venv.
"""
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_channel_guard as guard  # noqa: E402
from lib import st_sockutil  # noqa: E402


# ---------------------------------------------------------------------------------- avant l'authentification

def test_only_auth_is_accepted_before_authentication():
    assert guard.allowed("AUTH", authenticated=False)
    for command in ("SAVE_METRIC", "SAVE_LOGS", "GET_RELEASE_CHUNK", "SYSTEM_INFOS", "AWAITING_COMMAND", "HEARTBEAT"):
        assert not guard.allowed(command, authenticated=False), command
        assert guard.allowed(command, authenticated=True)


def test_message_size_limit_depends_on_authentication():
    assert guard.max_message_bytes(False) == guard.MAX_PREAUTH_BYTES < guard.max_message_bytes(True)


# ---------------------------------------------------------------------------------- réception bornée

def pair():
    a, b = socket.socketpair()
    a.settimeout(5)
    b.settimeout(5)
    return a, b


def test_a_message_above_the_limit_is_refused_without_reading_it():
    a, b = pair()
    b.sendall(struct.pack(">l", 10_000_000))
    with pytest.raises(st_sockutil.ProtocolViolation):
        st_sockutil.recv_message(a, max_bytes=65_536)
    a.close(), b.close()


def test_a_negative_size_is_refused():
    a, b = pair()
    b.sendall(struct.pack(">l", -5))
    with pytest.raises(st_sockutil.ProtocolViolation):
        st_sockutil.recv_message(a, max_bytes=65_536)
    a.close(), b.close()


def test_a_normal_message_is_read():
    a, b = pair()
    b.sendall(struct.pack(">l", 5) + b"hello")
    assert st_sockutil.recv_message(a, max_bytes=65_536) == b"hello"
    a.close(), b.close()


def test_a_peer_trickling_bytes_cannot_outlast_the_deadline():
    a, b = pair()
    stop = threading.Event()

    def trickle():
        b.sendall(struct.pack(">l", 100))
        while not stop.is_set():
            try:
                b.sendall(b"x")  # un octet de temps en temps : chaque recv réussit, le message n'arrive jamais
            except OSError:
                return
            time.sleep(0.05)
    threading.Thread(target=trickle, daemon=True).start()
    started = time.monotonic()
    with pytest.raises(st_sockutil.ProtocolViolation):
        st_sockutil.recv_message(a, max_bytes=65_536, deadline=time.monotonic() + 0.5)
    assert time.monotonic() - started < 2
    stop.set()
    a.close(), b.close()


# ---------------------------------------------------------------------------------- connexions

def test_connections_are_limited_in_total_and_per_address():
    lim = guard.ConnectionLimiter(max_total=3, max_per_ip=2)
    assert lim.acquire("10.0.0.1") and lim.acquire("10.0.0.1")
    assert not lim.acquire("10.0.0.1")           # par adresse
    assert lim.acquire("10.0.0.2")
    assert not lim.acquire("10.0.0.3")           # au total
    lim.release("10.0.0.1")
    assert lim.acquire("10.0.0.3")


# ---------------------------------------------------------------------------------- mesures

def point(server, measurement="SYNTRAF"):
    return {"measurement": measurement, "tags": {"CLIENT": "A", "SERVER": server, "MESH_GROUP": "G"},
            "fields": {"RX_PCT_LOSS": 0.0}, "time": 1}


def test_a_client_only_writes_the_measurements_it_receives():
    kept, dropped = guard.authorized_points([point("NODE_B"), point("NODE_C"), point("NODE_B", "SYNTRAF_CONFIG"),
                                             {"bad": 1}], "NODE_B")
    assert kept == [point("NODE_B")] and dropped == 3


def test_payload_that_is_not_a_list_is_dropped():
    assert guard.authorized_points({"x": 1}, "NODE_B") == ([], 1)


# ---------------------------------------------------------------------------------- journaux

def test_untrusted_text_cannot_forge_log_lines():
    forged = "X\n 2026-11-22 10:00:00+0000 - CRITICAL - st_mesh (a,1) - fake"
    cleaned = guard.clean(forged)
    assert "\n" not in cleaned and len(guard.clean("A" * 500)) <= guard.CLEAN_MAX + 1

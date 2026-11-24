"""Statistiques système des sondes (lib/st_system_stats.py) : interface réseau détectée seule."""
import socket
import sys
from collections import namedtuple
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_system_stats as ss  # noqa: E402

Addr = namedtuple("Addr", "family address netmask broadcast ptp")
ADDRS = {"lo": [Addr(socket.AF_INET, "127.0.0.1", None, None, None)],
         "eth0": [Addr(socket.AF_INET, "172.30.0.31", None, None, None)],
         "eth1": [Addr(socket.AF_INET, "10.99.0.34", None, None, None)]}


def test_without_a_configured_name_the_interface_towards_the_server_is_used():
    assert ss.interface_for_address("10.99.0.34", ADDRS) == "eth1"
    assert ss.interface_for_address("192.0.2.1", ADDRS) is None


def test_the_configured_name_wins_and_an_unknown_one_falls_back_to_detection(monkeypatch):
    monkeypatch.setattr(ss.psutil, "net_if_addrs", lambda: ADDRS)
    monkeypatch.setattr(ss, "local_address_towards", lambda host: "172.30.0.31")
    assert ss.choose_interface({"NETWORK_INTERFACE_NAME": "eth1", "SERVER": "srv"}) == "eth1"
    assert ss.choose_interface({"SERVER": "srv"}) == "eth0"
    assert ss.choose_interface({"NETWORK_INTERFACE_NAME": "wlan9", "SERVER": "srv"}) == "eth0"
    monkeypatch.setattr(ss, "local_address_towards", lambda host: None)
    assert ss.choose_interface({"SERVER": "srv"}) is None

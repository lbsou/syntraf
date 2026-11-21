"""Tests de la file de commandes du canal de contrôle (lib/st_cc_commands.py), sans Docker.

Course au démarrage (rapport du 2026-11-20, § 6) : quand deux clients à IP dynamique s'annoncent
coup sur coup, la mise à jour d'IP du premier ne doit pas être effacée par celle du second.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lib import st_cc_commands as cc  # noqa: E402


def config(**overrides):
    clients = [{"UID": uid, "IP_ADDRESS": ip} for uid, ip in
               (("LAB_C1", "172.30.0.31"), ("LAB_C2", "172.30.0.32"), ("LAB_C3", "0.0.0.0"), ("LAB_C4", "0.0.0.0"))]
    for c in clients:
        c.update(overrides.get(c["UID"], {}))
    return {"SERVER_CLIENT": clients}


def ip_update(uid, ip):
    return {"ACTION": "UPDATED_CONFIG", "ELEMENT": "CLIENT_IP", "CLIENT_UID": uid, "IP_ADDRESS": ip}


def test_two_dynamic_clients_in_a_row_both_reach_fixed_clients():
    commands = {}
    cfg = config()
    cc.queue_client_ip_update(cfg, commands, "LAB_C4", "172.30.0.34")
    cc.queue_client_ip_update(cfg, commands, "LAB_C3", "172.30.0.33")
    for fixed in ("LAB_C1", "LAB_C2"):
        assert commands[fixed] == [ip_update("LAB_C4", "172.30.0.34"), ip_update("LAB_C3", "172.30.0.33")]
    assert commands["LAB_C3"] == [ip_update("LAB_C4", "172.30.0.34")]
    assert commands["LAB_C4"] == [ip_update("LAB_C3", "172.30.0.33")]


def test_pending_command_from_webui_is_kept():
    commands = {"LAB_C1": [{"ACTION": "RESTART_CLIENT"}]}
    cc.queue_client_ip_update(config(), commands, "LAB_C3", "172.30.0.33")
    assert commands["LAB_C1"] == [{"ACTION": "RESTART_CLIENT"}, ip_update("LAB_C3", "172.30.0.33")]


def test_announcing_client_is_not_notified_of_itself():
    commands = {}
    notified = cc.queue_client_ip_update(config(), commands, "LAB_C3", "172.30.0.33")
    assert "LAB_C3" not in commands
    assert notified == ["LAB_C1", "LAB_C2", "LAB_C4"]


def test_client_overriding_the_destination_ip_is_skipped():
    commands = {}
    cfg = config(LAB_C2={"OVERRIDE_DST_NODE_IP": {"LAB_C3": "10.0.0.3"}})
    cc.queue_client_ip_update(cfg, commands, "LAB_C3", "172.30.0.33")
    assert "LAB_C2" not in commands
    assert commands["LAB_C1"] == [ip_update("LAB_C3", "172.30.0.33")]


def test_forget_then_reconnect_keeps_order():
    commands = {}
    cfg = config()
    cc.queue_client_ip_update(cfg, commands, "LAB_C4", "0.0.0.0")
    cc.queue_client_ip_update(cfg, commands, "LAB_C4", "172.30.0.34")
    assert [c["IP_ADDRESS"] for c in commands["LAB_C1"]] == ["0.0.0.0", "172.30.0.34"]


def test_next_command_hands_out_one_command_per_call_in_order():
    commands = {"LAB_C1": [ip_update("LAB_C4", "0.0.0.0"), ip_update("LAB_C4", "172.30.0.34"),
                           ip_update("LAB_C3", "172.30.0.33")]}
    got = [cc.next_command(commands, "LAB_C1") for _ in range(4)]
    assert got == [ip_update("LAB_C4", "0.0.0.0"), ip_update("LAB_C4", "172.30.0.34"),
                   ip_update("LAB_C3", "172.30.0.33"), None]


def test_next_command_for_unknown_client_is_none():
    assert cc.next_command({}, "LAB_C9") is None

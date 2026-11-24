"""Accessibilité entrante des sondes (NAT, pare-feu) : ports ouverts un instant, essais des pairs (lib/st_reach.py)."""
import json
import socket
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_reach as sr  # noqa: E402
from lib import st_twamp  # noqa: E402

NONCE = "00112233445566778899aabbccddeeff"


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------------------------------------------------- validation

def test_actions_are_validated():
    ok = {"ID": "1-abc", "NONCE": NONCE, "START_AT": time.time(), "TCP_PORTS": [15000], "UDP_PORTS": [15000]}
    assert sr.listen_problem(dict(ok, DURATION_S=30)) is None
    assert sr.check_problem(dict(ok, ADDRESS="10.0.0.1", LATENCY_PORT=8620)) is None
    assert sr.listen_problem(dict(ok, DURATION_S=600)) == "bad duration"
    assert sr.listen_problem(dict(ok, NONCE="zz")) == "bad nonce"
    assert sr.listen_problem(dict(ok, TCP_PORTS=[1, 2, 3, 4, 5])) == "bad ports"
    assert sr.listen_problem(dict(ok, TCP_PORTS=["22; rm"])) == "bad ports"
    assert sr.check_problem(dict(ok, ADDRESS="-oProxy")) == "bad address"
    assert sr.check_problem(dict(ok, ADDRESS="h", LATENCY_PORT=70000)) == "bad latency port"


# ----------------------------------------------------------------------------- sonde testée et testeur

def run_listener(command):
    out = {}
    t = threading.Thread(target=lambda: out.update(sr.listen(command)), daemon=True)
    t.start()
    time.sleep(0.3)
    return t, out


def test_open_ports_are_reached_and_closed_ones_refused():
    tcp, udp = free_port(), free_port(socket.SOCK_DGRAM)
    t, listener = run_listener({"ID": "t", "NONCE": NONCE, "START_AT": time.time(), "DURATION_S": 3,
                                "TCP_PORTS": [tcp], "UDP_PORTS": [udp]})
    closed = free_port()
    result = sr.check({"ADDRESS": "127.0.0.1", "NONCE": NONCE, "TCP_PORTS": [tcp, closed], "UDP_PORTS": [udp]},
                      deadline=time.time())
    t.join(5)
    assert result["tcp"][str(tcp)] == "open"
    assert result["tcp"][str(closed)] == "refused"
    assert result["udp"][str(udp)] == "open"
    assert listener["tcp"][str(tcp)] == "listening" and listener["udp"][str(udp)] == "listening"
    assert listener["contacts"][f"tcp:{tcp}"] >= 1 and listener["contacts"][f"udp:{udp}"] >= 1


def test_udp_echo_needs_the_test_nonce_and_never_grows():
    udp = free_port(socket.SOCK_DGRAM)
    t, _ = run_listener({"ID": "t", "NONCE": NONCE, "START_AT": time.time(), "DURATION_S": 2, "TCP_PORTS": [],
                         "UDP_PORTS": [udp]})
    assert sr.try_udp("127.0.0.1", udp, "ff" * 16, timeout=0.6) in ("timeout", "refused")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    pkt = sr.echo_packet(NONCE, 7)
    s.sendto(pkt, ("127.0.0.1", udp))
    assert s.recv(512) == pkt  # même taille : aucune amplification
    s.close()
    t.join(4)


def test_busy_tcp_port_still_counts_as_listening_service():
    busy = socket.socket()
    busy.bind(("0.0.0.0", 0))
    busy.listen(1)
    port = busy.getsockname()[1]
    try:
        result = sr.listen({"ID": "t", "NONCE": NONCE, "START_AT": time.time(), "DURATION_S": 0, "TCP_PORTS": [port],
                            "UDP_PORTS": []})
        assert result["tcp"][str(port)] in ("in_use", "listening")  # Windows sans SO_REUSEADDR : in_use
    finally:
        busy.close()


def test_latency_reflector_admits_the_test_nonce_only_during_the_test():
    refl = st_twamp.Reflector(0, host="127.0.0.1").start()
    refl.set_allowed(set())  # aucun pair connu : seul le jeton du test fait répondre
    try:
        assert sr.try_latency("127.0.0.1", refl.port, NONCE, timeout=0.6) == "timeout"
        st_twamp.admit_test(bytes.fromhex(NONCE), time.time() + 5)
        assert sr.try_latency("127.0.0.1", refl.port, NONCE, timeout=1.5) == "open"
        assert sr.try_latency("127.0.0.1", refl.port, "ab" * 16, timeout=0.6) == "timeout"
        st_twamp.admit_test(bytes.fromhex(NONCE), time.time() - 1)
        assert sr.try_latency("127.0.0.1", refl.port, NONCE, timeout=0.6) == "timeout"
    finally:
        refl.stop()


# ------------------------------------------------------------------------------------------------ serveur

def probes(*connected):
    return {uid: SimpleNamespace(status="CONNECTED", ip_address=f"10.0.0.{i + 1}") for i, uid in enumerate(connected)}


def config(**global_):
    return {"GLOBAL": dict({"LATENCY": True, "LATENCY_PORT": "8620"}, **global_),
            "SERVER": {"MESH_LISTENERS_PORT_RANGE": "15000-15003"},
            "SERVER_CLIENT": [{"UID": "A", "IP_ADDRESS": "10.0.0.1", "MESH_GROUP_UID_LIST": ["G"]},
                              {"UID": "B", "IP_ADDRESS": "0.0.0.0", "MESH_GROUP_UID_LIST": ["G"]},
                              {"UID": "C", "IP_ADDRESS": "10.0.0.3", "MESH_GROUP_UID_LIST": ["OTHER"]},
                              {"UID": "N", "IP_ADDRESS": "0.0.0.0", "BEHIND_NAT": True, "MESH_GROUP_UID_LIST": ["G"]}]}


def test_ports_avoid_the_listeners_of_the_probe():
    generated = {"LISTENERS": {"x": {"PORT": "15000"}, "y": {"PORT": 15001}}}
    ports = sr.plan_ports(config(), {}, generated)
    assert ports["iperf3"] in (15002, 15003) and ports["iperf3_range"] == "15000-15003"
    assert ports["latency"] == 8620 and ports["tcp_test"] is None
    ports = sr.plan_ports(dict(config(LATENCY="false"), TCP_TEST=[{"UID": "t"}]),
                          {"MESH_LISTENERS_PORT_RANGE": "20000-20000"}, None)
    assert ports == {"iperf3": 20000, "iperf3_range": "20000-20000", "latency": None, "tcp_test": 5201}


def test_testers_are_connected_peers_of_the_same_groups_first():
    declared = {c["UID"]: c for c in config()["SERVER_CLIENT"]}
    assert sr.choose_testers("A", declared, probes("A", "B", "C", "N")) == ["B", "N", "C"]
    assert sr.choose_testers("A", declared, probes("A")) == []


def test_address_is_the_one_the_tester_uses_for_its_flows():
    declared = {c["UID"]: c for c in config()["SERVER_CLIENT"]}
    generated = {"N": {"CONNECTORS": {"k": {"UID_SERVER": "A", "DESTINATION_ADDRESS": "203.0.113.5"}}}}
    clients = probes("A", "B")
    assert sr.target_address("N", "A", declared, generated, clients) == "203.0.113.5"
    assert sr.target_address("C", "A", declared, generated, clients) == "10.0.0.1"
    assert sr.target_address("A", "B", declared, generated, clients) == "10.0.0.2"  # dynamique : adresse vue


def test_a_test_goes_to_the_probe_and_its_testers_then_gets_a_verdict(tmp_path):
    store = sr.ReachStore(tmp_path / "reach.json")
    rec = store.request("A", "manual", now=1000)
    commands = {}
    sr.tick(config(REACHABILITY_CHECK="false"), probes("A", "B", "N"), {}, commands, store, now=1000)
    listen = commands["A"][0]
    assert listen["ACTION"] == "REACH_LISTEN" and sr.listen_problem(listen) is None
    checks = {uid: commands[uid][0] for uid in ("B", "N")}
    assert all(c["ACTION"] == "REACH_CHECK" and c["ADDRESS"] == "10.0.0.1" and sr.check_problem(c) is None
               for c in checks.values())
    port = listen["UDP_PORTS"][0]
    p = str(port)
    assert store.file(rec["id"], "A", "listen", {"tcp": {p: "listening"}, "udp": {p: "listening"},
                                                 "latency": "listening"})
    assert not store.file(rec["id"], "C", "check", {})  # pas un testeur de ce test
    store.file(rec["id"], "B", "check", {"tcp": {p: "open"}, "udp": {p: "timeout"}, "latency": "timeout"})
    store.file(rec["id"], "N", "check", {"tcp": {p: "open"}, "udp": {p: "timeout"}, "latency": "timeout"})
    done = store.get(rec["id"])
    assert done["status"] == "done" and done["verdict"] == "partial"
    assert done["services"]["iperf3_tcp"]["state"] == "open"
    assert done["services"]["iperf3_udp"] == {"port": port, "state": "blocked", "detail": "timeout"}
    assert sr.summary(done)["testers"] == ["B", "N"]
    assert sr.ReachStore(tmp_path / "reach.json").get(rec["id"])["verdict"] == "partial"  # gardé sur disque


def test_missing_results_end_the_test_and_an_old_probe_gives_unknown(tmp_path):
    store = sr.ReachStore(tmp_path / "reach.json")
    rec = store.request("A", "manual", now=1000)
    sr.tick(config(REACHABILITY_CHECK="false"), probes("A", "B"), {}, {}, store, now=1000)
    store.expire(1000 + sr.START_DELAY_S + sr.RESULT_TIMEOUT_S + 1)
    done = store.get(rec["id"])
    assert done["status"] == "done" and done["verdict"] == "unknown" and done["error"] == "no answer from the probe"
    assert done["testers"]["B"]["status"] == "no result"


def test_all_blocked_and_the_server_tests_alone_when_no_peer(tmp_path):
    store = sr.ReachStore(tmp_path / "reach.json")
    rec = store.request("A", "manual", now=1000)
    asked = []
    sr.tick(config(REACHABILITY_CHECK="false"), probes("A"), {}, {}, store, now=1000,
            server_check=lambda st, rid, cmd: asked.append(cmd))
    assert asked and asked[0]["ADDRESS"] == "10.0.0.1"
    p = str(asked[0]["TCP_PORTS"][0])
    store.file(rec["id"], "A", "listen", {"tcp": {p: "listening"}, "udp": {p: "listening"}, "latency": "listening"})
    store.file(rec["id"], sr.SERVER_TESTER, "check", {"tcp": {p: "timeout"}, "udp": {p: "timeout"}, "latency": "refused"})
    assert store.get(rec["id"])["verdict"] == "blocked"


def test_unconnected_probe_fails_at_once(tmp_path):
    store = sr.ReachStore(tmp_path / "reach.json")
    rec = store.request("C", "manual", now=1000)
    sr.tick(config(REACHABILITY_CHECK="false"), probes("A"), {}, {}, store, now=1000)
    assert store.get(rec["id"])["status"] == "failed"


def test_automatic_tests_settle_skip_outbound_only_and_repeat(tmp_path):
    store = sr.ReachStore(tmp_path / "reach.json")
    cfg = config()
    clients = probes("A", "N")
    sr.tick(cfg, clients, {}, {}, store, now=1000)
    assert store.list() == []  # une minute pour installer ses flux
    sr.tick(cfg, clients, {}, {}, store, now=1000 + sr.AUTO_SETTLE_S)
    assert [r["target"] for r in store.list()] == ["A"]  # N : sortant seulement, pas testé d'office
    store.update(store.list()[0]["id"], status="done", verdict="open")
    sr.tick(cfg, clients, {}, {}, store, now=1000 + sr.AUTO_SETTLE_S + 10)
    sr.tick(cfg, clients, {}, {}, store, now=1000 + sr.AUTO_SETTLE_S + sr.AUTO_RETRY_S + 1)
    assert len(store.list()) == 1  # conclu : rien avant AUTO_EVERY_S
    clients["A"].ip_address = "10.9.9.9"  # nouvelle adresse : nouveau test
    sr.tick(cfg, clients, {}, {}, store, now=1000 + sr.AUTO_SETTLE_S + 20)
    assert len(store.list()) == 2
    sr.tick(config(REACHABILITY_CHECK="false"), probes("A", "C"), {}, {}, sr.ReachStore(tmp_path / "x.json"), now=9e9)


def test_inconclusive_automatic_test_is_retried_sooner(tmp_path):
    store = sr.ReachStore(tmp_path / "reach.json")
    cfg, clients = config(), probes("A")
    sr.tick(cfg, clients, {}, {}, store, now=1000)
    sr.tick(cfg, clients, {}, {}, store, now=1000 + sr.AUTO_SETTLE_S)
    store.update(store.list()[0]["id"], status="done", verdict="unknown")  # sonde muette, résultats perdus
    sr.tick(cfg, clients, {}, {}, store, now=1000 + sr.AUTO_SETTLE_S + sr.AUTO_RETRY_S - 5)
    assert len(store.list()) == 1
    sr.tick(cfg, clients, {}, {}, store, now=1000 + sr.AUTO_SETTLE_S + sr.AUTO_RETRY_S + 5)
    assert len(store.list()) == 2


def test_results_are_filed_and_kept_out_of_the_database(tmp_path):
    store = sr.ReachStore(tmp_path / "reach.json")
    rec = store.request("A", "manual", now=1000)
    sr.tick(config(REACHABILITY_CHECK="false"), probes("A", "B"), {}, {}, store, now=1000)
    other = {"measurement": "SYNTRAF_LATENCY", "tags": {}, "fields": {"RTT_MS": 1}}
    pt = sr.point("A", {"ID": rec["id"]}, "listen", {"tcp": {}, "udp": {}, "latency": None}, 1000)
    assert json.loads(pt["fields"]["RESULT"]) == {"tcp": {}, "udp": {}, "latency": None}
    assert sr.receive([other, pt], store, reporter="A") == [other]
    assert store.get(rec["id"])["listener"] is not None
    assert sr.receive([pt], store, reporter="B") == []  # pas sa part du test : ignoré


def test_results_pass_the_channel_guard():
    """Le serveur ne garde que les mesures connues d'une sonde : les résultats du test doivent passer la garde."""
    from lib import st_channel_guard as guard
    p = sr.point("LAB_C1", {"ID": "1-abc"}, "check", {"tcp": {}}, 1795521981)
    kept, dropped = guard.authorized_points([p], "LAB_C1")
    assert kept == [p] and dropped == 0
    assert guard.authorized_points([p], "LAB_C2") == ([], 1)  # jamais au nom d'une autre sonde

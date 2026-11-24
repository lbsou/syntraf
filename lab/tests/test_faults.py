from lablib import faults


def test_netem_uses_replace_and_values():
    cmds = faults.netem_cmds("eth0", delay_ms=200, loss_pct=10)
    assert cmds == [["tc", "qdisc", "replace", "dev", "eth0", "root", "netem", "delay", "200ms", "loss", "10%"]]


def test_netem_jitter_keeps_packet_order_with_a_rate():
    """Gigue sans réordonnancement (comme un vrai lien) : avec un débit, netem garde l'ordre des paquets."""
    assert faults.netem_cmds("eth1", delay_ms=100, jitter_ms=20) == [
        ["tc", "qdisc", "replace", "dev", "eth1", "root", "netem", "delay", "100ms", "20ms", "rate", "1gbit"]]
    assert faults.netem_cmds("eth1", delay_ms=100, jitter_ms=20, rate="1mbit")[0][-2:] == ["rate", "1mbit"]


def test_netem_jitter_may_reorder_on_request():
    cmds = faults.netem_cmds("eth1", delay_ms=100, jitter_ms=20, reorder=True)
    assert cmds == [["tc", "qdisc", "replace", "dev", "eth1", "root", "netem", "delay", "100ms", "20ms"]]


def test_netem_to_ip_with_jitter_keeps_order_too():
    cmds = faults.netem_cmds("eth0", delay_ms=50, jitter_ms=10, to_ip="172.30.0.33")
    assert cmds[1][-2:] == ["rate", "1gbit"]


def test_netem_to_ip_adds_prio_and_filter():
    cmds = faults.netem_cmds("eth0", delay_ms=50, to_ip="172.30.0.33")
    assert cmds[0][:6] == ["tc", "qdisc", "replace", "dev", "eth0", "root"] and "prio" in cmds[0]
    assert "netem" in cmds[1] and "1:4" in cmds[1]
    assert "172.30.0.33/32" in cmds[-1] and cmds[-1][:2] == ["tc", "filter"]


def test_drop_rules_are_tagged():
    cmds = faults.drop_cmds()
    assert len(cmds) == 2
    assert all("syntraf-lab" in c and c[-2:] == ["-j", "DROP"] for c in cmds)


def test_drop_to_ip_restricts_both_directions():
    cmds = faults.drop_cmds("172.30.0.20")
    assert ["-s", "172.30.0.20"] == cmds[0][cmds[0].index("-s"):cmds[0].index("-s") + 2]
    assert ["-d", "172.30.0.20"] == cmds[1][cmds[1].index("-d"):cmds[1].index("-d") + 2]


def test_heal_cmds_remove_qdisc_and_tagged_rules_only():
    cmds = faults.heal_cmds("eth0")
    assert ["tc", "qdisc", "del", "dev", "eth0", "root"] in cmds
    assert any("syntraf-lab" in " ".join(c) and "iptables-restore" in " ".join(c) for c in cmds)


def test_parse_lab_iface():
    out = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
           "52: eth1@if53    inet 172.30.0.33/24 brd 172.30.0.255 scope global eth1\\       valid_lft forever\n")
    assert faults.parse_lab_iface(out) == "eth1"


def test_parse_lab_iface_absent():
    assert faults.parse_lab_iface("1: lo    inet 127.0.0.1/8 scope host lo\n") is None


def test_remark_rewrites_the_dscp_like_a_router_would_and_heals_with_the_rest():
    cmds = faults.remark_cmds(8)
    assert cmds == [["iptables", "-t", "mangle", "-A", "POSTROUTING", "-m", "comment", "--comment", faults.TAG,
                     "-j", "DSCP", "--set-dscp", "8"]]
    to = faults.remark_cmds(0, to_ip="10.0.0.2")[0]
    assert to[to.index("-d") + 1] == "10.0.0.2" and to[-1] == "0"


def _fake_docker(monkeypatch):
    """Docker simulé : chaque conteneur tourne, sur son réseau, avec eth0 ; les commandes passées sont notées."""
    from types import SimpleNamespace
    from lablib import topology
    calls = []

    def exec_(service, cmd, check=True):
        calls.append((service, cmd))
        prefix = topology.subnet_prefix(service)
        return SimpleNamespace(stdout=f"2: eth0    inet {prefix}9/24 brd {prefix}255 scope global eth0\n")
    monkeypatch.setattr(faults.docker, "exec_", exec_)
    monkeypatch.setattr(faults.docker, "inspect_state", lambda s: {"running": True, "paused": False,
                                                                   "networks": [topology.network_of(s)]})
    return calls


def test_heal_puts_back_the_permanent_link_profile_of_a_satellite_or_mobile_site(monkeypatch):
    """Starlink et 5G/LTE ont un profil de lien permanent : retirer une panne ne doit pas l'effacer."""
    calls = _fake_docker(monkeypatch)
    faults.heal("starlink-gw")
    netem = [c for s, c in calls if "netem" in c]
    assert netem and all(v in netem[-1] for v in ("30ms", "12ms", "0.5%"))


def test_heal_leaves_an_ordinary_node_clean(monkeypatch):
    calls = _fake_docker(monkeypatch)
    faults.heal("c1")
    assert not [c for s, c in calls if "netem" in c]


def test_every_permanent_profile_targets_a_known_lab_service():
    from lablib import topology
    assert set(topology.LINK_PROFILES) == {"c4", "starlink-gw", "c5", "mobile-gw"}
    assert topology.LINK_PROFILES["c5"] == {"delay_ms": 22, "jitter_ms": 8, "loss_pct": 0.8, "rate": "20mbit"}

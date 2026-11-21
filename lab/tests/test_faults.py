from lablib import faults


def test_netem_uses_replace_and_values():
    cmds = faults.netem_cmds("eth0", delay_ms=200, loss_pct=10)
    assert cmds == [["tc", "qdisc", "replace", "dev", "eth0", "root", "netem", "delay", "200ms", "loss", "10%"]]


def test_netem_jitter_and_rate():
    cmds = faults.netem_cmds("eth1", delay_ms=100, jitter_ms=20, rate="1mbit")
    assert cmds == [["tc", "qdisc", "replace", "dev", "eth1", "root", "netem",
                     "delay", "100ms", "20ms", "rate", "1mbit"]]


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

from lablib import topology


def test_expected_flows_is_full_mesh_of_four():
    flows = topology.expected_flows()
    assert len(flows) == 12
    assert len(set(flows)) == 12
    assert "LAB_C1__TO__LAB_C2__ON__DSCP0" in flows
    assert not any(f.startswith("LAB_C1__TO__LAB_C1") for f in flows)


def test_flows_involving_from_and_to():
    assert len(topology.flows_involving("LAB_C3", "from")) == 3
    assert len(topology.flows_involving("LAB_C3", "to")) == 3
    assert len(topology.flows_involving("LAB_C3", "both")) == 6
    assert all(f.startswith("LAB_C3__TO__") for f in topology.flows_involving("LAB_C3", "from"))


def test_container_names_are_prefixed():
    assert topology.container("c1") == "syntraf-lab-c1"


def test_addressing_modes_and_ips():
    assert topology.SERVICES["server"] == "172.30.0.20"
    assert topology.SERVICES["c4"] == "172.30.0.34"
    assert topology.FIXED == ("c1", "c2") and topology.DYNAMIC == ("c3", "c4")
    assert topology.RECOVERY_S == 2 * topology.INTERVAL + topology.WATCHDOG + 10 == 14

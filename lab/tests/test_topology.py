from lablib import topology


def test_expected_flows_is_full_mesh_of_five_without_the_nat_to_nat_pair():
    flows = topology.expected_flows()
    assert len(flows) == 18  # 5 × 4, moins STARLINK ↔ LTE_5G : deux sondes derrière un NAT ne se joignent pas
    assert len(set(flows)) == 18
    assert "STARLINK__TO__LTE_5G__ON__DSCP0" not in flows and "LTE_5G__TO__STARLINK__ON__DSCP0" not in flows
    assert "LTE_5G__TO__LAB_C1__ON__DSCP0" in flows
    assert "LAB_C1__TO__LAB_C2__ON__DSCP0" in flows
    assert not any(f.startswith("LAB_C1__TO__LAB_C1") for f in flows)


def test_flows_involving_from_and_to():
    assert len(topology.flows_involving("LAB_C3", "from")) == 4
    assert len(topology.flows_involving("LAB_C3", "to")) == 4
    assert len(topology.flows_involving("LAB_C3", "both")) == 8
    assert all(f.startswith("LAB_C3__TO__") for f in topology.flows_involving("LAB_C3", "from"))


def test_container_names_are_prefixed():
    assert topology.container("c1") == "syntraf-lab-c1"


def test_addressing_modes_and_ips():
    assert topology.SERVICES["server"] == "172.30.0.20"
    # c4 (STARLINK) est derrière le routeur NAT starlink-gw, sur son propre réseau
    assert topology.SERVICES["c4"] == "10.99.0.34" and topology.network_of("c4") == "syntraf_starlink_lan"
    assert topology.subnet_prefix("c4") == "10.99.0." and topology.subnet_prefix("c1") == "172.30.0."
    assert topology.FIXED == ("c1", "c2") and topology.DYNAMIC == ("c3", "c4", "c5")
    # c5 (LTE_5G) : derrière son propre routeur NAT, comme le CGNAT d'un opérateur mobile
    assert topology.SERVICES["c5"] == "10.98.0.35" and topology.network_of("c5") == "syntraf_mobile_lan"
    assert topology.subnet_prefix("c5") == "10.98.0." and topology.network_of("mobile-gw") == "syntraf_mobile_lan"
    assert topology.GATEWAY_OF == {"c4": "starlink-gw", "c5": "mobile-gw"}
    assert {"starlink-gw", "mobile-gw"} <= set(topology.FAULT_TARGETS)
    assert topology.RECOVERY_S == 2 * topology.INTERVAL + topology.WATCHDOG + 10 == 14

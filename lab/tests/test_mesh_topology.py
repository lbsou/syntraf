"""Topologies d'un mesh group (lib/st_topology.py) : maillage complet, hub & spoke, deux hubs.
Module sans dépendance : tourne dans lab/.venv.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib import st_topology as topo  # noqa: E402

MEMBERS = ["A1", "B1", "C1", "D1", "E1"]


def pairs(group, members=MEMBERS):
    return {(a, b) for i, a in enumerate(members) for b in members[i + 1:] if topo.allows(group, a, b)}


def test_a_group_without_topology_is_a_full_mesh():
    assert len(pairs({"UID": "G"})) == 10
    assert topo.topology({"UID": "G"}) == "MESH"


def test_hub_and_spoke_links_every_member_to_the_hub_only():
    p = pairs({"TOPOLOGY": "HUB_SPOKE", "HUBS": ["A1"]})
    assert p == {("A1", m) for m in MEMBERS[1:]}


def test_dual_hub_links_every_member_to_both_hubs_and_the_hubs_together():
    p = pairs({"TOPOLOGY": "DUAL_HUB", "HUBS": ["A1", "B1"]})
    assert ("A1", "B1") in p and ("C1", "D1") not in p
    assert len(p) == 1 + 2 * 3


@pytest.mark.parametrize("topology,hubs,flows", [("MESH", [], 20), ("HUB_SPOKE", ["A1"], 8), ("DUAL_HUB", ["A1", "B1"], 14)])
def test_flow_counts_match_the_pairs(topology, hubs, flows):
    group = {"TOPOLOGY": topology, "HUBS": hubs}
    assert topo.flow_count(group, len(MEMBERS)) == flows == 2 * len(pairs(group))


def test_outgoing_flows_per_role():
    assert topo.outgoing({"TOPOLOGY": "MESH"}, 5) == {"member": 4}
    assert topo.outgoing({"TOPOLOGY": "HUB_SPOKE", "HUBS": ["A1"]}, 5) == {"hub": 4, "spoke": 1}
    assert topo.outgoing({"TOPOLOGY": "DUAL_HUB", "HUBS": ["A1", "B1"]}, 5) == {"hub": 4, "spoke": 2}


def test_errors():
    assert topo.errors({"TOPOLOGY": "STAR"}, MEMBERS) == {"TOPOLOGY": "MESH, HUB_SPOKE or DUAL_HUB"}
    assert "HUBS" in topo.errors({"TOPOLOGY": "HUB_SPOKE", "HUBS": []}, MEMBERS)
    assert "HUBS" in topo.errors({"TOPOLOGY": "DUAL_HUB", "HUBS": ["A1", "A1"]}, MEMBERS)
    assert "HUBS" in topo.errors({"TOPOLOGY": "HUB_SPOKE", "HUBS": ["Z9"]}, MEMBERS)
    assert topo.errors({"TOPOLOGY": "HUB_SPOKE", "HUBS": ["Z9"]}, None) == {}  # appartenance non vérifiable
    assert topo.errors({"TOPOLOGY": "DUAL_HUB", "HUBS": ["A1", "B1"]}, MEMBERS) == {}
    assert topo.errors({"TOPOLOGY": "MESH", "HUBS": ["A1"]}, MEMBERS) == {"HUBS": "A full mesh has no hub"}

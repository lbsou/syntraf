"""Topologie d'un mesh group : quelles paires de membres se mesurent.

  MESH       maillage complet : toutes les paires (défaut, et cas des groupes existants sans clé TOPOLOGY)
  HUB_SPOKE  chaque membre avec le hub (HUBS = [un membre])
  DUAL_HUB   chaque membre avec chacun des deux hubs, et les hubs entre eux (HUBS = [deux membres])

Chaque paire retenue donne un flux dans chaque sens. Module sans dépendance externe.
"""
TOPOLOGIES = ("MESH", "HUB_SPOKE", "DUAL_HUB")
HUB_COUNT = {"MESH": 0, "HUB_SPOKE": 1, "DUAL_HUB": 2}


def topology(group):
    return str(group.get("TOPOLOGY") or "MESH").upper()


def hubs(group):
    return list(group.get("HUBS") or [])


def allows(group, a, b):
    """La paire (a, b) de membres du groupe se mesure-t-elle ?"""
    if topology(group) == "MESH":
        return True
    h = set(hubs(group))
    return a in h or b in h


def outgoing(group, members):
    """Flux sortants par membre selon son rôle (débit à multiplier par la bande passante du groupe)."""
    t = topology(group)
    if t == "MESH":
        return {"member": max(members - 1, 0)}
    return {"hub": max(members - 1, 0), "spoke": HUB_COUNT[t]}


def flow_count(group, members):
    """Nombre total de flux (un par sens) pour `members` membres."""
    t = topology(group)
    if members < 2:
        return 0
    if t == "MESH":
        return members * (members - 1)
    k = HUB_COUNT[t]
    pairs = k * (members - k) + k * (k - 1) // 2
    return 2 * pairs


def errors(group, members):
    """{"TOPOLOGY" | "HUBS": message} ; members=None : appartenance des hubs non vérifiée."""
    t = topology(group)
    if t not in TOPOLOGIES:
        return {"TOPOLOGY": "MESH, HUB_SPOKE or DUAL_HUB"}
    h = hubs(group)
    if t == "MESH":
        return {"HUBS": "A full mesh has no hub"} if h else {}
    if len(h) != HUB_COUNT[t] or len(set(h)) != len(h):
        return {"HUBS": "Choose one hub" if t == "HUB_SPOKE" else "Choose two different hubs"}
    if members is not None:
        outside = [x for x in h if x not in members]
        if outside:
            return {"HUBS": f"Hubs must be members of the group: {', '.join(outside)}"}
    return {}

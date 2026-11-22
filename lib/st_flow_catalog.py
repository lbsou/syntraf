"""Flux attendus et événements de configuration, écrits dans les bases à côté des mesures.

SYNTRAF_FLOW_EXPECTED{MESH_GROUP, CLIENT (émetteur), SERVER (récepteur), UID, TOPOLOGY, CLIENT_ROLE, SERVER_ROLE} = 1
    publié par le serveur toutes les 30 s et après chaque changement : les tableaux de bord savent quels flux
    doivent être mesurés (un flux retiré par un changement de topologie n'est pas une panne, un flux attendu
    sans mesure en est une) et quel rôle (hub, spoke, member) a chaque extrémité.
SYNTRAF_CONFIG_CHANGE{ACTION, ACTOR, SUMMARY} = 1
    un point par entrée du journal d'audit : repères des changements sur les courbes.

Module sans dépendance externe.
"""
import datetime as dt
import logging
import threading

from lib import st_topology

log = logging.getLogger("syntraf." + __name__)
PUBLISH_PERIOD_S = 30


def _uid(sender, receiver, dscp):
    return f"{sender}__TO__{receiver}__ON__DSCP{dscp}"  # comme st_outage.flow_uid


def _role(group, uid):
    if group is None or st_topology.topology(group) == "MESH":
        return "member"
    return "hub" if uid in st_topology.hubs(group) else "spoke"


def expected_flows(config, generated):
    """Flux que les clients doivent mesurer : un par listener (et le retour d'un connecteur bidirectionnel)."""
    groups = {g.get("UID"): g for g in config.get("MESH_GROUP", [])}
    flows = {}
    for node in (generated or {}).values():
        node = node or {}
        edges = [(e["UID_CLIENT"], e["UID_SERVER"], e) for e in (node.get("LISTENERS") or {}).values()]
        edges += [(e["UID_SERVER"], e["UID_CLIENT"], e) for e in (node.get("CONNECTORS") or {}).values()
                  if e.get("BIDIR")]
        for sender, receiver, e in edges:
            group = groups.get(e.get("MESH_GROUP"))
            uid = _uid(sender, receiver, e.get("DSCP"))
            flows[(e.get("MESH_GROUP"), uid)] = {
                "MESH_GROUP": e.get("MESH_GROUP"), "CLIENT": sender, "SERVER": receiver, "UID": uid,
                "TOPOLOGY": st_topology.topology(group or {}), "CLIENT_ROLE": _role(group, sender),
                "SERVER_ROLE": _role(group, receiver)}
    return [flows[k] for k in sorted(flows)]


def expected_points(flows, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    return [{"measurement": "SYNTRAF_FLOW", "tags": dict(f), "time": now, "fields": {"EXPECTED": 1}} for f in flows]


def event_point(entry):
    summary = " ".join(str(entry.get("summary", "")).split())[:200]
    try:
        when = dt.datetime.fromisoformat(entry["time"])
    except (KeyError, ValueError):
        when = dt.datetime.now(dt.timezone.utc)
    return {"measurement": "SYNTRAF_CONFIG", "time": when, "fields": {"CHANGE": 1},
            "tags": {"ACTION": entry.get("action", ""), "ACTOR": entry.get("actor", ""), "SUMMARY": summary}}


def _write(points, conn_db, what):
    written = False
    if not conn_db:
        log.warning(f"{what}: NO DATABASE CONNECTION TO WRITE {len(points)} POINT(S) TO")
    for conn in list(conn_db or []):
        try:
            answer = conn.save_metrics_to_database_with_buffer(points, "server", what)
            if answer == "OK":
                written = True
            else:
                log.warning(f"{what}: {getattr(conn, 'DB_UID', '?')} ANSWERED {answer}")
        except Exception as exc:  # noqa: BLE001 - une base indisponible n'empêche pas les autres
            log.warning(f"{what}: {getattr(conn, 'DB_UID', '?')}: {type(exc).__name__}:{exc}")
    return written


def publish_expected(config, generated, conn_db):
    """Écrit les flux attendus dans chaque base ; renvoie leur nombre."""
    points = expected_points(expected_flows(config, generated))
    if points:
        _write(points, conn_db, "EXPECTED_FLOWS")
    return len(points)


def publish_event(entry, conn_db):
    _write([event_point(entry)], conn_db, "CONFIG_CHANGE")


class Publisher:
    """Publication périodique des flux attendus (au plus une fois par période, sauf si forcée)."""

    def __init__(self, period_s=PUBLISH_PERIOD_S):
        self.period_s, self.last, self.lock = period_s, None, threading.Lock()

    def maybe(self, config, generated, conn_db, now=None, force=False):
        now = now if now is not None else dt.datetime.now().timestamp()
        with self.lock:
            if not force and self.last is not None and now - self.last < self.period_s:
                return False
            self.last = now
        publish_expected(config, generated, conn_db)
        return True


PUBLISHER = Publisher()

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


def bandwidth_bps(text):
    """« 100K », « 2M », « 1G » ou un nombre de bit/s ; 0 si illisible."""
    t = str(text or "").strip().upper()
    factor = {"K": 1e3, "M": 1e6, "G": 1e9}.get(t[-1:], 1)
    try:
        return float(t[:-1] if factor != 1 else t) * factor if t else 0
    except ValueError:
        return 0


def _human_bps(bps):
    for unit, size in (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3)):
        if bps >= size:
            return f"{bps / size:g} {unit}"
    return f"{bps:g} bps"


def _number(text):
    try:
        value = float(str(text).strip())
        return int(value) if value.is_integer() else value
    except ValueError:
        return None


def group_points(config, flows, now=None):
    """Un point par mesh group actif : ses paramètres en vigueur (profil appliqué), pour les tableaux de bord.
    Étiquettes lisibles (bandeau) et champs numériques (ligne « débit prévu » sur les graphiques)."""
    now = now or dt.datetime.now(dt.timezone.utc)
    points = []
    for g in config.get("MESH_GROUP", []):
        if g.get("DISABLED"):
            continue
        uid = g.get("UID")
        mine = [f for f in flows if f["MESH_GROUP"] == uid]
        members = {n for f in mine for n in (f["CLIENT"], f["SERVER"])}
        bps = bandwidth_bps(g.get("BANDWIDTH"))
        size = _number(g.get("PACKET_SIZE", "")) or 0
        pps = bps / (size * 8) if bps and size else 0
        tags = {"MESH_GROUP": uid, "TOPOLOGY": st_topology.topology(g), "HUBS": ", ".join(st_topology.hubs(g)) or "-",
                "PROFILE": g.get("IPERF3_PROFILE") or "-", "BANDWIDTH": _human_bps(bps) if bps else "-",
                "DSCP": str(g.get("DSCP", "-")), "PACKET_SIZE": f"{size} B" if size else "-",
                "INTERVAL": f"{g.get('INTERVAL')} s" if g.get("INTERVAL") not in (None, "") else "-",
                "PPS": f"{pps:.0f}" if pps else "-", "MEMBERS": str(len(members)), "FLOWS": str(len(mine))}
        fields = {"INFO": 1, "BANDWIDTH_KBPS": bps / 1000, "PPS": pps, "PACKET_SIZE": size,
                  "DSCP": _number(g.get("DSCP", "")) or 0, "INTERVAL": _number(g.get("INTERVAL", "")) or 0,
                  "FLOWS": len(mine), "MEMBERS": len(members)}
        points.append({"measurement": "SYNTRAF_GROUP", "tags": tags, "time": now, "fields": fields})
    return points


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
    now = dt.datetime.now(dt.timezone.utc)
    flows = expected_flows(config, generated)
    points = expected_points(flows, now)
    groups = group_points(config, flows, now)  # même horodatage : les tableaux de bord prennent la dernière publication
    if points or groups:
        _write(points + groups, conn_db, "EXPECTED_FLOWS")
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

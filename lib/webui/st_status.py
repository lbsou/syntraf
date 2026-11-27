"""État du serveur pour le tableau de bord, /healthz et /metrics. Lit les objets partagés, ne les modifie pas."""
import datetime as dt
import ipaddress
import json

from lib import st_host_stats
from lib.st_global import DefaultValues

# Threads du serveur dont la mort rend le service inutilisable (les flux iperf3 vivent chez les clients).
CORE_THREAD_TYPES = ("SERVER", "SERVER_SOCKET", "STATS", "WEBUI", "UDP_HOLE")
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")


SECRET_MARKERS = ("TOKEN", "PASSWORD", "SECRET", "KEY")
MASK = "••••••••"


def display_value(value, key=""):
    """Valeur d'un paramètre de configuration à afficher : secrets et valeurs binaires masqués."""
    name = str(key).upper()
    # Un chemin, un dossier ou une empreinte n'est pas un secret, même si son nom contient KEY ou TOKEN
    secret_name = any(m in name for m in SECRET_MARKERS) and not name.endswith(("_DIRECTORY", "_PATH", "_FILE", "_SHA256"))
    if secret_name or isinstance(value, (bytes, bytearray)):
        return MASK
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=lambda o: MASK if isinstance(o, (bytes, bytearray)) else str(o))
    return value


def _s(value):
    """Horodatage ISO avec son fuseau (un datetime naïf est l'heure locale du serveur) : le navigateur l'affiche à
    l'heure de l'utilisateur, même quand le serveur tourne en UTC."""
    return value.astimezone().isoformat(timespec="seconds") if isinstance(value, dt.datetime) else value


def clients(state):
    """Un élément par client déclaré (SERVER_CLIENT) ou connu de la boucle de contrôle."""
    declared = {c["UID"]: c for c in state["config"].get("SERVER_CLIENT", [])}
    known = state["dict_of_clients"]
    generated = state["_dict_by_node_generated_config"]
    rows = []
    # Avant son authentification, une connexion est rangée sous son adresse IP (objet temporaire, gardé après un
    # refus) : ce n'est pas un client. Les demandes refusées ou en attente ont leur propre panneau.
    known = {u: o for u, o in known.items() if u in declared or not _is_ip(u)}
    for uid in sorted(set(declared) | set(known)):
        obj, decl, gen = known.get(uid), declared.get(uid, {}), generated.get(uid) or {}
        rows.append({
            "uid": uid,
            "status": getattr(obj, "status", "NEVER_SEEN") if obj is not None else "NEVER_SEEN",
            "status_since": _s(getattr(obj, "status_since", None)),
            "status_explanation": getattr(obj, "status_explanation", None),
            "paused": decl.get("PAUSED") is True,
            "status_label": _status_label(obj, decl),
            "ip_address": getattr(obj, "ip_address", "") or decl.get("IP_ADDRESS", ""),
            "dynamic_ip": decl.get("IP_ADDRESS", "") in ("", "0.0.0.0"),
            "syntraf_version": getattr(obj, "syntraf_version", "") if obj is not None else "",
            "clock_skew_seconds": getattr(obj, "clock_skew_in_seconds", None) if obj is not None else None,
            **_clock(obj),
            "mesh_groups": decl.get("MESH_GROUP_UID_LIST", []),
            "metrics_buffer": getattr(obj, "metrics_buffer", None) if obj is not None else None,
            "release": getattr(obj, "release_id", None) if obj is not None else None,
            "listeners": len(gen.get("LISTENERS") or {}),
            "connectors": len(gen.get("CONNECTORS") or {}),
            "declared": uid in declared,
            "host": st_host_stats.latest(obj),  # charge du poste : CPU, mémoire, carte réseau (None si inconnue)
        })
    return rows


def _status_label(obj, decl):
    """Statut affiché : celui de la connexion, suivi de « PAUSED » pour une sonde mise en pause."""
    status = getattr(obj, "status", "NEVER_SEEN") if obj is not None else "NEVER_SEEN"
    return f"{status} - PAUSED" if decl.get("PAUSED") is True else status


def _clock(obj):
    from lib import st_clock
    est = st_clock.estimate_of(obj) or {}
    return {"clock_offset_ms": est.get("offset_ms"), "clock_drift_ppm": est.get("drift_ppm"),
            "clock_delay_ms": est.get("delay_ms")}


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def databases(state, refresh=False):
    rows = []
    for db in state.get("conn_db") or []:
        if refresh:
            db.force_status_check()
        rows.append({"uid": db.DB_UID, "status": db.status, "status_since": _s(db.status_time),
                     "backlog": len(db.write_queue.queue)})
    return rows


def threads(state):
    rows = []
    for t in state.get("threads_n_processes") or []:
        try:
            alive = bool(t.getstatus())
        except Exception:  # noqa: BLE001 - un objet à moitié initialisé ne doit pas casser la page
            alive = False
        rows.append({"name": getattr(t, "name", "?"), "type": getattr(t, "syntraf_instance_type", "?"),
                     "alive": alive})
    return rows


def snapshot(state, refresh_databases=False):
    cl = clients(state)
    groups = state["config"].get("MESH_GROUP", [])
    th = threads(state)
    return {
        "time": _s(dt.datetime.now().astimezone()),
        "version": DefaultValues.SYNTRAF_VERSION,
        "clients": cl,
        "clients_summary": {
            "total": len(cl),
            "connected": sum(c["status"] == "CONNECTED" for c in cl),
            "disconnected": sum(c["status"] != "CONNECTED" for c in cl),
        },
        "mesh_groups_summary": {
            "total": len(groups),
            "disabled": sum(g.get("DISABLED") is True for g in groups),
            "enabled": sum(g.get("DISABLED") is not True for g in groups),
        },
        "databases": databases(state, refresh_databases),
        "threads": th,
        "queue_length": len(state.get("dict_data_to_send_to_server") or {}),
        "pending_clients": _pending_count(state),
    }


def _pending_count(state):
    path = state.get("config_file_path")
    if not path:
        return 0
    from lib.st_enrollment import Enrollment
    try:
        return len(Enrollment(path + ".pending.json").pending())
    except OSError:
        return 0


def health(state):
    """(statut HTTP, corps) : 503 si un thread essentiel est mort ou si aucune base n'est en ligne."""
    th = threads(state)
    dead = [t["name"] for t in th if t["type"] in CORE_THREAD_TYPES and not t["alive"]]
    dbs = databases(state)
    offline = [d["uid"] for d in dbs if d["status"] != "ONLINE"]
    checks = {
        "threads": {"ok": not dead, "dead": dead},
        "databases": {"ok": not dbs or len(offline) < len(dbs), "offline": offline},
    }
    ok = all(c["ok"] for c in checks.values())
    return (200 if ok else 503), {"status": "ok" if ok else "degraded", "version": DefaultValues.SYNTRAF_VERSION,
                                  "checks": checks}


def _label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def metrics(state):
    """Texte au format d'exposition Prometheus."""
    snap = snapshot(state)
    out = []

    def metric(name, help_text, kind, samples):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{_label(v)}"' for k, v in labels.items())
            out.append(f"{name}{{{lab}}} {value}" if lab else f"{name} {value}")

    metric("syntraf_build_info", "SYNTRAF server version.", "gauge", [({"version": snap["version"]}, 1)])
    metric("syntraf_client_connected", "1 if the client control channel is connected.", "gauge",
           [({"client": c["uid"]}, int(c["status"] == "CONNECTED")) for c in snap["clients"]])
    metric("syntraf_client_flows", "iperf3 flows generated for the client.", "gauge",
           [({"client": c["uid"], "role": role}, c[role]) for c in snap["clients"] for role in ("listeners", "connectors")])
    metric("syntraf_client_buffered_points", "Measurements waiting on the client to be sent to the server.", "gauge",
           [({"client": c["uid"]}, c["metrics_buffer"]) for c in snap["clients"] if c["metrics_buffer"] is not None])
    metric("syntraf_client_clock_offset_seconds", "Server clock minus client clock (positive: the client is behind).",
           "gauge", [({"client": c["uid"]}, c["clock_offset_ms"] / 1000.0) for c in snap["clients"]
                     if c.get("clock_offset_ms") is not None and c["status"] == "CONNECTED"])
    metric("syntraf_client_clock_drift_ppm", "Drift of the client clock over the last hour (positive: it gains).",
           "gauge", [({"client": c["uid"]}, c["clock_drift_ppm"]) for c in snap["clients"]
                     if c.get("clock_drift_ppm") is not None and c["status"] == "CONNECTED"])
    # Charge du poste de chaque sonde connectée (dernière valeur reçue, moins d'une minute)
    for name, field, help_text in (
            ("syntraf_client_cpu_percent", "cpu_pct", "CPU used on the probe host, average of all cores (%)."),
            ("syntraf_client_cpu_busiest_core_percent", "cpu_busiest_core_pct",
             "CPU used by the busiest core of the probe host (%)."),
            ("syntraf_client_memory_used_percent", "mem_used_pct", "Memory used on the probe host (%)."),
            ("syntraf_client_nic_rx_bits_per_second", "nic_rx_bps",
             "Traffic received by the probe network interface (bit/s), all applications."),
            ("syntraf_client_nic_tx_bits_per_second", "nic_tx_bps",
             "Traffic sent by the probe network interface (bit/s), all applications."),
            ("syntraf_client_nic_speed_mbps", "nic_speed_mbps", "Link speed of the probe network interface (Mbit/s)."),
            ("syntraf_client_nic_rx_percent", "nic_rx_pct", "Receive usage of the probe network interface (%)."),
            ("syntraf_client_nic_tx_percent", "nic_tx_pct", "Transmit usage of the probe network interface (%).")):
        metric(name, help_text, "gauge", [({"client": c["uid"]}, c["host"][field]) for c in snap["clients"]
                                          if c.get("host") and c["host"].get(field) is not None])
    metric("syntraf_mesh_groups", "Mesh groups by state.", "gauge",
           [({"state": s}, snap["mesh_groups_summary"][s]) for s in ("enabled", "disabled")])
    metric("syntraf_database_up", "1 if the database is reachable.", "gauge",
           [({"database": d["uid"]}, int(d["status"] == "ONLINE")) for d in snap["databases"]])
    metric("syntraf_database_backlog", "Points waiting to be written to the database.", "gauge",
           [({"database": d["uid"]}, d["backlog"]) for d in snap["databases"]])
    metric("syntraf_thread_up", "1 if the server thread is alive.", "gauge",
           [({"thread": t["name"], "type": t["type"]}, int(t["alive"])) for t in snap["threads"]])
    metric("syntraf_queue_length", "Points received from clients and not yet forwarded.", "gauge",
           [({}, snap["queue_length"])])
    # Alertes (hors baseline, et santé de SYNTRAF) : 1 ouverte, 0 refermée récemment. Un collecteur (Zabbix,
    # Prometheus) découvre chacune et lève, puis résout, son propre problème.
    from lib import st_baseline
    alerts = {}
    for value, rows in ((0, st_baseline.BOOK.recent() + st_baseline.HEALTH_BOOK.recent()),
                        (1, st_baseline.BOOK.open() + st_baseline.HEALTH_BOOK.open())):
        for alert in rows:
            labels = {"group": alert.get("MESH_GROUP", ""), "source": alert.get("SUBJECT") or alert.get("CLIENT", ""),
                      "destination": alert.get("SERVER", ""), "metric": alert.get("METRIC", ""),
                      "kind": alert.get("KIND", "")}
            alerts[tuple(labels.values())] = (labels, value)
    metric("syntraf_alert_open", "1 while the alert is open, 0 once closed (recent alerts only).", "gauge",
           list(alerts.values()))
    metric("syntraf_alerts_open", "Open alerts.", "gauge", [({}, sum(v for _, v in alerts.values()))])
    return "\n".join(out) + "\n"


def filter_log_lines(lines, level="", query=""):
    """Garde les lignes du niveau demandé ou plus grave, et contenant query (sans tenir compte de la casse)."""
    level = (level or "").upper()
    accepted = LEVELS[LEVELS.index(level):] if level in LEVELS else None
    q = (query or "").lower()
    kept = []
    for line in lines:
        if accepted is not None and not any(f" - {lv} - " in line for lv in accepted):
            continue
        if q and q not in line.lower():
            continue
        kept.append(line)
    return kept

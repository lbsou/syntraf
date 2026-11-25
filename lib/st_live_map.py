"""Carte de la topologie en direct : les sondes et leurs liens, colorés selon la qualité de la dernière minute.

Liens : un par paire de sondes et par mesh group, tirés des flux attendus (lib/st_flow_catalog.expected_flows) — un
flux attendu sans mesure apparaît donc aussi (« pas de données »). Chaque lien porte ses deux sens (pertes, gigue,
MOS) et le RTT de la paire ; sa couleur est celle du pire sens, pour l'indicateur choisi.

Valeurs lues dans VictoriaMetrics (moyenne sur 1 min) ; sans VictoriaMetrics, la carte montre les sondes et les
liens attendus, sans couleur de qualité.

Relecture d'un incident : les mêmes requêtes à un instant passé (paramètre time de VictoriaMetrics), avec l'état des
sondes (syntraf_client_connected, collecté sur /metrics) et les alertes ouvertes à ce moment (SYNTRAF_BASELINE_ALERT) ;
la frise (timeline) donne le pire état de chaque pas pour trouver l'incident.
"""

WINDOW = "1m"
QUERIES = {
    "loss": f"avg by (CLIENT, SERVER, MESH_GROUP) (avg_over_time(SYNTRAF_RX_PCT_LOSS[{WINDOW}]))",
    "jitter": f"avg by (CLIENT, SERVER, MESH_GROUP) (avg_over_time(SYNTRAF_RX_JITTER[{WINDOW}]))",
    "mos": f"avg by (CLIENT, SERVER, MESH_GROUP) (avg_over_time(SYNTRAF_RX_MOS[{WINDOW}]))",
    "rtt": f"avg by (CLIENT, SERVER) (avg_over_time(SYNTRAF_LATENCY_RTT_MS[{WINDOW}]))",
}
# (seuils croissants vert → jaune → orange → rouge) ; MOS : plus haut est meilleur
GRADES = {
    "loss": (1, 5, 20),
    "jitter": (10, 30, 50),
    "rtt": (100, 200, 300),
    "mos": (4.0, 3.6, 3.1),
}


def grade(kind, value):
    if value is None:
        return "nodata"
    a, b, c = GRADES[kind]
    if kind == "mos":
        return "green" if value >= a else "yellow" if value >= b else "orange" if value >= c else "red"
    return "green" if value < a else "yellow" if value < b else "orange" if value < c else "red"


def _query(vm, expr, at):
    return vm.query(expr) if at is None else vm.query(expr, time=at)


def read_metrics(vm, at=None):
    out = {k: {} for k in QUERIES}
    for kind, expr in QUERIES.items():
        try:
            result = _query(vm, expr, at)
        except Exception:  # noqa: BLE001 - une base indisponible : la carte reste sans couleurs
            result = []
        for r in result or []:
            m = r.get("metric", {})
            try:
                value = float(r.get("value", [0, "nan"])[1])
            except (TypeError, ValueError):
                continue
            if value != value:  # NaN
                continue
            key = (m.get("CLIENT"), m.get("SERVER")) + ((m.get("MESH_GROUP"),) if kind != "rtt" else ())
            out[kind][key] = value
    return out


def read_status(vm, at):
    """{sonde: CONNECTED | DISCONNECTED} à cet instant ; {} sans collecte de /metrics."""
    try:
        result = _query(vm, "max by (client) (max_over_time(syntraf_client_connected[2m]))", at)
    except Exception:  # noqa: BLE001
        return {}
    out = {}
    for r in result or []:
        uid = (r.get("metric") or {}).get("client")
        try:
            out[uid] = "CONNECTED" if float(r["value"][1]) >= 1 else "DISCONNECTED"
        except (KeyError, IndexError, TypeError, ValueError):
            continue
    return out


def read_alerts(vm, at):
    """Alertes hors baseline ouvertes à cet instant : [{CLIENT, SERVER, MESH_GROUP, METRIC}]."""
    try:
        result = _query(vm, "max by (MESH_GROUP, CLIENT, SERVER, METRIC) "
                            "(max_over_time(SYNTRAF_BASELINE_ALERT[2m])) > 0", at)
    except Exception:  # noqa: BLE001
        return []
    keys = ("CLIENT", "SERVER", "MESH_GROUP", "METRIC")
    return [{k: (r.get("metric") or {}).get(k) for k in keys} for r in result or []]


def _label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


TIMELINE = {  # pire valeur de tous les flux, par pas
    "loss": "max(avg_over_time(SYNTRAF_RX_PCT_LOSS{sel}[{w}s]))",
    "jitter": "max(avg_over_time(SYNTRAF_RX_JITTER{sel}[{w}s]))",
    "mos": "min(avg_over_time(SYNTRAF_RX_MOS{sel}[{w}s]))",
    "rtt": "max(avg_over_time(SYNTRAF_LATENCY_RTT_MS[{w}s]))",  # sans mesh group dans ses étiquettes
    "alerts": "count(max_over_time(SYNTRAF_BASELINE_ALERT{sel}[{w}s]) > 0)",
}


def timeline(vm, start, end, step, mesh_group=None):
    """Frise de start à end : pour chaque pas, le pire état (perte, gigue, MOS, RTT) et le nombre d'alertes ouvertes."""
    start, end, step = int(start), int(end), max(int(step), 1)
    ts = list(range(start, end + 1, step))
    sel = f'{{MESH_GROUP="{_label(mesh_group)}"}}' if mesh_group else ""
    out = {"t": ts, "grade": {}}
    for kind, tmpl in TIMELINE.items():
        values = {}
        try:
            result = vm.query_range(tmpl.replace("{sel}", sel).replace("{w}", str(max(step, 60))), start, end, step)
        except Exception:  # noqa: BLE001
            result = []
        for serie in result or []:
            for t, v in serie.get("values", []):
                try:
                    values[int(float(t))] = float(v)
                except (TypeError, ValueError):
                    continue
        if kind == "alerts":
            out[kind] = [int(values.get(t, 0)) for t in ts]
        else:
            out[kind] = [values.get(t) for t in ts]
            out["grade"][kind] = [grade(kind, v) for v in out[kind]]
    return out


def _worst(values, kind):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return min(values) if kind == "mos" else max(values)


def build(flows, clients, metrics, mesh_group=None, alerts=None):
    """flows : flux attendus ({MESH_GROUP, CLIENT (émetteur), SERVER (récepteur)}) ; clients : état des sondes."""
    flows = [f for f in flows if mesh_group in (None, "", f.get("MESH_GROUP"))]
    pairs = {}
    for f in flows:
        a, b, g = f["CLIENT"], f["SERVER"], f.get("MESH_GROUP")
        key = (min(a, b), max(a, b), g)
        link = pairs.setdefault(key, {"a": key[0], "b": key[1], "mesh_group": g, "directions": []})
        if not any(d["from"] == a and d["to"] == b for d in link["directions"]):
            d = {"from": a, "to": b,
                 "loss_pct": metrics.get("loss", {}).get((a, b, g)),
                 "jitter_ms": metrics.get("jitter", {}).get((a, b, g)),
                 "mos": metrics.get("mos", {}).get((a, b, g))}
            # Qualité de CE sens (la carte dessine une flèche par sens) ; le RTT est celui de la paire
            d["grade"] = {"loss": grade("loss", d["loss_pct"]), "jitter": grade("jitter", d["jitter_ms"]),
                          "mos": grade("mos", d["mos"])}
            link["directions"].append(d)
    links = []
    for link in pairs.values():
        d = link["directions"]
        rtt = metrics.get("rtt", {}).get((link["a"], link["b"]), metrics.get("rtt", {}).get((link["b"], link["a"])))
        link.update(loss_pct=_worst([x["loss_pct"] for x in d], "loss"),
                    jitter_ms=_worst([x["jitter_ms"] for x in d], "jitter"),
                    mos=_worst([x["mos"] for x in d], "mos"), rtt_ms=rtt)
        link["grade"] = {"loss": grade("loss", link["loss_pct"]), "jitter": grade("jitter", link["jitter_ms"]),
                         "mos": grade("mos", link["mos"]), "rtt": grade("rtt", rtt)}
        link["alerts"] = [f"{x.get('CLIENT')} → {x.get('SERVER')} {x.get('METRIC')}" for x in (alerts or [])
                          if x.get("MESH_GROUP") == link["mesh_group"] and {x.get("CLIENT"), x.get("SERVER")} == {link["a"], link["b"]}]
        links.append(link)
    used = {x for l in links for x in (l["a"], l["b"])}
    nodes = [{"id": c["uid"], "status": c.get("status", "UNKNOWN"), "behind_nat": bool(c.get("behind_nat")),
              "mesh_groups": c.get("mesh_groups", [])}
             for c in clients if mesh_group in (None, "") or c["uid"] in used]
    known = {n["id"] for n in nodes}
    nodes += [{"id": u, "status": "UNKNOWN", "behind_nat": False, "mesh_groups": []} for u in sorted(used - known)]
    return {"nodes": nodes, "links": sorted(links, key=lambda l: (l["mesh_group"] or "", l["a"], l["b"])),
            "grades": {k: list(v) for k, v in GRADES.items()}}

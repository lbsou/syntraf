"""Carte de la topologie en direct : les sondes et leurs liens, colorés selon la qualité de la dernière minute.

Liens : un par paire de sondes et par mesh group, tirés des flux attendus (lib/st_flow_catalog.expected_flows) — un
flux attendu sans mesure apparaît donc aussi (« pas de données »). Chaque lien porte ses deux sens (pertes, gigue,
MOS) et le RTT de la paire ; sa couleur est celle du pire sens, pour l'indicateur choisi.

Valeurs lues dans VictoriaMetrics (moyenne sur 1 min) ; sans VictoriaMetrics, la carte montre les sondes et les
liens attendus, sans couleur de qualité.
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


def read_metrics(vm):
    out = {k: {} for k in QUERIES}
    for kind, expr in QUERIES.items():
        try:
            result = vm.query(expr)
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


def _worst(values, kind):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return min(values) if kind == "mos" else max(values)


def build(flows, clients, metrics, mesh_group=None):
    """flows : flux attendus ({MESH_GROUP, CLIENT (émetteur), SERVER (récepteur)}) ; clients : état des sondes."""
    flows = [f for f in flows if mesh_group in (None, "", f.get("MESH_GROUP"))]
    pairs = {}
    for f in flows:
        a, b, g = f["CLIENT"], f["SERVER"], f.get("MESH_GROUP")
        key = (min(a, b), max(a, b), g)
        link = pairs.setdefault(key, {"a": key[0], "b": key[1], "mesh_group": g, "directions": []})
        if not any(d["from"] == a and d["to"] == b for d in link["directions"]):
            link["directions"].append({
                "from": a, "to": b,
                "loss_pct": metrics.get("loss", {}).get((a, b, g)),
                "jitter_ms": metrics.get("jitter", {}).get((a, b, g)),
                "mos": metrics.get("mos", {}).get((a, b, g)),
            })
    links = []
    for link in pairs.values():
        d = link["directions"]
        rtt = metrics.get("rtt", {}).get((link["a"], link["b"]), metrics.get("rtt", {}).get((link["b"], link["a"])))
        link.update(loss_pct=_worst([x["loss_pct"] for x in d], "loss"),
                    jitter_ms=_worst([x["jitter_ms"] for x in d], "jitter"),
                    mos=_worst([x["mos"] for x in d], "mos"), rtt_ms=rtt)
        link["grade"] = {"loss": grade("loss", link["loss_pct"]), "jitter": grade("jitter", link["jitter_ms"]),
                         "mos": grade("mos", link["mos"]), "rtt": grade("rtt", rtt)}
        links.append(link)
    used = {x for l in links for x in (l["a"], l["b"])}
    nodes = [{"id": c["uid"], "status": c.get("status", "UNKNOWN"), "behind_nat": bool(c.get("behind_nat")),
              "mesh_groups": c.get("mesh_groups", [])}
             for c in clients if mesh_group in (None, "") or c["uid"] in used]
    known = {n["id"] for n in nodes}
    nodes += [{"id": u, "status": "UNKNOWN", "behind_nat": False, "mesh_groups": []} for u in sorted(used - known)]
    return {"nodes": nodes, "links": sorted(links, key=lambda l: (l["mesh_group"] or "", l["a"], l["b"])),
            "grades": {k: list(v) for k, v in GRADES.items()}}

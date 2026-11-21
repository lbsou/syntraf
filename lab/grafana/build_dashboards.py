#!/usr/bin/env python3
"""Génère les tableaux de bord Grafana du lab SYNTRAF (lab/grafana/dashboards/*.json).

    python lab/grafana/build_dashboards.py
    python lab/labctl.py restart grafana    # Grafana ne relit pas toujours seul les fichiers

- syntraf.json : séries temporelles par flux (silence, pertes, débit, gigue, paquets perdus).
- syntraf-matrix.json : matrices source × destination, à la manière de grallama-panel
  (dropbox/grallama-panel, plugin Angular incompatible avec Grafana 13) : une table par
  métrique, transformation « Grouping to matrix », cellules colorées selon des seuils.

Dans les métriques SYNTRAF, CLIENT est l'émetteur iperf3 (source) et SERVER le récepteur
(destination) : c'est le récepteur qui mesure les pertes, la gigue et le débit.
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
DS = {"type": "prometheus", "uid": "syntraf-vm"}
SEL = 'MESH_GROUP=~"$mesh_group",CLIENT=~"$client",SERVER=~"$server"'
LEG = "{{CLIENT}} → {{SERVER}}"
LINKS = [{"title": "Tableaux de bord SYNTRAF", "type": "dashboards", "tags": ["syntraf"],
          "asDropdown": False, "includeVars": True, "keepTime": True}]


def steps(*pairs):
    """steps(("green", None), ("orange", 5)) → seuils Grafana."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in pairs]}


LOSS_STEPS = steps(("green", None), ("yellow", 1), ("orange", 5), ("red", 20))
SILENCE_STEPS = steps(("green", None), ("orange", 5), ("red", 15))
JITTER_STEPS = steps(("green", None), ("yellow", 1), ("orange", 5), ("red", 30))
BITRATE_STEPS = steps(("red", None), ("orange", 50), ("green", 90))


def var(name, label):
    q = f"label_values(SYNTRAF_RX_PCT_LOSS, {label})"
    return {"name": name, "label": label, "type": "query", "datasource": DS,
            "query": {"query": q, "refId": "v"}, "definition": q,
            "includeAll": True, "multi": True, "allValue": ".*", "refresh": 2, "sort": 1,
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]}}


def dashboard(uid, title, panels, refresh="5s", time_from="now-15m"):
    return {"uid": uid, "title": title, "tags": ["syntraf", "lab"], "timezone": "browser",
            "schemaVersion": 39, "version": 1, "editable": False, "refresh": refresh,
            "time": {"from": time_from, "to": "now"}, "links": LINKS,
            "templating": {"list": [var("mesh_group", "MESH_GROUP"), var("client", "CLIENT"),
                                    var("server", "SERVER")]},
            "annotations": {"list": []}, "panels": panels}


# ---------------------------------------------------------------------------
# Séries temporelles
# ---------------------------------------------------------------------------
def timeseries(pid, title, expr, unit, x, y, extra=None):
    p = {"id": pid, "type": "timeseries", "title": title, "datasource": DS,
         "gridPos": {"x": x, "y": y, "w": 12, "h": 9},
         "targets": [{"refId": "A", "datasource": DS, "expr": expr, "legendFormat": LEG}],
         "fieldConfig": {"defaults": {"unit": unit, "custom": {"lineWidth": 1, "fillOpacity": 10,
                                                               "spanNulls": False, "showPoints": "never"}},
                         "overrides": []},
         "options": {"legend": {"displayMode": "table", "placement": "right",
                                "calcs": ["mean", "max", "lastNotNull"]},
                     "tooltip": {"mode": "multi", "sort": "desc"}}}
    if extra:
        p["fieldConfig"]["defaults"].update(extra)
    return p


def series_dashboard():
    silence = {"id": 1, "type": "stat", "title": "Silence par flux (s depuis le dernier point)", "datasource": DS,
               "gridPos": {"x": 0, "y": 0, "w": 24, "h": 5},
               "targets": [{"refId": "A", "datasource": DS, "instant": True, "legendFormat": LEG,
                            "expr": f"time() - tlast_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[1h])"}],
               "fieldConfig": {"defaults": {"unit": "s", "decimals": 0, "thresholds": SILENCE_STEPS},
                               "overrides": []},
               "options": {"colorMode": "background", "graphMode": "none", "textMode": "value_and_name",
                           "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}}
    return dashboard("syntraf-lab", "SYNTRAF — mesures du maillage", [
        silence,
        timeseries(2, "Pertes (%) par flux", f"SYNTRAF_RX_PCT_LOSS{{{SEL}}}", "percent", 0, 5, {"min": 0, "max": 100}),
        timeseries(3, "Débit reçu par flux", f"SYNTRAF_RX_BITRATE{{{SEL}}}", "Kbits", 12, 5),
        timeseries(4, "Gigue par flux", f"SYNTRAF_RX_JITTER{{{SEL}}}", "ms", 0, 14),
        timeseries(5, "Paquets perdus par intervalle", f"SYNTRAF_RX_PACKET_LOSS{{{SEL}}}", "none", 12, 14),
    ])


# ---------------------------------------------------------------------------
# Matrices source × destination
# ---------------------------------------------------------------------------
def matrix(pid, title, expr, unit, decimals, thresholds, x, y, description=""):
    return {
        "id": pid, "type": "table", "title": title, "description": description, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": 12, "h": 8},
        # Sans nom de métrique, le champ numérique s'appelle toujours « Value ».
        "targets": [{"refId": "A", "datasource": DS, "expr": f'label_del({expr}, "__name__")',
                     "instant": True, "range": False}],
        # Une série par flux → labels en colonnes → une seule table → matrice CLIENT × SERVER.
        "transformations": [
            {"id": "labelsToFields", "options": {"mode": "columns"}},
            {"id": "merge", "options": {}},
            {"id": "groupingToMatrix",
             "options": {"columnField": "SERVER", "rowField": "CLIENT", "valueField": "Value",
                         "emptyValue": "null"}},
        ],
        "fieldConfig": {
            "defaults": {"unit": unit, "decimals": decimals, "noValue": "—", "thresholds": thresholds,
                         "custom": {"align": "center", "cellOptions": {"type": "color-background", "mode": "basic"}}},
            "overrides": [{"matcher": {"id": "byName", "options": "CLIENT\\SERVER"},
                           "properties": [{"id": "displayName", "value": "Source ↓ / Destination →"},
                                          {"id": "custom.cellOptions", "value": {"type": "auto"}},
                                          {"id": "custom.align", "value": "left"},
                                          {"id": "unit", "value": "string"}]}],
        },
        "options": {"showHeader": True, "cellHeight": "lg", "footer": {"show": False}},
    }


def matrix_dashboard():
    return dashboard("syntraf-matrix", "SYNTRAF — matrice source × destination", [
        matrix(1, "Pertes actuelles (%) — moyenne 30 s",
               f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[30s])", "percent", 1, LOSS_STEPS, 0, 0,
               "Pertes mesurées par la destination sur les 30 dernières secondes."),
        matrix(2, "Silence (s depuis le dernier point)",
               f"time() - tlast_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[1h])", "s", 0, SILENCE_STEPS, 12, 0,
               "Une cellule rouge = aucune mesure reçue : panne, ou SYNTRAF qui ne rapporte plus."),
        matrix(3, "Pertes moyennes sur la période affichée (%)",
               f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[$__range])", "percent", 2, LOSS_STEPS, 0, 8,
               "Moyenne sur toute la plage de temps choisie en haut à droite."),
        matrix(4, "Gigue (ms) — moyenne 30 s",
               f"avg_over_time(SYNTRAF_RX_JITTER{{{SEL}}}[30s])", "ms", 2, JITTER_STEPS, 12, 8),
        matrix(5, "Débit reçu (kbit/s) — moyenne 30 s",
               f"avg_over_time(SYNTRAF_RX_BITRATE{{{SEL}}}[30s])", "Kbits", 1, BITRATE_STEPS, 0, 16,
               "Débit configuré du groupe : 100 kbit/s."),
        matrix(6, "Paquets perdus — total sur la période affichée",
               f"sum_over_time(SYNTRAF_RX_PACKET_LOSS{{{SEL}}}[$__range])", "none", 0,
               steps(("green", None), ("orange", 1), ("red", 100)), 12, 16),
    ], time_from="now-1h")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, dash in (("syntraf.json", series_dashboard()), ("syntraf-matrix.json", matrix_dashboard())):
        (OUT / name).write_text(json.dumps(dash, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"écrit : {OUT / name}")


if __name__ == "__main__":
    main()

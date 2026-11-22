#!/usr/bin/env python3
"""Génère les tableaux de bord Grafana du lab SYNTRAF (lab/grafana/dashboards/*.json).

    python lab/grafana/build_dashboards.py
    python lab/labctl.py restart grafana    # Grafana ne relit pas toujours seul les fichiers

- syntraf.json : séries temporelles par flux (silence, pertes, débit, gigue, paquets perdus).
- syntraf-matrix.json : matrices source × destination, à la manière de grallama-panel
  (dropbox/grallama-panel, plugin Angular incompatible avec Grafana 13) : une table par
  métrique, transformation « Grouping to matrix », cellules colorées selon des seuils.
- syntraf-hubs.json : topologies à hubs (hub & spoke, deux hubs) : une ligne par spoke, une
  colonne par hub, la liaison entre hubs, la moyenne des spokes vers chaque hub.

Dans les métriques SYNTRAF, CLIENT est l'émetteur iperf3 (source) et SERVER le récepteur
(destination) : c'est le récepteur qui mesure les pertes, la gigue et le débit.

Flux attendus : le serveur publie SYNTRAF_FLOW_EXPECTED (un par flux que la configuration fait
mesurer, avec TOPOLOGY, CLIENT_ROLE et SERVER_ROLE). Les panneaux « état actuel » ne montrent que
ces flux : un flux retiré par un changement de topologie disparaît au lieu de ressembler à une panne,
et un flux attendu sans aucune mesure s'affiche « no data » en rouge (valeur sentinelle -1).
Les changements de configuration (SYNTRAF_CONFIG_CHANGE, depuis le journal d'audit) sont des repères.
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "dashboards"
DS = {"type": "prometheus", "uid": "syntraf-vm"}
SEL = 'MESH_GROUP=~"$mesh_group",CLIENT=~"$client",SERVER=~"$server"'
LEG = "{{CLIENT}} → {{SERVER}}"
LINKS = [{"title": "Tableaux de bord SYNTRAF", "type": "dashboards", "tags": ["syntraf"],
          "asDropdown": False, "includeVars": True, "keepTime": True}]
KEYS = "MESH_GROUP,CLIENT,SERVER"
NO_DATA = -1  # flux attendu sans aucune mesure dans la fenêtre
NO_DATA_MAPPING = [{"type": "value", "options": {str(NO_DATA): {"text": "no data", "color": "red", "index": 0}}}]
ANNOTATIONS = {"list": [{
    "name": "Changements de configuration", "datasource": DS, "enable": True, "iconColor": "orange",
    "expr": "last_over_time(SYNTRAF_CONFIG_CHANGE[1m])", "step": "60s",
    "titleFormat": "{{ACTION}}", "textFormat": "{{SUMMARY}} — {{ACTOR}}", "useValueForTime": False}]}


def steps(*pairs):
    """steps(("green", None), ("orange", 5)) → seuils Grafana."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in pairs]}


LOSS_STEPS = steps(("green", None), ("yellow", 1), ("orange", 5), ("red", 20))
SILENCE_STEPS = steps(("green", None), ("orange", 5), ("red", 15))
JITTER_STEPS = steps(("green", None), ("yellow", 1), ("orange", 5), ("red", 30))
BITRATE_STEPS = steps(("red", None), ("orange", 50), ("green", 90))


# ---------------------------------------------------------------------------
# Flux attendus
# ---------------------------------------------------------------------------
def expected(roles=""):
    """Flux attendus, éventuellement filtrés par rôle : ceux de la dernière publication du serveur seulement.

    Le serveur publie l'ensemble des flux d'un coup (même horodatage), toutes les 30 s et après chaque changement.
    Une fenêtre seule (90 s) garderait « attendus » pendant 90 s les flux qu'un changement vient de retirer :
    ils apparaîtraient « no data », précisément la fausse alerte à éviter.
    """
    extra = f",{roles}" if roles else ""
    metric = f"SYNTRAF_FLOW_EXPECTED{{{SEL}{extra}}}"
    last = f"tlast_over_time({metric}[90s])"
    return f"(last_over_time({metric}[90s]) and on({KEYS}) ({last} >= scalar(max({last})) - 5))"


def only_expected(expr, roles=""):
    """Les séries de expr qui correspondent à un flux attendu."""
    return f"(({expr}) and on({KEYS}) {expected(roles)})"


def current(expr, window, roles=""):
    """État actuel : les flux attendus, et « no data » (-1) pour ceux qui n'ont rien envoyé dans la fenêtre.

    La partie « no data » exclut exactement les flux de la partie mesurée (même expression) : les deux ne peuvent
    pas se recouvrir, donc pas de série en double (VictoriaMetrics refuserait la requête, HTTP 422).
    """
    measured = f'label_keep({only_expected(expr, roles)}, "MESH_GROUP", "CLIENT", "SERVER", "UID")'
    missing = (f'(label_keep({expected(roles)}, "MESH_GROUP", "CLIENT", "SERVER", "UID") * 0 + {NO_DATA}) '
               f"unless on({KEYS}) {measured}")
    return f"({measured} or {missing})"


def role(client, server):
    return f'CLIENT_ROLE="{client}",SERVER_ROLE="{server}"'


def var(name, label, metric="SYNTRAF_RX_PCT_LOSS"):
    q = f"label_values({metric}, {label})"
    return {"name": name, "label": label, "type": "query", "datasource": DS,
            "query": {"query": q, "refId": "v"}, "definition": q,
            "includeAll": True, "multi": True, "allValue": ".*", "refresh": 2, "sort": 1,
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]}}


def dashboard(uid, title, panels, refresh="5s", time_from="now-15m", variables=None):
    return {"uid": uid, "title": title, "tags": ["syntraf", "lab"], "timezone": "browser",
            "schemaVersion": 39, "version": 1, "editable": False, "refresh": refresh,
            "time": {"from": time_from, "to": "now"}, "links": LINKS,
            "templating": {"list": variables or [var("mesh_group", "MESH_GROUP"), var("client", "CLIENT"),
                                                 var("server", "SERVER")]},
            "annotations": ANNOTATIONS, "panels": panels}


# ---------------------------------------------------------------------------
# Séries temporelles
# ---------------------------------------------------------------------------
def timeseries(pid, title, expr, unit, x, y, extra=None, legend=LEG, w=12):
    p = {"id": pid, "type": "timeseries", "title": title, "datasource": DS,
         "gridPos": {"x": x, "y": y, "w": w, "h": 9},
         "targets": [{"refId": "A", "datasource": DS, "expr": expr, "legendFormat": legend}],
         "fieldConfig": {"defaults": {"unit": unit, "custom": {"lineWidth": 1, "fillOpacity": 10,
                                                               "spanNulls": False, "showPoints": "never"}},
                         "overrides": []},
         "options": {"legend": {"displayMode": "table", "placement": "right",
                                "calcs": ["mean", "max", "lastNotNull"]},
                     "tooltip": {"mode": "multi", "sort": "desc"}}}
    if extra:
        p["fieldConfig"]["defaults"].update(extra)
    return p


def stat(pid, title, expr, unit, thresholds, x, y, w=24, h=5, description=""):
    return {"id": pid, "type": "stat", "title": title, "description": description, "datasource": DS,
            "gridPos": {"x": x, "y": y, "w": w, "h": h},
            "targets": [{"refId": "A", "datasource": DS, "instant": True, "legendFormat": LEG, "expr": expr}],
            "fieldConfig": {"defaults": {"unit": unit, "decimals": 0, "thresholds": thresholds,
                                         "mappings": NO_DATA_MAPPING}, "overrides": []},
            "options": {"colorMode": "background", "graphMode": "none", "textMode": "value_and_name",
                        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}}


def series_dashboard():
    silence = stat(1, "Silence par flux attendu (s depuis le dernier point)",
                   current(f"time() - tlast_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[1h])", "1h"), "s",
                   SILENCE_STEPS, 0, 0,
                   description="Seuls les flux que la configuration fait mesurer. « no data » : flux attendu sans "
                               "aucune mesure depuis une heure.")
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
def matrix(pid, title, expr, unit, decimals, thresholds, x, y, description="", row="CLIENT", column="SERVER",
           corner="Source ↓ / Destination →", w=12):
    return {
        "id": pid, "type": "table", "title": title, "description": description, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": 8},
        # Sans nom de métrique, le champ numérique s'appelle toujours « Value ».
        "targets": [{"refId": "A", "datasource": DS, "expr": f'label_del({expr}, "__name__")',
                     "instant": True, "range": False}],
        # Une série par flux → labels en colonnes → une seule table → matrice CLIENT × SERVER.
        "transformations": [
            {"id": "labelsToFields", "options": {"mode": "columns"}},
            {"id": "merge", "options": {}},
            {"id": "groupingToMatrix",
             "options": {"columnField": column, "rowField": row, "valueField": "Value", "emptyValue": "null"}},
        ],
        "fieldConfig": {
            # Case vide (« — ») : flux que la configuration ne fait pas mesurer.
            "defaults": {"unit": unit, "decimals": decimals, "noValue": "—", "thresholds": thresholds,
                         "mappings": NO_DATA_MAPPING,
                         "custom": {"align": "center", "cellOptions": {"type": "color-background", "mode": "basic"}}},
            "overrides": [{"matcher": {"id": "byName", "options": f"{row}\\{column}"},
                           "properties": [{"id": "displayName", "value": corner},
                                          {"id": "custom.cellOptions", "value": {"type": "auto"}},
                                          {"id": "custom.align", "value": "left"},
                                          {"id": "unit", "value": "string"}]}],
        },
        "options": {"showHeader": True, "cellHeight": "lg", "footer": {"show": False}},
    }


EMPTY_CELLS = " Case « — » : flux non mesuré dans cette topologie ; « no data » : flux attendu sans mesure."


def matrix_dashboard():
    return dashboard("syntraf-matrix", "SYNTRAF — matrice source × destination", [
        matrix(1, "Pertes actuelles (%) — moyenne 30 s",
               current(f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[30s])", "30s"), "percent", 1, LOSS_STEPS, 0, 0,
               "Pertes mesurées par la destination sur les 30 dernières secondes." + EMPTY_CELLS),
        matrix(2, "Silence (s depuis le dernier point)",
               current(f"time() - tlast_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[1h])", "1h"), "s", 0, SILENCE_STEPS,
               12, 0, "Une cellule rouge = aucune mesure reçue : panne, ou SYNTRAF qui ne rapporte plus." + EMPTY_CELLS),
        matrix(3, "Pertes moyennes sur la période affichée (%)",
               only_expected(f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[$__range])"), "percent", 2, LOSS_STEPS, 0, 8,
               "Moyenne sur toute la plage de temps choisie en haut à droite, pour les flux actuellement mesurés."),
        matrix(4, "Gigue (ms) — moyenne 30 s",
               current(f"avg_over_time(SYNTRAF_RX_JITTER{{{SEL}}}[30s])", "30s"), "ms", 2, JITTER_STEPS, 12, 8),
        matrix(5, "Débit reçu (kbit/s) — moyenne 30 s",
               current(f"avg_over_time(SYNTRAF_RX_BITRATE{{{SEL}}}[30s])", "30s"), "Kbits", 1, BITRATE_STEPS, 0, 16,
               "Débit configuré du groupe : 100 kbit/s."),
        matrix(6, "Paquets perdus — total sur la période affichée",
               only_expected(f"sum_over_time(SYNTRAF_RX_PACKET_LOSS{{{SEL}}}[$__range])"), "none", 0,
               steps(("green", None), ("orange", 1), ("red", 100)), 12, 16),
    ], time_from="now-1h")


# ---------------------------------------------------------------------------
# Topologies à hubs
# ---------------------------------------------------------------------------
def hubs_dashboard():
    spoke_to_hub, hub_to_spoke, hub_to_hub = role("spoke", "hub"), role("hub", "spoke"), role("hub", "hub")
    loss = f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[30s])"
    jitter = f"avg_over_time(SYNTRAF_RX_JITTER{{{SEL}}}[30s])"
    silence = f"time() - tlast_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[1h])"
    hub_groups = 'SYNTRAF_FLOW_EXPECTED{TOPOLOGY=~"HUB_SPOKE|DUAL_HUB"}'
    variables = [var("mesh_group", "MESH_GROUP", hub_groups), var("client", "CLIENT"), var("server", "SERVER")]
    return dashboard("syntraf-hubs", "SYNTRAF — topologies à hubs", [
        matrix(1, "Spokes → hubs : pertes (%) — moyenne 30 s", current(loss, "30s", spoke_to_hub), "percent", 1,
               LOSS_STEPS, 0, 0, "Une ligne par spoke, une colonne par hub : ce que chaque hub reçoit du spoke. "
               "Avec deux hubs, comparer les deux colonnes désigne un hub (ou son chemin) dégradé.",
               corner="Spoke ↓ / Hub →"),
        matrix(2, "Hubs → spokes : pertes (%) — moyenne 30 s", current(loss, "30s", hub_to_spoke), "percent", 1,
               LOSS_STEPS, 12, 0, "Ce que chaque spoke reçoit de chaque hub.", row="SERVER", column="CLIENT",
               corner="Spoke ↓ / Hub →"),
        matrix(3, "Spokes → hubs : gigue (ms) — moyenne 30 s", current(jitter, "30s", spoke_to_hub), "ms", 2,
               JITTER_STEPS, 0, 8, corner="Spoke ↓ / Hub →"),
        matrix(4, "Spokes → hubs : silence (s depuis le dernier point)", current(silence, "1h", spoke_to_hub), "s",
               0, SILENCE_STEPS, 12, 8, corner="Spoke ↓ / Hub →"),
        stat(5, "Liaison entre les hubs : pertes (%) — moyenne 30 s", current(loss, "30s", hub_to_hub), "percent",
             LOSS_STEPS, 0, 16, w=24, h=4, description="Deux hubs seulement : les deux sens de leur liaison."),
        timeseries(6, "Pertes moyennes des spokes vers chaque hub (%)",
                   f"avg by (MESH_GROUP, SERVER) ({only_expected(f'SYNTRAF_RX_PCT_LOSS{{{SEL}}}', spoke_to_hub)})",
                   "percent", 0, 20, {"min": 0, "max": 100}, legend="{{MESH_GROUP}} · hub {{SERVER}}", w=24),
    ], time_from="now-1h", variables=variables)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, dash in (("syntraf.json", series_dashboard()), ("syntraf-matrix.json", matrix_dashboard()),
                       ("syntraf-hubs.json", hubs_dashboard())):
        (OUT / name).write_text(json.dumps(dash, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"écrit : {OUT / name}")


if __name__ == "__main__":
    main()

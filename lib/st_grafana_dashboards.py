#!/usr/bin/env python3
"""Tableaux de bord Grafana de SYNTRAF (source VictoriaMetrics « syntraf-vm »), générés en Python : écrits en fichiers
pour le lab (lab/grafana/build_dashboards.py), ou poussés dans un Grafana par l'interface (lib/st_grafana_deploy.py).

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

DS = {"type": "prometheus", "uid": "syntraf-vm"}
SEL = 'MESH_GROUP=~"$mesh_group",CLIENT=~"$client",SERVER=~"$server"'
LEG = "{{CLIENT}} → {{SERVER}}"
# Ordre de lecture : du général au particulier. Les titres sont numérotés dans cet ordre (le dossier SYNTRAF de
# Grafana donne déjà le contexte : pas de préfixe « SYNTRAF — » qui allongeait chaque bouton de navigation).
NAV = (("syntraf-lab", "Vue d'ensemble"), ("syntraf-matrix", "Matrices"), ("syntraf-quality", "Qualité voix et latence"),
       ("syntraf-tcp", "Tests TCP"), ("syntraf-hubs", "Hubs"), ("syntraf-correlation", "Corrélations"),
       ("syntraf-health", "Santé de SYNTRAF"))
LINKS = [{"title": f"{i} · {name}", "type": "link", "url": f"/d/{uid}", "icon": "dashboard", "asDropdown": False,
          "includeVars": True, "keepTime": True, "targetBlank": False, "tooltip": "", "tags": []}
         for i, (uid, name) in enumerate(NAV, start=1)]


def nav_title(uid):
    return next(f"{i} · {name}" for i, (u, name) in enumerate(NAV, start=1) if u == uid)
KEYS = "MESH_GROUP,CLIENT,SERVER"
NO_DATA = -1  # flux attendu sans aucune mesure dans la fenêtre
NAT_PAIR = -2  # deux sondes derrière un NAT : jamais mesurées, aucune ne peut joindre l'autre
DSCP_INTACT = -3  # marquage DSCP conservé de bout en bout (matrice « DSCP réécrit en »)
NO_DATA_MAPPING = [{"type": "value", "options": {str(NO_DATA): {"text": "no data", "color": "red", "index": 0}}},
                   # case vide (flux non mesuré, diagonale) : neutre, et non la couleur du premier seuil (rouge pour
                   # le MOS ou un débit)
                   {"type": "special", "options": {"match": "null", "result": {"text": "—", "color": "transparent",
                                                                                "index": 1}}},
                   {"type": "value", "options": {str(NAT_PAIR): {"text": "NAT ↔ NAT", "color": "transparent",
                                                                 "index": 2}}}]
NAT_NOTE = " « NAT ↔ NAT » : deux sondes derrière un NAT ne peuvent pas se joindre ; la paire n'est pas mesurée."
ANNOTATIONS = {"list": [{
    "name": "Changements de configuration", "datasource": DS, "enable": True, "iconColor": "orange",
    "expr": "last_over_time(SYNTRAF_CONFIG_CHANGE[1m])", "step": "60s",
    "titleFormat": "{{ACTION}}", "textFormat": "{{SUMMARY}} — {{ACTOR}}", "useValueForTime": False}, {
    # Alertes hors baseline (lib/st_baseline.py) : ouverture et fermeture, sur toutes les courbes
    "name": "Alertes", "datasource": DS, "enable": True, "iconColor": "red",
    "expr": "last_over_time(SYNTRAF_ALERT_EVENT[1m])", "step": "60s",
    "titleFormat": "Alerte {{ACTION}} · {{METRIC}} · {{FLOW}}", "textFormat": "{{MESH_GROUP}} — {{SUMMARY}}",
    "useValueForTime": False}, {
    # Démarrage du serveur, sonde reconnectée, mise à jour installée, retour arrière (lib/st_lifecycle.py)
    "name": "Redémarrages et mises à jour", "datasource": DS, "enable": True, "iconColor": "blue",
    "expr": "last_over_time(SYNTRAF_LIFECYCLE_EVENT[1m])", "step": "60s",
    "titleFormat": "{{EVENT}} · {{SUBJECT}}", "textFormat": "{{SUMMARY}}", "useValueForTime": False}, {
    # Fenêtres de maintenance actives (lib/st_maintenance.py) : zones, alertes suspendues
    "name": "Maintenance", "datasource": DS, "enable": True, "iconColor": "purple",
    "expr": "max by (UID, TARGET_TYPE, TARGET, DESCRIPTION) (SYNTRAF_MAINTENANCE_ACTIVE)", "step": "60s",
    "titleFormat": "Maintenance {{UID}} · {{TARGET}}", "textFormat": "{{DESCRIPTION}} — alertes suspendues",
    "useValueForTime": False}]}
ALERT_HELP = ("Alertes hors baseline de SYNTRAF (page Alertes de l'interface) : une mesure sortie de la norme apprise "
              "de son flux, du mauvais côté. Les flux encore en apprentissage (moins de 24 h d'historique) n'y "
              "figurent pas.")


def steps(*pairs):
    """steps(("green", None), ("orange", 5)) → seuils Grafana."""
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in pairs]}


LOSS_STEPS = steps(("green", None), ("yellow", 1), ("orange", 5), ("red", 20))
# Courbes de pertes : en rouge (nuances distinctes par flux, pour les reconnaître dans la légende)
LOSS_COLOR = {"color": {"mode": "shades", "fixedColor": "red"}}
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


# Dans les mesures, CLIENT est l'émetteur et SERVER le récepteur : les filtres le disent en clair
TITLES = {"MESH_GROUP": "Groupe", "CLIENT": "Source", "SERVER": "Destination", "TEST": "Test", "DIRECTION": "Sens"}


def var(name, label, metric="SYNTRAF_RX_PCT_LOSS", title=None):
    q = f"label_values({metric}, {label})"
    return {"name": name, "label": title or TITLES.get(label, label), "type": "query", "datasource": DS,
            "query": {"query": q, "refId": "v"}, "definition": q,
            "includeAll": True, "multi": True, "allValue": ".*", "refresh": 2, "sort": 1,
            "current": {"selected": True, "text": ["All"], "value": ["$__all"]}}


BANNER_H = 5  # en-tête et deux groupes sans défilement
GROUP_COLUMNS = (("MESH_GROUP", "Groupe"), ("TOPOLOGY", "Topologie"), ("HUBS", "Hubs"), ("PROFILE", "Profil"),
                 ("BANDWIDTH", "Débit par flux"), ("PPS", "Paquets/s"), ("PACKET_SIZE", "Taille de paquet"),
                 ("DSCP", "DSCP"), ("INTERVAL", "Intervalle"), ("MEMBERS", "Membres"), ("FLOWS", "Flux"))


def group_banner():
    """Paramètres en vigueur de chaque groupe (profil appliqué), publiés par le serveur avec les flux attendus."""
    metric = 'SYNTRAF_GROUP_INFO{MESH_GROUP=~"$mesh_group"}'
    last = f"tlast_over_time({metric}[90s])"
    keep = [k for k, _ in GROUP_COLUMNS]
    return {"id": 100, "type": "table", "title": "Paramètres des groupes", "datasource": DS,
            "description": "Valeurs en vigueur, profil appliqué. Paquets/s = débit par flux ÷ (taille × 8).",
            "gridPos": {"x": 0, "y": 0, "w": 24, "h": BANNER_H},
            "targets": [{"refId": "A", "datasource": DS, "instant": True, "format": "table",
                         "expr": f"last_over_time({metric}[90s]) and ({last} >= scalar(max({last})) - 5)"}],
            "transformations": [{"id": "organize", "options": {
                "excludeByName": {"Time": True, "Value": True, "__name__": True},
                "indexByName": {k: i for i, k in enumerate(keep)},
                "renameByName": dict(GROUP_COLUMNS)}}],
            "fieldConfig": {"defaults": {"custom": {"align": "left"}}, "overrides": []},
            "options": {"showHeader": True, "cellHeight": "sm"}}


def expected_bitrate():
    """Débit configuré par flux, à superposer au débit reçu."""
    return {"refId": "B", "datasource": DS, "legendFormat": "débit prévu · {{MESH_GROUP}}",
            "expr": 'max by (MESH_GROUP) (last_over_time(SYNTRAF_GROUP_BANDWIDTH_KBPS{MESH_GROUP=~"$mesh_group"}[40s]))'}


def layout(sections, y=0):
    """Place les panneaux section par section : une ligne de titre (repliable) puis les panneaux de gauche à droite,
    à la ligne quand la largeur (24) est atteinte. Plus de positions calculées à la main."""
    out, rid = [], 200
    for title, panels in sections:
        if title:
            out.append({"id": rid, "type": "row", "title": title, "collapsed": False, "panels": [],
                        "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}})
            rid, y = rid + 1, y + 1
        x, line_h = 0, 0
        for p in panels:
            w, h = p["gridPos"]["w"], p["gridPos"]["h"]
            if x + w > 24:
                x, y, line_h = 0, y + line_h, 0
            p["gridPos"] = {"x": x, "y": y, "w": w, "h": h}
            x, line_h = x + w, max(line_h, h)
            out.append(p)
        y += line_h
    for i, p in enumerate((p for p in out if p["type"] != "row"), start=1):
        p["id"] = i
    return out


def dashboard(uid, sections, refresh="5s", time_from="now-15m", variables=None, banner=True, annotations=True):
    panels = layout(sections, BANNER_H if banner else 0)
    if banner:  # le bandeau des paramètres occupe le haut
        panels = [group_banner()] + panels
    notes = json.loads(json.dumps(ANNOTATIONS))
    notes["list"][0]["enable"] = annotations  # changements de configuration ; les alertes restent toujours visibles
    return {"uid": uid, "title": nav_title(uid), "tags": ["syntraf", "lab"], "timezone": "browser",
            "schemaVersion": 39, "version": 1, "editable": False, "refresh": refresh,
            "time": {"from": time_from, "to": "now"}, "links": LINKS,
            "templating": {"list": variables or [var("mesh_group", "MESH_GROUP"), var("client", "CLIENT"),
                                                 var("server", "SERVER")]},
            "annotations": notes, "panels": panels}


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
    bitrate = timeseries(3, "Débit reçu", f"SYNTRAF_RX_BITRATE{{{SEL}}}", "Kbits", 0, 0)
    bitrate["targets"].append(expected_bitrate())
    bitrate["fieldConfig"]["overrides"].append({
        "matcher": {"id": "byFrameRefID", "options": "B"},
        "properties": [{"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
                       {"id": "custom.fillOpacity", "value": 0}, {"id": "color", "value": {"mode": "fixed", "fixedColor": "#aaaaaa"}}]})
    tcp_sel = 'MESH_GROUP=~"$mesh_group"'
    alert_now = f'last_over_time(SYNTRAF_BASELINE_ALERT{{{SEL},METRIC!="tcp"}}[3m])'
    open_count = matrix(8, "Alertes ouvertes", f"sum by (CLIENT, SERVER) ({alert_now})", "none", 0,
                        steps(("green", None), ("red", 1)), 0, 0,
                        ALERT_HELP + " Nombre de métriques en alerte sur chaque flux ; « OK » : aucune.")
    open_count["fieldConfig"]["defaults"]["mappings"] = open_count["fieldConfig"]["defaults"]["mappings"] + [
        {"type": "value", "options": {"0": {"text": "OK", "color": "green", "index": 4}}}]
    detail = {"id": 9, "type": "table", "title": "Alertes ouvertes · détail", "datasource": DS,
              "description": ALERT_HELP + " Écart : 1 = au seuil, 2 = deux fois plus loin que le seuil.",
              "gridPos": {"x": 0, "y": 0, "w": 12, "h": 10},
              "targets": [{"refId": "A", "datasource": DS, "instant": True, "format": "table",
                           "expr": f'last_over_time(SYNTRAF_BASELINE_SCORE{{{SEL}}}[3m]) and on(MESH_GROUP, CLIENT, '
                                   f'SERVER, METRIC, DIRECTION, TEST) (last_over_time(SYNTRAF_BASELINE_ALERT{{{SEL}}}'
                                   f'[3m]) == 1)'}],
              "transformations": [{"id": "organize", "options": {
                  "excludeByName": {"Time": True, "__name__": True},
                  "indexByName": {"MESH_GROUP": 0, "CLIENT": 1, "SERVER": 2, "METRIC": 3, "Value": 4},
                  "renameByName": {"MESH_GROUP": "Groupe", "CLIENT": "Source", "SERVER": "Destination",
                                   "METRIC": "Métrique", "Value": "Écart (× seuil)", "DIRECTION": "Sens",
                                   "TEST": "Test"}}}],
              "fieldConfig": {"defaults": {"decimals": 1, "noValue": "Aucune alerte ouverte",
                                           "custom": {"align": "left"}}, "overrides": []},
              "options": {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}}
    return dashboard("syntraf-lab", [
        ("Alertes", [open_count, detail]),
        ("Maintenant", [
            matrix(1, "Pertes · 30 s", current(f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[30s])", "30s"), "percent",
                   1, LOSS_STEPS, 0, 0, "Pertes mesurées par la destination sur les 30 dernières secondes." + EMPTY_CELLS),
            matrix(2, "Silence (s sans mesure)",
                   current(f"time() - tlast_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[1h])", "1h"), "s", 0, SILENCE_STEPS,
                   0, 0, "Secondes depuis la dernière mesure. Rouge : plus rien n'arrive (panne, ou SYNTRAF qui ne "
                         "rapporte plus)." + EMPTY_CELLS),
        ]),
        ("Évolution", [
            timeseries(2, "Pertes", f"SYNTRAF_RX_PCT_LOSS{{{SEL}}}", "percent", 0, 0, {"min": 0, "max": 100, **LOSS_COLOR}),
            bitrate,
            timeseries(4, "Gigue", f"SYNTRAF_RX_JITTER{{{SEL}}}", "ms", 0, 0),
            timeseries(5, "Paquets perdus par intervalle", f"SYNTRAF_RX_PACKET_LOSS{{{SEL}}}", "none", 0, 0, LOSS_COLOR),
        ]),
        ("Derniers tests TCP", [
            matrix(6, "Débit TCP · dernier test", tcp_latest("BITRATE_MBPS", tcp_sel), "Mbits", 1, TCP_RATE_STEPS, 0, 0,
                   TCP_HELP, row="SRC", column="DST"),
            tcp_series(7, "Débit TCP", "BITRATE_MBPS", "Mbits", tcp_sel, log=True),
        ]),
    ])


# ---------------------------------------------------------------------------
# Matrices source × destination
# ---------------------------------------------------------------------------
def nat_pairs(row, column):
    """Paires de sondes toutes deux derrière un NAT (publiées par le serveur), valeur NAT_PAIR, sous les noms de
    ligne et de colonne de la matrice."""
    sel = SEL if (row, column) == ("CLIENT", "SERVER") else 'MESH_GROUP=~"$mesh_group"'
    pairs = f"max by (CLIENT, SERVER) (last_over_time(SYNTRAF_FLOW_NAT_PAIR{{{sel}}}[90s]))"
    if (row, column) == ("SRC", "DST"):
        pairs = (f'max by (SRC, DST) (label_replace(label_replace({pairs}, "SRC", "$1", "CLIENT", "(.*)"), '
                 f'"DST", "$1", "SERVER", "(.*)"))')
    return f"({pairs} * 0 + {NAT_PAIR})"


def matrix(pid, title, expr, unit, decimals, thresholds, x, y, description="", row="CLIENT", column="SERVER",
           corner="De ↓  Vers →", w=12, h=10, nat=None):
    if nat is None:  # matrices sonde × sonde ; pas les hubs (spokes × hubs) ni les corrélations (flux × flux)
        nat = (row, column) in (("CLIENT", "SERVER"), ("SRC", "DST"))
    if nat:
        expr = f"(({expr}) or ({nat_pairs(row, column)} unless on({row}, {column}) ({expr})))"
        description = (description + NAT_NOTE).strip()
    return {
        "id": pid, "type": "table", "title": title, "description": description, "datasource": DS,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        # Sans nom de métrique, le champ numérique s'appelle toujours « Value ».
        # Séries triées par colonne puis ligne : la matrice prend ses colonnes dans l'ordre où elle les rencontre
        "targets": [{"refId": "A", "datasource": DS,
                     "expr": f'sort_by_label(label_del({expr}, "__name__"), "{column}", "{row}")',
                     "instant": True, "range": False}],
        # Une série par flux → labels en colonnes → une seule table → matrice ligne × colonne.
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
                         # 150 px par défaut : au-delà de 4 sondes, la dernière colonne était coupée
                         "custom": {"align": "center", "minWidth": 70,
                                    "cellOptions": {"type": "color-background", "mode": "basic"}}},
            "overrides": [{"matcher": {"id": "byName", "options": f"{row}\\{column}"},
                           "properties": [{"id": "displayName", "value": corner},
                                          {"id": "custom.cellOptions", "value": {"type": "auto"}},
                                          {"id": "custom.align", "value": "left"},
                                          {"id": "custom.width", "value": 120},
                                          {"id": "unit", "value": "string"}]}],
        },
        "options": {"showHeader": True, "cellHeight": "md", "footer": {"show": False},
                    "sortBy": [{"displayName": corner, "desc": False}]},  # lignes dans l'ordre alphabétique
    }


EMPTY_CELLS = " Case « — » : flux non mesuré dans cette topologie ; « no data » : flux attendu sans mesure."


def matrix_dashboard():
    return dashboard("syntraf-matrix", [
        ("Maintenant · 30 s", [
            matrix(1, "Pertes", current(f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[30s])", "30s"), "percent", 1,
                   LOSS_STEPS, 0, 0, "Pertes mesurées par la destination sur les 30 dernières secondes." + EMPTY_CELLS),
            matrix(2, "Silence (s sans mesure)",
                   current(f"time() - tlast_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[1h])", "1h"), "s", 0, SILENCE_STEPS,
                   0, 0, "Une cellule rouge = aucune mesure reçue : panne, ou SYNTRAF qui ne rapporte plus." + EMPTY_CELLS),
            matrix(4, "Gigue", current(f"avg_over_time(SYNTRAF_RX_JITTER{{{SEL}}}[30s])", "30s"), "ms", 2,
                   JITTER_STEPS, 0, 0),
            matrix(5, "Débit reçu", current(f"avg_over_time(SYNTRAF_RX_BITRATE{{{SEL}}}[30s])", "30s"), "Kbits", 1,
                   BITRATE_STEPS, 0, 0, "Comparer au débit par flux du bandeau « Paramètres des groupes »."),
        ]),
        ("Sur la période affichée", [
            matrix(3, "Pertes moyennes",
                   only_expected(f"avg_over_time(SYNTRAF_RX_PCT_LOSS{{{SEL}}}[$__range])"), "percent", 2, LOSS_STEPS,
                   0, 0, "Moyenne sur toute la plage de temps choisie en haut à droite, pour les flux actuellement "
                         "mesurés."),
            matrix(6, "Paquets perdus (total)",
                   only_expected(f"sum_over_time(SYNTRAF_RX_PACKET_LOSS{{{SEL}}}[$__range])"), "none", 0,
                   steps(("green", None), ("orange", 1), ("red", 100)), 0, 0),
        ]),
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
    spoke = "Spoke ↓  Hub →"
    return dashboard("syntraf-hubs", [
        ("Spokes → hubs · 30 s", [
            matrix(1, "Pertes", current(loss, "30s", spoke_to_hub), "percent", 1, LOSS_STEPS, 0, 0,
                   "Une ligne par spoke, une colonne par hub : ce que chaque hub reçoit du spoke. Avec deux hubs, "
                   "comparer les deux colonnes désigne un hub (ou son chemin) dégradé.", corner=spoke, nat=False),
            matrix(3, "Gigue", current(jitter, "30s", spoke_to_hub), "ms", 2, JITTER_STEPS, 0, 0, corner=spoke, nat=False),
            matrix(4, "Silence (s sans mesure)", current(silence, "1h", spoke_to_hub), "s", 0, SILENCE_STEPS, 0, 0,
                   corner=spoke, nat=False),
            timeseries(6, "Pertes moyennes vers chaque hub",
                       f"avg by (MESH_GROUP, SERVER) ({only_expected(f'SYNTRAF_RX_PCT_LOSS{{{SEL}}}', spoke_to_hub)})",
                       "percent", 0, 0, {"min": 0, "max": 100, **LOSS_COLOR}, legend="{{MESH_GROUP}} · hub {{SERVER}}"),
        ]),
        ("Hubs → spokes · 30 s", [
            matrix(2, "Pertes", current(loss, "30s", hub_to_spoke), "percent", 1, LOSS_STEPS, 0, 0,
                   "Ce que chaque spoke reçoit de chaque hub.", row="SERVER", column="CLIENT", corner=spoke, nat=False),
            stat(5, "Liaison entre les hubs · pertes", current(loss, "30s", hub_to_hub), "percent", LOSS_STEPS, 0, 0,
                 w=12, h=10, description="Deux hubs seulement : les deux sens de leur liaison."),
        ]),
    ], time_from="now-1h", variables=variables)


# ---------------------------------------------------------------------------
# Corrélations (calculées par le serveur, lib/st_correlation.py)
# ---------------------------------------------------------------------------
# -1 bleu (opposés), autour de 0 gris (indépendants), vers 1 orange puis rouge (ils se dégradent ensemble)
CORRELATION_STEPS = steps(("#3274d9", None), ("#555555", -0.3), ("#555555", 0.3), ("orange", 0.5), ("red", 0.8))


def correlation_dashboard():
    help_text = ("Corrélation de Pearson entre flux sur les 15 dernières minutes (un point toutes les 10 s), "
                 "recalculée chaque minute par le serveur. Rouge : ces flux se dégradent ensemble (lien, équipement "
                 "ou goulot commun probable). Les flux sans variation (aucune perte) n'apparaissent pas.")
    return dashboard("syntraf-correlation", [(None, [
        matrix(1, "Corrélation des pertes", "last_over_time(SYNTRAF_CORRELATION_LOSS[5m])", "none", 2,
               CORRELATION_STEPS, 0, 0, help_text, row="FLOW_A", column="FLOW_B", corner="Flux ↓  Flux →", w=24, h=12),
        matrix(2, "Corrélation de la gigue", "last_over_time(SYNTRAF_CORRELATION_JITTER[5m])", "none", 2,
               CORRELATION_STEPS, 0, 0, help_text, row="FLOW_A", column="FLOW_B", corner="Flux ↓  Flux →", w=24, h=12),
    ])], refresh="1m", time_from="now-15m", variables=[], banner=False)


# ---------------------------------------------------------------------------
# Qualité perçue : MOS de la voix (modèle E) et rafales de pertes (lib/st_quality.py)
# ---------------------------------------------------------------------------
# Satisfaction des utilisateurs selon G.107 : R 60/70/80 ↔ MOS 3.1/3.6/4.0
MOS_STEPS = steps(("red", None), ("orange", 3.1), ("yellow", 3.6), ("green", 4.0))
BURST_RATIO_STEPS = steps(("green", None), ("yellow", 1.5), ("orange", 3), ("red", 6))
LONGEST_STEPS = steps(("green", None), ("yellow", 2), ("orange", 5), ("red", 10))
HEAVY_STEPS = steps(("green", None), ("yellow", 25), ("orange", 50), ("red", 75))
# RTT : la voix supporte 150 ms dans un sens (UIT-T G.114), soit 300 ms aller-retour
RTT_STEPS = steps(("green", None), ("yellow", 100), ("orange", 200), ("red", 300))
REORDER_STEPS = steps(("green", None), ("yellow", 0.5), ("orange", 2), ("red", 5))
DUP_STEPS = steps(("green", None), ("yellow", 1), ("orange", 10), ("red", 100))


def dscp_rewritten():
    """Par flux : la valeur réécrite là où le DSCP n'a pas été conservé (moins de 100 % des échos), DSCP_INTACT
    sinon. Une paire reliée par plusieurs groupes montre une réécriture dès qu'un seul groupe la subit (max : une
    valeur réécrite, toujours ≥ 0, l'emporte sur « intact »)."""
    def one(suffix):
        ok = f"avg_over_time(SYNTRAF_LATENCY_DSCP_OK_PCT_{suffix}{{{SEL}}}[1m])"
        recv = f"last_over_time(SYNTRAF_LATENCY_DSCP_RECV_{suffix}{{{SEL}}}[1m])"
        return f"(({recv} and on(MESH_GROUP, CLIENT, SERVER, UID) ({ok} < 100)) or (({ok} == 100) * 0 + {DSCP_INTACT}))"
    fwd = one("FWD")
    swapped = (f'label_replace(label_replace(label_replace({fwd}, "PEER", "$1", "CLIENT", "(.*)"), '
               f'"CLIENT", "$1", "SERVER", "(.*)"), "SERVER", "$1", "PEER", "(.*)")')
    return f'max by (CLIENT, SERVER) ({one("REV")} or label_del({swapped}, "PEER"))'


def per_flow(metric, fn, agg="max"):
    """Mesure d'écho par sens → par flux (émetteur CLIENT, récepteur SERVER) : le sens retour est déjà étiqueté ainsi
    (CLIENT = pair, SERVER = sonde qui mesure) ; le sens aller a ses étiquettes inversées."""
    rev = f"{fn}(SYNTRAF_LATENCY_{metric}_REV{{{SEL}}}[1m])" if fn == "avg_over_time" else         f"{fn}(SYNTRAF_LATENCY_{metric}_REV{{{SEL}}}[15m])"
    fwd = rev.replace(f"{metric}_REV", f"{metric}_FWD")
    swapped = (f'label_replace(label_replace(label_replace({fwd}, "PEER", "$1", "CLIENT", "(.*)"), '
               f'"CLIENT", "$1", "SERVER", "(.*)"), "SERVER", "$1", "PEER", "(.*)")')
    return f"{agg} by (CLIENT, SERVER) ({rev} or {swapped})"


def symmetric(expr):
    """Mesure d'une paire (RTT) : la sonde qui mesure range la valeur sous CLIENT = pair, SERVER = elle-même ; le sens
    inverse reprend la même valeur (sinon « no data » sur la ligne d'une sonde derrière un NAT, qui seule mesure)."""
    swapped = (f'label_replace(label_replace(label_replace({expr}, "PEER", "$1", "CLIENT", "(.*)"), '
               f'"CLIENT", "$1", "SERVER", "(.*)"), "SERVER", "$1", "PEER", "(.*)")')
    return f'max by (MESH_GROUP, CLIENT, SERVER) (({expr}) or label_del({swapped}, "PEER"))'


def dscp_matrix():
    p = matrix(12, "DSCP réécrit en", dscp_rewritten(), "none", 0, steps(("red", None)), 0, 0,
               "« intact » : chaque écho est arrivé avec le DSCP de son groupe. Une valeur (en rouge) : le DSCP "
               "devenu, sur ce sens du chemin, celui d'au moins un groupe ; le DSCP envoyé est dans le bandeau du "
               "haut (filtrer sur un groupe quand plusieurs relient la paire).")
    p["fieldConfig"]["defaults"]["mappings"] = p["fieldConfig"]["defaults"]["mappings"] + [
        {"type": "value", "options": {str(DSCP_INTACT): {"text": "intact", "color": "green", "index": 3}}}]
    return p


def quality_dashboard():
    mos = f"avg_over_time(SYNTRAF_RX_MOS{{{SEL}}}[1m])"
    rtt = f"avg_over_time(SYNTRAF_LATENCY_RTT_MS{{{SEL}}}[1m])"
    order_help = ("Par flux (émetteur en ligne, récepteur en colonne), mesuré par l'écho de latence : 10 paquets "
                  "espacés de 20 ms comme la voix, avec le DSCP du mesh group. Réordonné : arrivé après un paquet "
                  "envoyé plus tard (RFC 4737). Dupliqué : reçu deux fois. iperf3 ne publie ni l'un ni l'autre "
                  "pendant un test continu (seulement dans son résumé de fin).")
    rtt_help = ("Aller-retour entre les deux sondes (TWAMP-Light, 10 échos par intervalle, avec le DSCP du mesh "
                "group), le même dans les deux sens. Une sonde derrière un NAT mesure toujours elle-même. Sert au MOS "
                "(latence d'un sens = RTT / 2). Rouge : au-delà de 300 ms (150 ms dans un sens, G.114).")
    burst = lambda m: f"last_over_time(SYNTRAF_LOSS_BURST_{m}{{{SEL}}}[5m])"  # noqa: E731
    mos_help = ("Note de qualité d'une voix sur chaque flux (1 à 4.5), modèle E de l'UIT-T G.107, pour le codec du "
                "profil du mesh group (G.711 par défaut) : pertes, gigue (tampon), délai du codec et latence, "
                "mesurée par écho (RTT / 2), quand elle est disponible. "
                "Vert : très satisfaisant ; jaune : satisfaisant ; orange : certains insatisfaits ; rouge : mauvais.")
    burst_help = ("Sur les 15 dernières minutes, à la seconde (iperf3 ne donne pas le détail par paquet). Une rafale "
                  "est une suite de secondes à au moins 10 % de pertes. Ratio de rafale : 1 = ces mauvaises secondes "
                  "tombent au hasard, plus de 1 = elles se regroupent (bien plus gênant pour la voix). 0 : aucune "
                  "rafale.")
    dscp_help = ("Par flux (émetteur en ligne, récepteur en colonne), vérifié sur l'écho de latence, qui porte le "
                 "DSCP du mesh group : part des paquets arrivés avec ce DSCP, et la valeur reçue. Moins de 100 % : un "
                 "équipement ou un opérateur réécrit le marquage, la priorité de service est perdue sur ce chemin. "
                 "Chaque sens est vérifié seul (le réflecteur répond avec le DSCP voulu, pas celui reçu). Vide : "
                 "sonde sous Windows ou version plus ancienne.")
    reorder = per_flow("REORDER", "avg_over_time").replace("_REORDER_REV", "_REORDER_REV_PCT") \
        .replace("_REORDER_FWD", "_REORDER_FWD_PCT")
    return dashboard("syntraf-quality", [
        ("Voix · MOS", [
            matrix(1, "MOS · 1 min", current(mos, "1m"), "none", 2, MOS_STEPS, 0, 0, mos_help),
            timeseries(2, "MOS par flux", mos, "none", 0, 0, {"min": 1, "max": 4.5}),
        ]),
        ("Latence", [
            matrix(6, "RTT · 1 min", current(symmetric(rtt), "1m"), "ms", 1, RTT_STEPS, 0, 0, rtt_help),
            timeseries(7, "RTT par paire", rtt, "ms", 0, 0, {"min": 0}),
            timeseries(8, "Échos perdus", f"avg_over_time(SYNTRAF_LATENCY_LOSS_PCT{{{SEL}}}[1m])", "percent", 0, 0,
                       {"min": 0, "max": 100, **LOSS_COLOR}, w=24),
        ]),
        ("Rafales de pertes · 15 min", [
            matrix(3, "Ratio de rafale", burst("BURST_RATIO"), "none", 1, BURST_RATIO_STEPS, 0, 0, burst_help),
            matrix(4, "Plus longue rafale", burst("LONGEST_S"), "s", 0, LONGEST_STEPS, 0, 0, burst_help),
            matrix(5, "Pertes en secondes lourdes (≥ 20 %)", burst("HEAVY_SHARE"), "percent", 0, HEAVY_STEPS, 0, 0,
                   burst_help),
        ]),
        ("Marquage DSCP", [
            matrix(11, "DSCP conservé · 1 min", per_flow("DSCP_OK_PCT", "avg_over_time", "min"), "percent", 0,
                   steps(("red", None), ("orange", 50), ("yellow", 99), ("green", 100)), 0, 0, dscp_help),
            dscp_matrix(),
        ]),
        ("Ordre des paquets", [
            matrix(9, "Réordonnés · 1 min", reorder, "percent", 1, REORDER_STEPS, 0, 0, order_help),
            matrix(10, "Dupliqués · 15 min", per_flow("DUP", "sum_over_time"), "none", 0, DUP_STEPS, 0, 0, order_help),
        ]),
    ], refresh="30s", time_from="now-1h")


TCP_RATE_STEPS = steps(("red", None), ("orange", 1), ("yellow", 10), ("green", 50))
TCP_HELP = ("Tests TCP planifiés (page Tests TCP de SYNTRAF), un point par test. Lu dans le sens des données : en "
            "ligne la sonde qui envoie, en colonne celle qui reçoit. Débit reçu, sans les premières secondes (-O).")


def tcp_flow(expr):
    """Résultat d'un test → sens des données : SRC envoie, DST reçoit. SERVER est la sonde qui initie, CLIENT son
    pair ; en upload l'initiateur envoie, en download (-R) il reçoit. DIRECTION_SEL marque le sélecteur du sens."""
    up = expr.replace("DIRECTION_SEL", 'DIRECTION="upload"')
    down = expr.replace("DIRECTION_SEL", 'DIRECTION="download"')
    up = f'label_replace(label_replace({up}, "SRC", "$1", "SERVER", "(.*)"), "DST", "$1", "CLIENT", "(.*)")'
    down = f'label_replace(label_replace({down}, "SRC", "$1", "CLIENT", "(.*)"), "DST", "$1", "SERVER", "(.*)")'
    return f"({up} or {down})"


def tcp_latest(metric, sel):
    """Dernier résultat de chaque sens de chaque paire (le plus haut si plusieurs tâches les testent)."""
    return f"max by (SRC, DST) ({tcp_flow(f'last_over_time(SYNTRAF_TCP_{metric}{{{sel},DIRECTION_SEL}}[7d])')})"


def tcp_series(pid, title, metric, unit, sel, log=False, w=12):
    p = timeseries(pid, title, tcp_flow(f"SYNTRAF_TCP_{metric}{{{sel},DIRECTION_SEL}}"), unit, 0, 0,
                   legend="{{SRC}} → {{DST}} · {{TEST}}", w=w)
    p["fieldConfig"]["defaults"]["custom"].update(
        {"lineWidth": 1, "fillOpacity": 0, "spanNulls": True, "showPoints": "always", "pointSize": 6})
    if log:  # de quelques Mbit/s (radio, satellite) à des dizaines de Gbit/s (lab) : une échelle linéaire écrase tout
        p["fieldConfig"]["defaults"]["custom"]["scaleDistribution"] = {"type": "log", "log": 10}
    else:
        p["fieldConfig"]["defaults"]["min"] = 0
    p["options"]["legend"]["calcs"] = ["lastNotNull", "mean", "max"]
    p["description"] = TCP_HELP
    return p


def tcp_dashboard():
    sel = 'MESH_GROUP=~"$mesh_group",CLIENT=~"$client",SERVER=~"$server",TEST=~"$test",DIRECTION=~"$direction"'
    failed = f"sum by (SRC, DST) ({tcp_flow(f'sum_over_time(SYNTRAF_TCP_FAILED{{{sel},DIRECTION_SEL}}[$__range])')})"
    m = "SYNTRAF_TCP_BITRATE_MBPS"
    variables = [var("mesh_group", "MESH_GROUP", m), var("test", "TEST", m), var("direction", "DIRECTION", m),
                 var("server", "SERVER", m, "Initiateur"), var("client", "CLIENT", m, "Pair")]
    return dashboard("syntraf-tcp", [
        ("Derniers résultats", [
            matrix(1, "Débit · dernier test", tcp_latest("BITRATE_MBPS", sel), "Mbits", 1, TCP_RATE_STEPS, 0, 0,
                   TCP_HELP, row="SRC", column="DST"),
            matrix(2, "Retransmissions · dernier test", tcp_latest("RETRANSMITS", sel), "none", 0,
                   steps(("green", None), ("yellow", 10), ("orange", 100), ("red", 1000)), 0, 0, TCP_HELP,
                   row="SRC", column="DST"),
            matrix(3, "Échecs sur la période", failed, "none", 0, steps(("green", None), ("red", 1)), 0, 0,
                   "Tests qui n'ont pas abouti : pair injoignable, port fermé, authentification refusée, sonde en "
                   "cours de redémarrage…", row="SRC", column="DST"),
            matrix(4, "RTT TCP · dernier test", tcp_latest("RTT_MS", sel), "ms", 1, RTT_STEPS, 0, 0,
                   "RTT moyen vu par TCP pendant le test, charge comprise : à comparer au RTT à vide (tableau Qualité "
                   "voix et latence).", row="SRC", column="DST"),
        ]),
        ("Évolution", [
            tcp_series(5, "Débit", "BITRATE_MBPS", "Mbits", sel, log=True),
            tcp_series(6, "Retransmissions", "RETRANSMITS", "none", sel),
            tcp_series(7, "RTT TCP", "RTT_MS", "ms", sel),
            tcp_series(8, "Fenêtre de congestion maximale", "CWND_MAX_KB", "kbytes", sel),
        ]),
    ], refresh="1m", time_from="now-24h", variables=variables, banner=False, annotations=False)


def health_dashboard():
    """Santé de SYNTRAF lui-même : son endpoint /metrics, collecté par VictoriaMetrics (job « syntraf »)."""
    up_steps = steps(("red", None), ("green", 1))
    help_ = ("Collecté toutes les 15 s sur /metrics du serveur (Server › Interface web : collecteurs autorisés). "
             "Les mêmes contrôles lèvent des alertes dans l'interface (groupe « SYNTRAF »).")

    def state(pid, title, expr, legend, ok, bad, w=12):
        p = stat(pid, title, expr, "none", up_steps, 0, 0, w=w, h=5, description=help_)
        p["targets"][0]["legendFormat"] = legend
        p["fieldConfig"]["defaults"]["mappings"] = [
            {"type": "value", "options": {"1": {"text": ok, "color": "green", "index": 0},
                                          "0": {"text": bad, "color": "red", "index": 1}}}]
        return p

    def series(pid, title, expr, legend, w=12):
        p = timeseries(pid, title, expr, "none", 0, 0, {"min": 0}, legend=legend, w=w)
        p["description"] = help_
        return p
    def clock(pid, title, expr, unit, description, w=12):
        p = timeseries(pid, title, expr, unit, 0, 0, {}, legend="{{client}}", w=w)
        p["description"] = description
        return p
    return dashboard("syntraf-health", [
        ("Collecte", [
            state(1, "Collecte de /metrics", 'up{job="syntraf"}', "serveur", "collecté", "injoignable", w=24),
        ]),
        ("Sondes", [
            state(2, "Sondes", "syntraf_client_connected", "{{client}}", "connectée", "déconnectée", w=24),
            series(3, "Mesures en attente sur les sondes", "syntraf_client_buffered_points", "{{client}}"),
            series(4, "Flux iperf3 par sonde", "syntraf_client_flows", "{{client}} · {{role}}"),
            clock(9, "Horloge des sondes : écart au serveur",
                  "syntraf_client_clock_offset_seconds * 1000", "ms",
                  "Horloge du serveur moins celle de la sonde, mesurée en continu sur le canal de contrôle (comme NTP) : "
                  "positif, la sonde retarde. Alerte au-delà du seuil réglé dans Server › Global (1 s par défaut)."),
            clock(10, "Horloge des sondes : dérive", "syntraf_client_clock_drift_ppm", "ppm",
                  "Pente de l'écart sur la dernière heure, en millionièmes : positive, l'horloge de la sonde avance. "
                  "15 ppm ≈ 1,3 s par jour, une horloge sans synchronisation (NTP). Calculée après une heure de mesures."),
        ]),
        ("Serveur et bases", [
            state(5, "Bases de données", "syntraf_database_up", "{{database}}", "en ligne", "injoignable"),
            state(6, "Fils du serveur", "syntraf_thread_up", "{{thread}}", "actif", "arrêté"),
            series(7, "Points en attente d'écriture", "syntraf_database_backlog", "{{database}}"),
            series(8, "File du serveur", "syntraf_queue_length", "mesures reçues, pas encore transmises"),
        ]),
    ], refresh="30s", time_from="now-6h", variables=[], banner=False)



def all_dashboards():
    """[(nom de fichier, tableau)] dans l'ordre de lecture."""
    return [("syntraf.json", series_dashboard()), ("syntraf-matrix.json", matrix_dashboard()),
            ("syntraf-quality.json", quality_dashboard()), ("syntraf-tcp.json", tcp_dashboard()),
            ("syntraf-hubs.json", hubs_dashboard()), ("syntraf-correlation.json", correlation_dashboard()),
            ("syntraf-health.json", health_dashboard())]

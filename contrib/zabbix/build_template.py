#!/usr/bin/env python3
"""Génère le modèle Zabbix « SYNTRAF by HTTP » (contrib/zabbix/syntraf_by_http.json, format d'export Zabbix 6.0,
importable aussi dans 6.4 et 7.0 : Data collection › Templates › Import).

    python contrib/zabbix/build_template.py

Une seule requête HTTP par minute sur /metrics du serveur SYNTRAF (format Prometheus) ; tout le reste en éléments
dépendants : version, alertes ouvertes, et des découvertes (sondes, bases, fils du serveur, alertes) qui créent leurs
éléments et leurs déclencheurs. Une alerte SYNTRAF (hors baseline ou santé de l'outil) devient un problème Zabbix,
résolu quand elle se ferme. Accès : l'adresse du serveur ou du proxy Zabbix dans Server › Interface web (collecteurs
autorisés), ou un jeton d'API dans {$SYNTRAF.TOKEN}.
"""
import json
import uuid
from pathlib import Path

NAME = "SYNTRAF by HTTP"
MASTER = "syntraf.get_metrics"
NS = uuid.UUID("6f1c7a52-3c55-4a8e-9b0b-3f5e7d1c2a90")


def uid(*parts):
    """Identifiants stables (un modèle réimporté met à jour au lieu de dupliquer)."""
    return uuid.uuid5(NS, "/".join(parts)).hex


def pattern(expr, error_value=None):
    step = {"type": "PROMETHEUS_PATTERN", "parameters": [expr, "value", ""]}
    if error_value is not None:  # série disparue (alerte oubliée, sonde retirée) : valeur neutre plutôt qu'une erreur
        step.update(error_handler="CUSTOM_VALUE", error_handler_params=error_value)
    return [step]


def dependent(name, key, prep, value_type="FLOAT", units="", triggers=(), description=""):
    item = {"uuid": uid("item", key), "name": name, "type": "DEPENDENT", "key": key, "delay": "0",
            "history": "7d", "value_type": value_type, "units": units, "description": description,
            "preprocessing": prep, "master_item": {"key": MASTER},
            "tags": [{"tag": "component", "value": "syntraf"}]}
    if triggers:
        item["triggers" if "{#" not in key else "trigger_prototypes"] = [
            {"uuid": uid("trigger", key, t[1]), "expression": t[0], "name": t[1], "priority": t[2],
             "description": t[3] if len(t) > 3 else ""} for t in triggers]
    return item


def discovery(name, key, metric, macros, prototypes, lifetime="7d"):
    return {"uuid": uid("rule", key), "name": name, "type": "DEPENDENT", "key": key, "delay": "0",
            "lifetime": lifetime, "master_item": {"key": MASTER},
            "preprocessing": [{"type": "PROMETHEUS_TO_JSON", "parameters": [metric]}],
            "lld_macro_paths": [{"lld_macro": m, "path": f"$.labels['{label}']"} for m, label in macros],
            "item_prototypes": prototypes}


def ref(key):
    return f"/{NAME}/{key}"


def template():
    master = {"uuid": uid("item", MASTER), "name": "SYNTRAF: get /metrics", "type": "HTTP_AGENT", "key": MASTER,
              "delay": "1m", "history": "0", "trends": "0", "value_type": "TEXT", "timeout": "10s",
              "url": "{$SYNTRAF.URL}/metrics", "verify_peer": "NO", "verify_host": "NO",
              "headers": [{"name": "Authorization", "value": "Bearer {$SYNTRAF.TOKEN}"}],
              "description": "The health of SYNTRAF and its alerts, in the Prometheus format.",
              "tags": [{"tag": "component", "value": "syntraf"}],
              "triggers": [{"uuid": uid("trigger", MASTER, "nodata"), "expression": f"nodata({ref(MASTER)},5m)=1",
                            "name": "SYNTRAF: no answer from the server for 5 minutes", "priority": "HIGH",
                            "description": "Server down, network, or access refused (token, collectors allowed)."}]}
    items = [
        master,
        dependent("SYNTRAF: version", "syntraf.version",
                  [{"type": "PROMETHEUS_PATTERN", "parameters": ["syntraf_build_info", "label", "version"]}], "CHAR"),
        dependent("SYNTRAF: open alerts", "syntraf.alerts.open", pattern("syntraf_alerts_open"), "UNSIGNED"),
        dependent("SYNTRAF: server queue", "syntraf.queue", pattern("syntraf_queue_length"), "UNSIGNED",
                  triggers=[(f"min({ref('syntraf.queue')},10m)>{{$SYNTRAF.QUEUE.MAX}}",
                             "SYNTRAF: measurements pile up in the server queue", "WARNING")]),
    ]
    probes = discovery("Probes", "syntraf.probes.discovery", "syntraf_client_connected", [("{#CLIENT}", "client")], [
        dependent("SYNTRAF: probe {#CLIENT} connected", "syntraf.probe.connected[{#CLIENT}]",
                  pattern('syntraf_client_connected{client="{#CLIENT}"}', "0"),
                  triggers=[(f"max({ref('syntraf.probe.connected[{#CLIENT}]')},5m)=0",
                             "SYNTRAF: probe {#CLIENT} disconnected", "HIGH")]),
        dependent("SYNTRAF: measurements waiting on probe {#CLIENT}", "syntraf.probe.backlog[{#CLIENT}]",
                  pattern('syntraf_client_buffered_points{client="{#CLIENT}"}', "0"), "UNSIGNED",
                  triggers=[(f"min({ref('syntraf.probe.backlog[{#CLIENT}]')},10m)>{{$SYNTRAF.PROBE.BACKLOG.MAX}}",
                             "SYNTRAF: measurements pile up on probe {#CLIENT}", "WARNING",
                             "They do not reach the server: control channel or server problem.")]),
    ])
    databases = discovery("Databases", "syntraf.databases.discovery", "syntraf_database_up",
                          [("{#DB}", "database")], [
        dependent("SYNTRAF: database {#DB} up", "syntraf.db.up[{#DB}]", pattern('syntraf_database_up{database="{#DB}"}', "0"),
                  triggers=[(f"max({ref('syntraf.db.up[{#DB}]')},5m)=0", "SYNTRAF: database {#DB} unreachable", "HIGH")]),
        dependent("SYNTRAF: points waiting for database {#DB}", "syntraf.db.backlog[{#DB}]",
                  pattern('syntraf_database_backlog{database="{#DB}"}', "0"), "UNSIGNED",
                  triggers=[(f"min({ref('syntraf.db.backlog[{#DB}]')},10m)>{{$SYNTRAF.DB.BACKLOG.MAX}}",
                             "SYNTRAF: database {#DB} falls behind", "WARNING")]),
    ])
    threads = discovery("Server threads", "syntraf.threads.discovery", "syntraf_thread_up", [("{#THREAD}", "thread")], [
        dependent("SYNTRAF: server thread {#THREAD} up", "syntraf.thread.up[{#THREAD}]",
                  pattern('syntraf_thread_up{thread="{#THREAD}"}', "0"),
                  triggers=[(f"max({ref('syntraf.thread.up[{#THREAD}]')},3m)=0",
                             "SYNTRAF: server thread {#THREAD} stopped", "HIGH")]),
    ])
    alert_key = "syntraf.alert[{#GROUP},{#SOURCE},{#DEST},{#METRIC}]"
    alerts = discovery("Alerts", "syntraf.alerts.discovery", "syntraf_alert_open",
                       [("{#GROUP}", "group"), ("{#SOURCE}", "source"), ("{#DEST}", "destination"),
                        ("{#METRIC}", "metric"), ("{#KIND}", "kind")], [
        dependent("SYNTRAF: alert {#METRIC} {#SOURCE} → {#DEST} ({#GROUP})", alert_key,
                  pattern('syntraf_alert_open{group="{#GROUP}",source="{#SOURCE}",destination="{#DEST}",'
                          'metric="{#METRIC}"}', "0"), "UNSIGNED",
                  triggers=[(f"last({ref(alert_key)})=1", "SYNTRAF: {#METRIC} alert, {#SOURCE} → {#DEST} ({#GROUP})",
                             "AVERAGE", "Out of the flow's baseline (or a problem of SYNTRAF itself, group SYNTRAF). "
                                        "Details on the Alerts page of SYNTRAF.")]),
    ], lifetime="1d")
    tpl = {"uuid": uid("template", NAME), "template": NAME, "name": NAME,
           "description": "SYNTRAF network quality probes: health of the tool and its alerts, from /metrics. "
                          "Generated by contrib/zabbix/build_template.py.",
           "groups": [{"name": "Templates/Applications"}],
           "items": items, "discovery_rules": [probes, databases, threads, alerts],
           "macros": [{"macro": "{$SYNTRAF.URL}", "value": "https://syntraf.example.com:5000",
                       "description": "Address of the SYNTRAF web interface"},
                      {"macro": "{$SYNTRAF.TOKEN}", "type": "SECRET_TEXT", "value": "",
                       "description": "API token; empty if Zabbix is among the collectors allowed (Server › Web interface)"},
                      {"macro": "{$SYNTRAF.PROBE.BACKLOG.MAX}", "value": "1000"},
                      {"macro": "{$SYNTRAF.DB.BACKLOG.MAX}", "value": "10000"},
                      {"macro": "{$SYNTRAF.QUEUE.MAX}", "value": "10000"}],
           "tags": [{"tag": "class", "value": "application"}, {"tag": "target", "value": "syntraf"}]}
    return {"zabbix_export": {"version": "6.0", "groups": [{"uuid": uid("group", "Templates/Applications"),
                                                             "name": "Templates/Applications"}],
                              "templates": [tpl]}}


def main():
    out = Path(__file__).resolve().parent / "syntraf_by_http.json"
    out.write_text(json.dumps(template(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"écrit : {out}")


if __name__ == "__main__":
    main()

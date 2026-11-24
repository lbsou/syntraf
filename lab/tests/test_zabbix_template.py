"""Modèle Zabbix « SYNTRAF by HTTP » (contrib/zabbix) : importable, cohérent, et à jour."""
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_template", ROOT / "contrib" / "zabbix" / "build_template.py")
zb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(zb)


def walk(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk(v)


def test_the_template_is_a_zabbix_export_with_unique_uuids():
    t = zb.template()
    assert t["zabbix_export"]["version"] == "6.0"
    uuids = [o["uuid"] for o in walk(t) if "uuid" in o]
    assert len(uuids) == len(set(uuids)) and all(re.fullmatch(r"[0-9a-f]{32}", u) for u in uuids)


def test_every_dependent_item_reads_the_single_metrics_request_and_triggers_use_existing_keys():
    tpl = zb.template()["zabbix_export"]["templates"][0]
    master = [i for i in tpl["items"] if i["type"] == "HTTP_AGENT"]
    assert len(master) == 1 and master[0]["url"] == "{$SYNTRAF.URL}/metrics"
    keys = {i["key"] for i in tpl["items"]}
    for rule in tpl["discovery_rules"]:
        assert rule["master_item"]["key"] == master[0]["key"]
        keys |= {p["key"] for p in rule["item_prototypes"]}
    for o in walk(tpl):
        if o.get("type") == "DEPENDENT":
            assert o["master_item"]["key"] == master[0]["key"]
        if "expression" in o:
            for key in re.findall(r"/SYNTRAF by HTTP/((?:[^,()\[]|\[[^\]]*\])+)", o["expression"]):
                assert key in keys, key
    names = {r["key"] for r in tpl["discovery_rules"]}
    assert {"syntraf.probes.discovery", "syntraf.databases.discovery", "syntraf.threads.discovery",
            "syntraf.alerts.discovery"} <= names


def test_alert_discovery_follows_the_metrics_exposed_by_the_server():
    tpl = zb.template()["zabbix_export"]["templates"][0]
    rule = next(r for r in tpl["discovery_rules"] if r["key"] == "syntraf.alerts.discovery")
    assert rule["preprocessing"][0]["parameters"] == ["syntraf_alert_open"]
    assert {m["lld_macro"] for m in rule["lld_macro_paths"]} == {"{#GROUP}", "{#SOURCE}", "{#DEST}", "{#METRIC}", "{#KIND}"}


def test_the_committed_template_is_up_to_date():
    committed = json.loads((ROOT / "contrib" / "zabbix" / "syntraf_by_http.json").read_text(encoding="utf-8"))
    assert committed == zb.template()

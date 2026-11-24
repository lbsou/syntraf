#!/usr/bin/env python3
"""Banc d'essai des alertes hors baseline : des pannes injectées à des instants connus (anomalies étiquetées), puis
ce que SYNTRAF en a vu. Sert à juger un détecteur (lib/st_baseline.py) et à comparer un détecteur de remplacement
(un modèle appris ne s'ajoute que s'il fait mieux ici).

    python lab/bench_alerts.py                       # trois scénarios, environ 40 min
    python lab/bench_alerts.py --only loss --hold 360

Pour chaque scénario : panne sur un nœud sain pendant --hold secondes, puis retour et --rest secondes de calme.
Mesuré : détecté (une alerte de la bonne métrique sur un flux du nœud fautif), délai de détection, fausses alertes
(toute autre alerte ouverte pendant le banc), alertes refermées après le retour. Rapport dans lab/reports/.
Variables : SYNTRAF_URL (https://127.0.0.1:18080), SYNTRAF_TOKEN (sinon SYNTRAF_TOKEN_FILE).
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))
from lablib import faults, topology  # noqa: E402

# (nom, nœud fautif, réglages de la panne, métriques attendues, sens : flux dont le nœud est la source/destination)
SCENARIOS = [
    ("loss", "c2", {"loss_pct": 5.0}, {"loss", "mos"}, "from"),
    ("jitter", "c3", {"delay_ms": 10, "jitter_ms": 15}, {"jitter", "mos"}, "from"),
    ("rtt", "c3", {"delay_ms": 60}, {"rtt"}, "both"),
]


def api(url, token, path):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # certificat auto-signé du lab
    req = urllib.request.Request(url + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        return json.load(r)


def matches(alert, node_uid, metrics, direction):
    if alert.get("METRIC") not in metrics:
        return False
    src, dst = alert.get("CLIENT"), alert.get("SERVER")
    return (direction in ("from", "both") and src == node_uid) or (direction in ("to", "both") and dst == node_uid)


def run(url, token, hold, rest, only=None):
    results, seen = [], {}
    started = time.time()
    for name, node, fault, metrics, direction in SCENARIOS:
        if only and name not in only:
            continue
        uid = topology.CLIENT_UID[node]
        print(f"[{name}] panne sur {node} ({uid}) : {fault} pendant {hold} s")
        t0 = time.time()
        faults.degrade(node, **fault)
        detected_at = None
        try:
            while time.time() - t0 < hold:
                for a in api(url, token, "/api/v1/alerts")["open"]:
                    seen.setdefault((tuple(a["key"]), a["opened_at"]), a)
                    if detected_at is None and a["opened_at"] >= t0 and matches(a, uid, metrics, direction):
                        detected_at = a["opened_at"]
                        print(f"    détecté après {detected_at - t0:.0f} s : {a['CLIENT']} → {a['SERVER']} "
                              f"{a['METRIC']} | {a['explanation']}")
                time.sleep(20)
        finally:
            faults.heal(node)
        t1 = time.time()
        while time.time() - t1 < rest:
            for a in api(url, token, "/api/v1/alerts")["open"]:
                seen.setdefault((tuple(a["key"]), a["opened_at"]), a)
            time.sleep(20)
        still_open = [a for a in api(url, token, "/api/v1/alerts")["open"] if matches(a, uid, metrics, direction)]
        results.append({"scenario": name, "node": uid, "fault": fault, "detected": detected_at is not None,
                        "delay_s": None if detected_at is None else round(detected_at - t0),
                        "window": [t0, time.time()], "metrics": sorted(metrics), "direction": direction,
                        "closed_after_rest": not still_open})
        print(f"    {'DÉTECTÉ' if detected_at else 'RATÉ'} ; alertes refermées après le retour : {not still_open}")
    # Fausses alertes : ouvertes pendant le banc, sans rapport avec la panne en cours ou juste finie
    false_alarms = []
    for (key, opened), a in seen.items():
        if opened < started:
            continue
        explained = any(r["window"][0] <= opened <= r["window"][1] and
                        matches(a, r["node"], set(r["metrics"]), r["direction"]) for r in results)
        if not explained:
            false_alarms.append(a)
    return results, false_alarms


def report(results, false_alarms, detector):
    lines = [f"# Banc d'essai des alertes ({time.strftime('%Y-%m-%d %H:%M')}) — détecteur « {detector} »", "",
             "| Scénario | Nœud | Panne | Détecté | Délai | Refermée après le retour |", "|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['scenario']} | {r['node']} | {r['fault']} | {'oui' if r['detected'] else '**non**'} | "
                     f"{'' if r['delay_s'] is None else str(r['delay_s']) + ' s'} | "
                     f"{'oui' if r['closed_after_rest'] else 'non'} |")
    found = sum(r["detected"] for r in results)
    lines += ["", f"Détections : {found}/{len(results)} ; fausses alertes : {len(false_alarms)}"]
    for a in false_alarms:
        lines.append(f"- fausse alerte : {a['MESH_GROUP']} {a['CLIENT']} → {a['SERVER']} {a['METRIC']} | "
                     f"{a['explanation']}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--hold", type=int, default=420, help="durée de chaque panne (s)")
    ap.add_argument("--rest", type=int, default=600, help="calme après chaque panne (s) : une alerte se ferme après ~8 min")
    ap.add_argument("--only", nargs="*", choices=[s[0] for s in SCENARIOS])
    args = ap.parse_args()
    url = os.environ.get("SYNTRAF_URL", "https://127.0.0.1:18080")
    token = os.environ.get("SYNTRAF_TOKEN") or Path(os.environ["SYNTRAF_TOKEN_FILE"]).read_text().strip()
    detector = api(url, token, "/api/v1/alerts").get("detector", "?")
    results, false_alarms = run(url, token, args.hold, args.rest, args.only)
    text = report(results, false_alarms, detector)
    out = LAB / "reports" / f"bench_alerts-{time.strftime('%Y%m%dT%H%M')}.md"
    out.parent.mkdir(exist_ok=True)
    out.write_text(text, encoding="utf-8")
    print(text)
    print(f"rapport : {out}")
    return 0 if all(r["detected"] for r in results) and not false_alarms else 1


if __name__ == "__main__":
    sys.exit(main())

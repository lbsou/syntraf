#!/usr/bin/env python3
"""Écrit les tableaux de bord Grafana du lab (lab/grafana/dashboards/*.json), provisionnés au démarrage de Grafana.

    python lab/grafana/build_dashboards.py

La génération elle-même est dans lib/st_grafana_dashboards.py (le serveur s'en sert aussi pour déployer les tableaux
dans un Grafana, depuis l'interface).
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lib.st_grafana_dashboards import *  # noqa: E402,F401,F403
from lib import st_grafana_dashboards as _gd  # noqa: E402

OUT = Path(__file__).resolve().parent / "dashboards"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, dash in _gd.all_dashboards():
        (OUT / name).write_text(json.dumps(dash, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"écrit : {OUT / name}")


if __name__ == "__main__":
    main()

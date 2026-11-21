#!/usr/bin/env python3
"""Pilote du lab de robustesse SYNTRAF (bibliothèque standard uniquement).

Exemples :
    python lab/labctl.py up --build
    python lab/labctl.py status --json
    python lab/labctl.py down
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB_DIR))

from lablib import docker, health, topology  # noqa: E402


def _print_tail(service: str, lines: int = 30) -> None:
    r = docker.compose(["logs", "--no-color", "--tail", str(lines), service], check=False)
    print(f"----- {service} (dernières {lines} lignes) -----")
    print(r.stdout or r.stderr)


def _service_of_uid(uid: str) -> str:
    return {v: k for k, v in topology.CLIENT_UID.items()}[uid]


def cmd_up(args) -> int:
    for svc in topology.SYNTRAF_NODES:
        (LAB_DIR / "reports" / "logs" / svc).mkdir(parents=True, exist_ok=True)
    up = ["up", "-d"] + (["--build"] if args.build else [])
    r = docker.compose(up, check=False)
    if r.returncode != 0:
        print(r.stdout, r.stderr, sep="\n")
        return 1
    print("Conteneurs démarrés ; attente de l'état sain (12 flux qui écrivent)…")
    try:
        health.wait_healthy(health.influx_client(), timeout_s=args.timeout)
    except TimeoutError as exc:
        print(f"ÉCHEC : {exc}")
        _print_tail("server")
        stale = str(exc).split(" : ", 1)[-1].split(", ")
        if stale and "__TO__" in stale[0]:
            receiver = stale[0].split("__ON__")[0].split("__TO__")[1]
            _print_tail(_service_of_uid(receiver))
        return 1
    print("Lab sain.")
    return 0


def _heal_all_quietly() -> None:
    try:
        from lablib import faults
    except ImportError:
        return
    try:
        faults.heal_all()
    except Exception as exc:  # le lab peut être déjà arrêté
        print(f"(rétablissement ignoré : {exc})")


def cmd_down(args) -> int:
    _heal_all_quietly()
    r = docker.compose(["down"] + (["--volumes"] if args.volumes else []), check=False)
    print(r.stdout or r.stderr)
    return r.returncode


def collect_status() -> dict:
    ps = docker.compose(["ps", "--all", "--format", "json"], check=False).stdout
    containers = {}
    for line in ps.splitlines():
        line = line.strip()
        if not line:
            continue
        items = json.loads(line)
        for c in items if isinstance(items, list) else [items]:
            containers[c["Service"]] = c.get("State", "?")
    stats = docker.run(["stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}"], check=False).stdout
    mem = {}
    for line in stats.splitlines():
        name, _, usage = line.partition("\t")
        if name.startswith(topology.PROJECT + "-"):
            mem[name[len(topology.PROJECT) + 1:]] = usage
    nodes = {}
    for svc in topology.SYNTRAF_NODES:
        entry = {"state": containers.get(svc, "absent"), "mem": mem.get(svc, "-")}
        if containers.get(svc) == "running":
            try:
                entry.update(vars(health.snapshot(svc)))
            except subprocess.CalledProcessError:
                pass
            try:
                from lablib import faults
                entry["faults"] = faults.active(svc)
            except ImportError:
                pass
        nodes[svc] = entry
    flows = {}
    try:
        client = health.influx_client()
        now = datetime.now(timezone.utc)
        for f in topology.expected_flows():
            t = client.last_point_time(f, lookback_s=600)
            flows[f] = None if t is None else round((now - t).total_seconds(), 1)
    except Exception as exc:
        flows = {"erreur": str(exc)}
    return {"influxdb": containers.get("influxdb", "absent"), "influxdb_mem": mem.get("influxdb", "-"),
            "nodes": nodes, "flow_age_s": flows}


def cmd_status(args) -> int:
    st = collect_status()
    if args.json:
        print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0
    print(f"influxdb : {st['influxdb']}  RAM {st['influxdb_mem']}")
    for svc, n in st["nodes"].items():
        extra = ""
        if "iperf3_count" in n:
            extra = f"  iperf3={n['iperf3_count']} zombies={n['zombies']} threads={n['threads']}"
        faults_txt = f"  PANNES: {'; '.join(n['faults'])}" if n.get("faults") else ""
        print(f"{svc:8} : {n['state']:8} RAM {n['mem']}{extra}{faults_txt}")
    print("Âge du dernier point par flux (s) :")
    for f, age in st["flow_age_s"].items():
        print(f"  {f:40} {age if age is not None else 'aucun point'}")
    return 0


def cmd_logs(args) -> int:
    r = docker.compose(["logs", "--no-color", "--since", args.since, args.service], check=False)
    print(r.stdout or r.stderr)
    return r.returncode


def cmd_bootstrap(args) -> int:
    venv = LAB_DIR / ".venv"
    if not venv.exists():
        subprocess.run(["py", "-3.14", "-m", "venv", str(venv)], check=True)
    py = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    subprocess.run([str(py), "-m", "pip", "install", "-q", "-r", str(LAB_DIR / "requirements-dev.txt")], check=True)
    print(f"venv prêt : {venv}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="labctl", description="Pilote du lab de robustesse SYNTRAF")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("up", help="démarre le lab et attend l'état sain")
    s.add_argument("--build", action="store_true")
    s.add_argument("--timeout", type=float, default=180)
    s.set_defaults(func=cmd_up)
    s = sub.add_parser("down", help="arrête le lab (rétablit les pannes d'abord)")
    s.add_argument("--volumes", action="store_true", help="efface aussi les données InfluxDB")
    s.set_defaults(func=cmd_down)
    s = sub.add_parser("status", help="état des conteneurs, processus, pannes, flux")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)
    s = sub.add_parser("logs", help="logs d'un service")
    s.add_argument("service")
    s.add_argument("--since", default="10m")
    s.set_defaults(func=cmd_logs)
    s = sub.add_parser("bootstrap", help="crée lab/.venv avec pytest")
    s.set_defaults(func=cmd_bootstrap)
    return p


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except subprocess.CalledProcessError as exc:
        print(f"ÉCHEC : {' '.join(map(str, exc.cmd))}\n{exc.stderr}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

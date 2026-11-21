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
        health.wait_healthy(health.metrics_client(), timeout_s=args.timeout)
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
        client = health.metrics_client()
        now = datetime.now(timezone.utc)
        for f in topology.expected_flows():
            t = client.last_point_time(f, lookback_s=600)
            flows[f] = None if t is None else round((now - t).total_seconds(), 1)
    except Exception as exc:
        flows = {"erreur": str(exc)}
    infra = {svc: {"state": containers.get(svc, "absent"), "mem": mem.get(svc, "-")}
             for svc in ("victoriametrics", "grafana")}
    return {"infra": infra, "nodes": nodes, "flow_age_s": flows}


def cmd_status(args) -> int:
    st = collect_status()
    if args.json:
        print(json.dumps(st, indent=2, ensure_ascii=False))
        return 0
    for svc, n in st["infra"].items():
        print(f"{svc:15} : {n['state']:8} RAM {n['mem']}")
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


def cmd_degrade(args) -> int:
    from lablib import faults
    faults.degrade(args.service, delay_ms=args.delay, jitter_ms=args.jitter, loss_pct=args.loss,
                   rate=args.rate, to=args.to)
    print(f"{args.service} : {'; '.join(faults.active(args.service))}")
    return 0


def cmd_cut(args) -> int:
    import time
    from lablib import faults
    faults.cut(args.service, args.mode, to=args.to)
    print(f"{args.service} coupé (mode {args.mode}{', vers ' + args.to if args.to else ''})")
    if args.for_s:
        try:
            time.sleep(args.for_s)
        finally:
            faults.heal(args.service)
            print(f"{args.service} rétabli après {args.for_s:g} s")
    return 0


def cmd_heal(args) -> int:
    from lablib import faults
    if args.all or not args.service:
        faults.heal_all()
        print("toutes les pannes retirées")
    else:
        faults.heal(args.service)
        print(f"{args.service} rétabli")
    return 0


def cmd_flap(args) -> int:
    from lablib import faults
    faults.flap(args.service, args.mode, args.off, args.on, args.count)
    print(f"{args.service} : {args.count} coupures ({args.mode}) terminées, service rétabli")
    return 0


def cmd_kill_iperf(args) -> int:
    from lablib import faults
    faults.kill_iperf(args.service, args.signal)
    print(f"iperf3 tués sur {args.service} (SIG{args.signal})")
    return 0


def cmd_restart(args) -> int:
    from lablib import faults
    faults.restart(args.service)
    print(f"{args.service} redémarré")
    return 0


VERSION_KEYS = {"iperf3": "IPERF3_REF", "python": "PYTHON_VERSION",
                "victoriametrics": "VM_VERSION", "grafana": "GRAFANA_VERSION"}


def set_env_value(path: Path, key: str, value: str) -> None:
    """Remplace la valeur d'une clé existante de lab.env en conservant toutes les autres lignes."""
    lines = Path(path).read_text(encoding="utf-8").splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key and not line.lstrip().startswith("#"):
            lines[i] = f"{key}={value}\n"
            Path(path).write_text("".join(lines), encoding="utf-8")
            return
    raise KeyError(f"{key} absent de {path}")


def cmd_set_version(args) -> int:
    set_env_value(docker.ENV_FILE, VERSION_KEYS[args.component], args.value)
    if args.component == "iperf3" and args.source:
        set_env_value(docker.ENV_FILE, "IPERF3_SOURCE", args.source)
    print(f"{VERSION_KEYS[args.component]}={args.value} écrit dans {docker.ENV_FILE}")
    if args.no_restart:
        return 0
    args.build, args.timeout = True, 300
    return cmd_up(args)


def cmd_versions(args) -> int:
    def first_line(r):
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else "?"
    print("iperf3          :", first_line(docker.exec_("c1", ["iperf3", "--version"], check=False)))
    print("python          :", first_line(docker.exec_("c1", ["python", "--version"], check=False)))
    env = health.read_env()
    print("victoriametrics :", env.get("VM_VERSION"))
    print("grafana         :", env.get("GRAFANA_VERSION"))
    return 0


def cmd_install_shortcut(args) -> int:
    import os
    targets = {"SYNTRAF Lab.lnk": LAB_DIR / "start-lab.ps1",
               "SYNTRAF Lab - arrêt.lnk": LAB_DIR / "stop-lab.ps1"}
    for name, script in targets.items():
        # Le Bureau peut être redirigé (OneDrive) : Windows en donne le vrai chemin.
        ps = ("$lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) $env:LNK_NAME; "
              "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk); "
              "$s.TargetPath = 'pwsh.exe'; "
              "$s.Arguments = '-NoExit -ExecutionPolicy Bypass -File \"' + $env:SCRIPT + '\"'; "
              "$s.WorkingDirectory = $env:WORKDIR; $s.Save(); $lnk")
        env = dict(os.environ, LNK_NAME=name, SCRIPT=str(script), WORKDIR=str(LAB_DIR.parent))
        r = subprocess.run(["pwsh", "-NoProfile", "-Command", ps], check=True, env=env,
                           capture_output=True, text=True, encoding="utf-8")
        print(f"raccourci créé : {r.stdout.strip()}")
    return 0


def wait_child_then_heal(proc, heal) -> int:
    """Attend pytest ; au 1er Ctrl+C, le laisse finir son nettoyage (il reçoit aussi le signal) ;
    au 2e, le tue. Dans tous les cas, retire ensuite toute panne du lab."""
    interrupted = False
    try:
        while True:
            try:
                return proc.wait()
            except KeyboardInterrupt:
                if interrupted:
                    print("Second Ctrl+C : arrêt immédiat de pytest.")
                    proc.kill()
                    proc.wait()
                    return 130
                interrupted = True
                print("Ctrl+C : pytest termine son nettoyage (Ctrl+C de nouveau pour forcer l'arrêt)…")
    finally:
        heal()


def cmd_test(args) -> int:
    py = LAB_DIR / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not py.exists():
        print("lab/.venv absent : lancer d'abord `python lab/labctl.py bootstrap`")
        return 1
    report = LAB_DIR / "reports" / datetime.now().strftime("%Y-%m-%d_%H%M%S")
    cmd = [str(py), "-m", "pytest", str(LAB_DIR / "scenarios"), "-p", "no:cacheprovider",
           f"--report-dir={report}", f"--junitxml={report / 'junit.xml'}", "-q", "-rA"]
    if args.k:
        cmd += ["-k", args.k]
    if args.quick:
        cmd += ["-m", "not slow"]
    print(f"Rapport : {report}")
    code = wait_child_then_heal(subprocess.Popen(cmd, cwd=LAB_DIR), _heal_all_quietly)
    summary = report / "summary.md"
    if summary.exists():
        print(summary.read_text(encoding="utf-8").split("## Détails", 1)[0])
    return code


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

    nodes = list(topology.SYNTRAF_NODES)
    s = sub.add_parser("degrade", help="latence/gigue/pertes/débit (tc netem) en sortie d'un nœud")
    s.add_argument("service", choices=nodes)
    s.add_argument("--delay", type=int, default=0, help="ms")
    s.add_argument("--jitter", type=int, default=0, help="ms")
    s.add_argument("--loss", type=float, default=0.0, help="%%")
    s.add_argument("--rate", help="ex. 1mbit")
    s.add_argument("--to", choices=nodes, help="seulement vers ce nœud")
    s.set_defaults(func=cmd_degrade)
    s = sub.add_parser("cut", help="coupure : drop (silencieuse), disconnect (interface), pause (hôte figé)")
    s.add_argument("service", choices=nodes)
    s.add_argument("--mode", choices=["drop", "disconnect", "pause"], default="drop")
    s.add_argument("--to", choices=nodes, help="seulement vers ce nœud (mode drop)")
    s.add_argument("--for", dest="for_s", type=float, help="rétablir après N secondes")
    s.set_defaults(func=cmd_cut)
    s = sub.add_parser("heal", help="retire les pannes d'un nœud (ou de tous)")
    s.add_argument("service", nargs="?", choices=nodes)
    s.add_argument("--all", action="store_true")
    s.set_defaults(func=cmd_heal)
    s = sub.add_parser("flap", help="coupures répétées")
    s.add_argument("service", choices=nodes)
    s.add_argument("--mode", choices=["drop", "disconnect", "pause"], default="drop")
    s.add_argument("--off", type=float, default=5)
    s.add_argument("--on", type=float, default=10)
    s.add_argument("--count", type=int, default=10)
    s.set_defaults(func=cmd_flap)
    s = sub.add_parser("kill-iperf", help="tue les processus iperf3 d'un nœud")
    s.add_argument("service", choices=nodes)
    s.add_argument("--signal", default="KILL")
    s.set_defaults(func=cmd_kill_iperf)
    s = sub.add_parser("restart", help="redémarre un service")
    s.add_argument("service", choices=nodes + ["victoriametrics", "grafana"])
    s.set_defaults(func=cmd_restart)
    s = sub.add_parser("set-version", help="change une version dans lab.env puis reconstruit/redémarre")
    s.add_argument("component", choices=list(VERSION_KEYS))
    s.add_argument("value")
    s.add_argument("--source", choices=["esnet", "fork"], help="iperf3 seulement")
    s.add_argument("--no-restart", action="store_true")
    s.set_defaults(func=cmd_set_version)
    s = sub.add_parser("versions", help="versions en service")
    s.set_defaults(func=cmd_versions)
    s = sub.add_parser("install-shortcut", help="crée les raccourcis du Bureau (démarrage et arrêt)")
    s.set_defaults(func=cmd_install_shortcut)
    s = sub.add_parser("test", help="lance les scénarios ; rapport dans lab/reports/<date>/")
    s.add_argument("-k", help="filtre pytest (ex. s3)")
    s.add_argument("--quick", action="store_true", help="exclut les scénarios longs (S1, S8)")
    s.set_defaults(func=cmd_test)
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

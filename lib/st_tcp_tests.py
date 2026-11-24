"""Tests TCP courts et récurrents entre sondes (iperf3 -J), planifiés par le serveur.

Une tâche ([[TCP_TEST]]) : un mesh group (ses paires de sondes), une fréquence (EVERY : 15m, 1h, 2d ; sans unité,
des minutes ; au moins une minute), une durée (1 à 60 s), un sens (upload : l'initiateur envoie ; download : il
reçoit, -R ; both : les deux, l'un après l'autre) et les paramètres TCP (PARALLEL, WINDOW, MSS, CONGESTION, BANDWIDTH,
DSCP, OMIT). MODE = auto applique le principe d'AMPR-NG : fenêtre = produit débit × délai × facteur (AUTO_FACTOR, 2
par défaut, de 1 à 8 ; débit = capacité × 0.95), débit cible -b = capacité, rythme --pacing-timer en option
(AUTO_PACING). Le RTT vient de la mesure de latence continue de SYNTRAF (TWAMP) ; la capacité de la tâche (BANDWIDTH)
ou, à défaut, du plus petit « débit maximal » déclaré des deux sondes. Sans l'un ou l'autre : l'OS règle TCP seul.

Le serveur fait passer un test à la fois sur tout le maillage (les tests ne se perturbent pas entre eux) : il envoie
au répondeur « iperf3 -s à telle heure, pour la durée du test », puis à l'initiateur « iperf3 -c à telle heure ». L'initiateur
est la sonde derrière un NAT s'il y en a une (comme pour la latence) ; deux sondes derrière un NAT ne sont pas
testées. L'initiateur renvoie le résultat comme une mesure : SYNTRAF_TCP{MESH_GROUP, CLIENT (pair), SERVER
(initiateur), TEST, DIRECTION} avec BITRATE_MBPS (reçu), SENT_MBPS, RETRANSMITS, RTT_MS, RTT_MAX_MS, CWND_MAX_KB, MSS,
STREAMS, CPU_LOCAL, CPU_REMOTE, FAILED, et les paramètres appliqués (WINDOW_BYTES, TARGET_MBPS).

Bibliothèque standard uniquement (exécuté aussi par la sonde légère).
"""
import collections
import datetime as dt
import json
import logging
import os
import re
import subprocess
import threading
import time
import uuid

log = logging.getLogger("syntraf." + __name__)

DEFAULT_PORT = 5201
DIRECTIONS = ("upload", "download", "both")
MODES = ("fixed", "auto")
UID_RE = re.compile(r"^[A-Za-z0-9_-]{4,50}$")
SIZE_RE = re.compile(r"^\d+(\.\d+)?[KMG]?$", re.I)
CC_RE = re.compile(r"^[a-z0-9_]{1,16}$")
OVERHEAD_FACTOR = 0.95
MARGIN_S = 15


# ------------------------------------------------------------------------------------------ paramètres

def parse_every(text):
    m = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(text or ""), re.I)
    if not m:
        return None
    seconds = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 60}[m.group(2).lower()]
    return seconds if seconds >= 60 else None


def size_bps(text):
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMG]?)\s*", str(text or ""), re.I)
    if not m:
        return None
    return float(m.group(1)) * {"": 1, "K": 1e3, "M": 1e6, "G": 1e9}[m.group(2).upper()]


def _int_in(value, low, high):
    return str(value).strip().isdigit() and low <= int(value) <= high


def field_errors(v, mesh_groups=(), with_uid=True):
    e = {}
    get = lambda k: str(v.get(k, "") or "").strip()  # noqa: E731
    if with_uid and not UID_RE.match(get("UID")):
        e["UID"] = "4 to 50 letters, digits, '_' or '-'"
    if get("MESH_GROUP") not in set(mesh_groups):
        e["MESH_GROUP"] = "An existing mesh group"
    if parse_every(get("EVERY")) is None:
        e["EVERY"] = "A frequency of at least one minute, e.g. 15m, 1h, 1d"
    if not _int_in(get("DURATION") or "10", 1, 60):
        e["DURATION"] = "1 to 60 seconds"
    if (get("DIRECTION") or "both") not in DIRECTIONS:
        e["DIRECTION"] = "upload, download or both"
    if get("PARALLEL") and not _int_in(get("PARALLEL"), 1, 32):
        e["PARALLEL"] = "1 to 32 parallel streams"
    if get("WINDOW") and not SIZE_RE.match(get("WINDOW")):
        e["WINDOW"] = "A size such as 256K or 4M"
    if get("BANDWIDTH") and not SIZE_RE.match(get("BANDWIDTH")):
        e["BANDWIDTH"] = "A rate such as 100M or 1G"
    if get("MSS") and not _int_in(get("MSS"), 88, 9000):
        e["MSS"] = "88 to 9000 bytes"
    if get("CONGESTION") and not CC_RE.match(get("CONGESTION")):
        e["CONGESTION"] = "A TCP congestion control name, e.g. cubic, bbr"
    if get("DSCP") and not _int_in(get("DSCP"), 0, 63):
        e["DSCP"] = "0 to 63"
    if get("OMIT") and not _int_in(get("OMIT"), 0, 10):
        e["OMIT"] = "0 to 10 seconds"
    if (get("MODE") or "fixed") not in MODES:
        e["MODE"] = "fixed or auto"
    if get("AUTO_FACTOR"):
        try:
            if not 1 <= float(get("AUTO_FACTOR")) <= 8:
                raise ValueError
        except ValueError:
            e["AUTO_FACTOR"] = "1 to 8"
    return e


def pairs(flows, mesh_group, probes):
    """[(initiateur, répondeur, adresse du répondeur)] : une paire par couple de sondes du mesh group ; la sonde
    derrière un NAT initie (elle seule peut ouvrir la connexion) ; deux NAT : impossible, écarté."""
    seen, out = set(), []
    for f in flows:
        if f.get("MESH_GROUP") != mesh_group:
            continue
        a, b = sorted((f["CLIENT"], f["SERVER"]))
        if (a, b) in seen:
            continue
        seen.add((a, b))
        pa, pb = probes.get(a, {}), probes.get(b, {})
        if pa.get("nat") and pb.get("nat"):
            continue
        initiator, responder = (b, a) if pb.get("nat") else (a, b)
        address = probes.get(responder, {}).get("address")
        if address and address != "0.0.0.0":
            out.append((initiator, responder, address))
    return out


def capacity_bps(test, max_a, max_b):
    if size_bps(test.get("BANDWIDTH")):
        return size_bps(test.get("BANDWIDTH"))
    known = [b for b in (size_bps(max_a), size_bps(max_b)) if b]
    return min(known) if known else None


def auto_params(capacity_bps, rtt_ms, factor=2.0, pacing=False, mss=1460):
    """Mode auto (AMPR-NG) : fenêtre = débit × RTT / 8 × facteur ; débit cible = capacité × 0.95."""
    if not capacity_bps or not rtt_ms:
        return {}
    bps = capacity_bps * OVERHEAD_FACTOR
    out = {"WINDOW": str(int(bps * rtt_ms / 1000 / 8 * float(factor))), "BANDWIDTH": f"{int(bps / 1e6)}M"}
    if pacing:
        out["PACING_US"] = int(mss * 8 / bps * 1e6)
    return out


def client_args(binary, test, address, port, direction, auth):
    a = [binary, "-c", address, "-p", str(port), "-t", str(test.get("DURATION") or 10),
         "-O", str(test.get("OMIT") or 1), "-P", str(test.get("PARALLEL") or 1)]
    for key, flag in (("WINDOW", "-w"), ("MSS", "-M"), ("CONGESTION", "-C"), ("BANDWIDTH", "-b"),
                      ("PACING_US", "--pacing-timer")):
        if str(test.get(key) or "").strip():
            a += [flag, str(test[key]).strip()]
    a += ["--dscp", str(test.get("DSCP") or 0), "-J", "--connect-timeout", "5000"]
    if direction == "download":
        a += ["-R", "--get-server-output"]  # le pair envoie : son RTT et sa fenêtre viennent de sa sortie
    return a + list(auth)


def server_args(binary, port, idle_s, auth):
    # sans --one-off : l'initiateur peut relancer sans -w si la fenêtre est refusée ; arrêté en fin de plage (_run)
    return [binary, "-s", "-p", str(port), "--idle-timeout", str(int(idle_s)), "-J"] + list(auth)


def os_buffer_max():
    """Plus grand tampon de socket qu'une application peut demander (Linux : min de net.core.wmem_max, rmem_max),
    ou None si inconnu."""
    try:
        values = []
        for name in ("wmem_max", "rmem_max"):
            with open(f"/proc/sys/net/core/{name}", encoding="ascii") as f:
                values.append(int(f.read().strip()))
        return min(values)
    except (OSError, ValueError):
        return None


def window_within(test, os_max):
    """(test, limité) : une fenêtre au-delà du plafond du système n'est pas imposée (l'autoréglage de TCP va plus
    loin que ce plafond) ; limité = True pour le signaler dans le résultat."""
    window = size_bps(test.get("WINDOW"))
    if not window or not os_max or window <= os_max:
        return test, False
    return {k: v for k, v in test.items() if k != "WINDOW"}, True


def responder_not_ready(error):
    """Le répondeur n'écoute pas encore (action reçue en retard) : un second essai, 2 s plus tard, a sa chance."""
    return "connection refused" in str(error or "").lower()


def refused_window(error):
    return "socket buffer size" in str(error or "").lower()


# ---------------------------------------------------------------------------------------------- résultat

def result_error(text):
    try:
        return str(json.loads(text).get("error") or "")
    except (ValueError, AttributeError):
        return str(text or "").strip()[:200]


def parse_result(text):
    try:
        d = json.loads(text)
    except (ValueError, TypeError):
        return {"FAILED": 1}
    end = d.get("end") or {}
    if d.get("error") or not end.get("sum_received"):
        return {"FAILED": 1}
    streams = end.get("streams") or []
    senders = [s.get("sender") or {} for s in streams]
    if not any(s.get("mean_rtt") for s in senders):  # -R : l'émetteur est le pair (sortie du serveur)
        remote = ((d.get("server_output_json") or {}).get("end") or {}).get("streams") or []
        senders = [s.get("sender") or {} for s in remote] or senders
    rtts = [s["mean_rtt"] for s in senders if s.get("mean_rtt")]
    f = {"BITRATE_MBPS": round(end["sum_received"].get("bits_per_second", 0) / 1e6, 2),
         "SENT_MBPS": round((end.get("sum_sent") or {}).get("bits_per_second", 0) / 1e6, 2),
         "RETRANSMITS": int((end.get("sum_sent") or {}).get("retransmits") or 0),
         "STREAMS": len(streams), "FAILED": 0}
    if rtts:
        f["RTT_MS"] = round(sum(rtts) / len(rtts) / 1000, 3)
        f["RTT_MAX_MS"] = round(max(s.get("max_rtt", 0) for s in senders) / 1000, 3)
    cwnd = [s["max_snd_cwnd"] for s in senders if s.get("max_snd_cwnd")]
    if cwnd:
        f["CWND_MAX_KB"] = round(max(cwnd) / 1024, 1)
    mss = (d.get("start") or {}).get("tcp_mss_default") or (d.get("start") or {}).get("tcp_mss")
    if mss:
        f["MSS"] = int(mss)
    cpu = end.get("cpu_utilization_percent") or {}
    if cpu:
        f["CPU_LOCAL"], f["CPU_REMOTE"] = round(cpu.get("host_total", 0), 1), round(cpu.get("remote_total", 0), 1)
    return f


def point(test, me, peer, direction, fields, utime):
    return {"measurement": "SYNTRAF_TCP",
            "tags": {"MESH_GROUP": test.get("MESH_GROUP"), "CLIENT": peer, "SERVER": me, "TEST": test.get("UID"),
                     "DIRECTION": direction},
            "time": dt.datetime.fromtimestamp(utime, dt.timezone.utc), "fields": dict(fields)}


# --------------------------------------------------------------------------------- ordonnancement (serveur)

class Scheduler:
    """Échéances des tâches, file de tests, un seul test à la fois. Première échéance d'une tâche : une période
    après son apparition (pas d'avalanche au démarrage du serveur) ; run_now(uid) la lance au passage suivant."""

    def __init__(self, start_delay_s=10):
        self.start_delay_s = start_delay_s
        self.next_due, self.queue, self.busy_until, self.now_requests = {}, collections.deque(), 0.0, set()
        self.lock = threading.Lock()
        self.last_jobs = collections.deque(maxlen=50)

    def run_now(self, uid):
        with self.lock:
            self.now_requests.add(uid)

    def queued(self):
        with self.lock:
            return [{"test": j["test"].get("UID"), "initiator": j["initiator"], "responder": j["responder"],
                     "direction": j["direction"]} for j in self.queue]

    def tick(self, now, tests, pairs_fn):
        with self.lock:
            for t in tests:
                uid = t.get("UID")
                if not t.get("ENABLED", True) or str(t.get("ENABLED")).lower() == "false":
                    self.now_requests.discard(uid)
                    continue
                every = parse_every(t.get("EVERY")) or 3600
                self.next_due.setdefault(uid, now + every)
                if uid in self.now_requests or now >= self.next_due[uid]:
                    self.now_requests.discard(uid)
                    if now >= self.next_due[uid]:
                        self.next_due[uid] = now + every
                    directions = ["upload", "download"] if (t.get("DIRECTION") or "both") == "both" \
                        else [t.get("DIRECTION")]
                    for initiator, responder, address in pairs_fn(t):
                        for d in directions:
                            self.queue.append({"test": dict(t), "initiator": initiator, "responder": responder,
                                               "address": address, "direction": d})
            known = {t.get("UID") for t in tests}
            for uid in [u for u in self.next_due if u not in known]:
                del self.next_due[uid]
            if now < self.busy_until or not self.queue:
                return []
            job = self.queue.popleft()
            t = job["test"]
            slot = self.start_delay_s + int(t.get("OMIT") or 1) + int(t.get("DURATION") or 10) + MARGIN_S
            job.update(start_at=now + self.start_delay_s, slot_s=slot, run_id=uuid.uuid4().hex[:12],
                       run_s=slot - self.start_delay_s)  # du départ à la fin de la plage : le répondeur s'arrête avant
            self.busy_until = now + slot
            self.last_jobs.append(job)
            return [job]


SCHEDULER = Scheduler()

def dispatch(job, commands, port=DEFAULT_PORT):
    """Le test devient deux actions : le répondeur ouvre iperf3 -s un peu avant que l'initiateur lance iperf3 -c."""
    test = dict(job["test"], **(job.get("auto") or {}))
    commands.setdefault(job["responder"], []).append(
        {"ACTION": "TCP_TEST", "ROLE": "server", "PORT": port, "START_AT": job["start_at"] - 3,
         "IDLE_S": job.get("run_s", job["slot_s"]), "RUN_ID": job["run_id"]})
    commands.setdefault(job["initiator"], []).append(
        {"ACTION": "TCP_TEST", "ROLE": "client", "ADDRESS": job["address"], "PORT": port, "START_AT": job["start_at"],
         "DIRECTION": job["direction"], "TEST": test, "PEER": job["responder"], "RUN_ID": job["run_id"]})


# ------------------------------------------------------------------------------- résultats (côté serveur)

RESULTS = collections.deque(maxlen=500)
_RESULTS_LOCK = threading.Lock()


def record(points):
    for p in points or []:
        if isinstance(p, dict) and p.get("measurement") == "SYNTRAF_TCP":
            t = p.get("time")
            with _RESULTS_LOCK:
                RESULTS.append({"time": t.isoformat() if hasattr(t, "isoformat") else str(t),
                                **{k.lower(): v for k, v in (p.get("tags") or {}).items()},
                                **{k: v for k, v in (p.get("fields") or {}).items()}})


RESULT_FIELDS = ("BITRATE_MBPS", "SENT_MBPS", "RETRANSMITS", "RTT_MS", "RTT_MAX_MS", "CWND_MAX_KB", "MSS", "STREAMS",
                 "WINDOW_BYTES", "WINDOW_LIMITED", "TARGET_MBPS", "FAILED")


def results_from_vm(vm, window="7d"):
    """Dernier résultat de chaque (test, paire, sens) lu dans VictoriaMetrics (après un redémarrage du serveur)."""
    key = lambda m: tuple(m.get(k, "") for k in ("MESH_GROUP", "TEST", "DIRECTION", "SERVER", "CLIENT"))  # noqa: E731
    rows, at = {}, {}
    for serie in vm.query(f"tlast_over_time(SYNTRAF_TCP_FAILED[{window}])"):
        m = serie["metric"]
        at[key(m)] = float(serie["value"][1])
        when = dt.datetime.fromtimestamp(at[key(m)], dt.timezone.utc)
        rows[key(m)] = {"time": when.isoformat(), **{k.lower(): m.get(k) for k in
                                                     ("MESH_GROUP", "TEST", "DIRECTION", "SERVER", "CLIENT")}}
    for field in RESULT_FIELDS:
        same_run = {key(x["metric"]) for x in vm.query(f"tlast_over_time(SYNTRAF_TCP_{field}[{window}])")
                    if abs(float(x["value"][1]) - at.get(key(x["metric"]), -1e9)) < 1}
        for serie in vm.query(f"last_over_time(SYNTRAF_TCP_{field}[{window}])"):
            row = rows.get(key(serie["metric"]))
            if row is not None and (field == "FAILED" or key(serie["metric"]) in same_run):
                value = float(serie["value"][1])
                row[field] = int(value) if field in ("FAILED", "RETRANSMITS", "STREAMS", "WINDOW_LIMITED") else value
    return sorted(rows.values(), key=lambda r: r["time"], reverse=True)


_SEEDED = {"done": False}


def seed(rows):
    """Historique relu de la base, une fois, quand la mémoire est vide (serveur redémarré)."""
    with _RESULTS_LOCK:
        if not _SEEDED["done"] and not RESULTS:
            RESULTS.extend(sorted(rows, key=lambda r: r["time"]))
        _SEEDED["done"] = True


def seeded():
    return _SEEDED["done"]


def recent_results(limit=100):
    with _RESULTS_LOCK:
        return list(RESULTS)[-limit:][::-1]


# ---------------------------------------------------------------------------------- exécution (côté sonde)

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,253}$")


def command_problem(c):
    """None si l'action TCP_TEST reçue est sûre à exécuter, sinon la raison du refus (aucune valeur ne peut
    devenir une option d'iperf3)."""
    if not isinstance(c, dict) or c.get("ROLE") not in ("server", "client"):
        return "unknown role"
    if not _int_in(c.get("PORT", ""), 1, 65535):
        return "bad port"
    try:
        float(c.get("START_AT"))
    except (TypeError, ValueError):
        return "bad start time"
    if c["ROLE"] == "server":
        return None if _int_in(c.get("IDLE_S", ""), 1, 3600) else "bad idle timeout"
    if not HOST_RE.match(str(c.get("ADDRESS", ""))):
        return "bad address"
    if c.get("DIRECTION") not in ("upload", "download"):
        return "bad direction"
    test = c.get("TEST")
    if not isinstance(test, dict):
        return "no test"
    errors = field_errors(test, mesh_groups={test.get("MESH_GROUP")}, with_uid=False)
    if errors:
        return "bad test parameters: " + ", ".join(sorted(errors))
    if str(test.get("PACING_US", "") or "") and not _int_in(test.get("PACING_US"), 1, 1000000):
        return "bad pacing"
    return None


def _auth(config, role):
    g, c = config.get("GLOBAL", {}), config.get("CLIENT", {})
    if not g.get("IPERF3_AUTH"):
        return [], None
    keys = g.get("IPERF3_RSA_KEY_DIRECTORY", "")
    if role == "server":
        return ["--rsa-private-key-path", os.path.join(keys, "private_key_iperf_client.pem"),
                "--authorized-users-path", os.path.join(keys, "credentials.csv"),
                "--time-skew-threshold", str(g.get("IPERF3_TIME_SKEW_THRESHOLD", "10"))], None
    env = dict(os.environ, IPERF3_PASSWORD=str(c.get("IPERF3_PASSWORD", "")))
    return ["--username", str(c.get("IPERF3_USERNAME", "")),
            "--rsa-public-key-path", os.path.join(keys, "public_key_iperf_client.pem")], env


def run_command(config, command, queue, enqueue):
    """Exécute une action TCP_TEST reçue du serveur, dans un fil à part (la boucle de contrôle continue)."""
    threading.Thread(target=_run, args=(config, command, queue, enqueue),
                     name=f"TCP_TEST:{command.get('ROLE')}:{command.get('RUN_ID')}", daemon=True).start()


def _run(config, command, queue, enqueue):
    binary = config.get("GLOBAL", {}).get("IPERF3_BINARY_PATH", "iperf3")
    try:
        time.sleep(max(float(command.get("START_AT", 0)) - time.time(), 0))
        role = command.get("ROLE")
        auth, env = _auth(config, role)
        if role == "server":
            args = server_args(binary, command["PORT"], command.get("IDLE_S", 60), auth)
            p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                p.wait(timeout=float(command.get("IDLE_S", 60)))  # arrêté avant la plage suivante
            except subprocess.TimeoutExpired:
                p.kill()
            return
        test, limited = window_within(command.get("TEST") or {}, os_buffer_max())

        def attempt(t):
            args = client_args(binary, t, command["ADDRESS"], command["PORT"], command.get("DIRECTION", "upload"), auth)
            return subprocess.run(args, capture_output=True, text=True, env=env,
                                  timeout=int(t.get("DURATION") or 10) + int(t.get("OMIT") or 1) + 30)
        start = time.time()
        r = attempt(test)
        if responder_not_ready(result_error(r.stdout or r.stderr)):
            time.sleep(2)
            start = time.time()
            r = attempt(test)
        if refused_window(result_error(r.stdout or r.stderr)) and test.get("WINDOW"):
            test, limited = {k: v for k, v in test.items() if k != "WINDOW"}, True  # refusée par le pair
            start = time.time()
            r = attempt(test)
        fields = parse_result(r.stdout)
        if fields.get("FAILED"):
            log.warning(f"TCP TEST {test.get('UID')} TO {command.get('PEER')} FAILED: {result_error(r.stdout or r.stderr)}")
        if limited:
            fields["WINDOW_LIMITED"] = 1
            log.warning(f"TCP TEST {test.get('UID')} TO {command.get('PEER')}: WINDOW ABOVE THE OPERATING SYSTEM LIMIT "
                        f"(net.core.wmem_max / rmem_max), LEFT TO TCP AUTOTUNING")
        if test.get("WINDOW"):
            fields["WINDOW_BYTES"] = size_bps(test["WINDOW"]) or 0
        if test.get("BANDWIDTH"):
            fields["TARGET_MBPS"] = round((size_bps(test["BANDWIDTH"]) or 0) / 1e6, 2)
        me = config.get("CLIENT", {}).get("CLIENT_UID", "")
        enqueue(queue, point(test, me, command.get("PEER"), command.get("DIRECTION", "upload"), fields, int(start)))
    except Exception as exc:  # noqa: BLE001 - un test raté ne doit jamais gêner la sonde
        log.warning(f"TCP TEST {command.get('RUN_ID')}: {type(exc).__name__}:{exc}")

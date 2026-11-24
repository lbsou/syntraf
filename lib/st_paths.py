"""Chemin réseau entre deux sondes (traceroute façon MTR), à la demande ou à l'ouverture d'une alerte.

Sonde : plusieurs tours de sondes UDP à TTL croissant ; par saut, le routeur qui répond, la perte et le temps
d'aller-retour (moyen, meilleur, pire). Sous Linux, sans privilège : les réponses ICMP arrivent par la file d'erreurs
de la socket (IP_RECVERR, comme tracepath). Sous Windows, tracert ; ailleurs, traceroute. IPv4.

Serveur : une demande devient l'action PATH_TRACE envoyée à la sonde source, avec l'adresse de la destination (même
injoignable : c'est justement le chemin de ce moment qu'on veut garder). Le résultat revient comme une mesure
SYNTRAF_PATH ; le serveur le range (PathStore, sur disque) et n'écrit dans la base qu'un résumé numérique.
À l'ouverture d'une alerte d'un flux, les deux sens sont tracés, au plus une fois par AUTO_COOLDOWN_S pour la paire.
"""
import collections
import datetime as dt
import json
import logging
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time

log = logging.getLogger("syntraf." + __name__)

ROUNDS, MAX_HOPS = 5, 30
WAIT_S = 1.0               # attente des réponses d'un tour
ROUND_INTERVAL_S = 1.2     # un tour par 1,2 s : les routeurs limitent leurs ICMP à ~1/s (sinon fausse perte)
BASE_PORT = 33434          # ports UDP de destination, comme traceroute
AUTO_COOLDOWN_S = 600      # alertes : une trace par paire de sondes toutes les 10 minutes au plus
RUNNING_TIMEOUT_S = 180    # sans résultat de la sonde après ce délai : échec
KEEP = 500

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
IP_RECVERR, MSG_ERRQUEUE = 11, 0x2000
_EXT_ERR = struct.Struct("=IBBBBII")  # struct sock_extended_err
ORIGIN_ICMP = 2


# ------------------------------------------------------------------------------------------------ sonde

def parse_errqueue(ancdata):
    """("hop" | "dest" | "unreach", adresse) d'après l'ICMP rapporté dans la file d'erreurs, sinon None."""
    for level, kind, data in ancdata:
        if level != socket.IPPROTO_IP or kind != IP_RECVERR or len(data) < _EXT_ERR.size + 8:
            continue
        _errno, origin, icmp_type, code, _pad, _info, _data = _EXT_ERR.unpack_from(data)
        if origin != ORIGIN_ICMP:
            continue
        offender = socket.inet_ntoa(data[_EXT_ERR.size + 4:_EXT_ERR.size + 8])
        if icmp_type == 11:
            return "hop", offender
        if icmp_type == 3:
            return ("dest" if code == 3 else "unreach"), offender
    return None


def aggregate(samples):
    """samples [(ttl, adresse | None, rtt_ms | None, genre)] → ([saut], destination atteinte). Les sauts au-delà
    de la destination sont ignorés ; sans destination, la fin muette est réduite à un seul saut."""
    by = collections.defaultdict(list)
    for ttl, addr, rtt, kind in samples:
        by[ttl].append((addr, rtt, kind))
    end_ttls = [t for t, rows in by.items() if any(k in ("dest", "unreach") for _, _, k in rows)]
    reached = any(k == "dest" for t in end_ttls for _, _, k in by[t])
    last = min(end_ttls) if end_ttls else max((t for t, rows in by.items() if any(a for a, _, _ in rows)), default=0)
    if not end_ttls and last < max(by, default=0):
        last += 1  # le premier saut muet : là où le chemin se perd
    hops = []
    for ttl in sorted(t for t in by if t <= last):
        rows = by[ttl]
        addrs = collections.Counter(a for a, _, _ in rows if a)
        rtts = [r for _, r, _ in rows if r is not None]
        main = addrs.most_common(1)[0][0] if addrs else None
        received = sum(1 for a, _, _ in rows if a)
        hops.append({"hop": ttl, "address": main, "sent": len(rows), "received": received,
                     "loss_pct": round(100.0 * (len(rows) - received) / len(rows), 1),
                     "rtt_avg": round(sum(rtts) / len(rtts), 2) if rtts else None,
                     "rtt_min": round(min(rtts), 2) if rtts else None,
                     "rtt_max": round(max(rtts), 2) if rtts else None,
                     "others": sorted(a for a in addrs if a != main)})
    return hops, reached


_TRACERT_LINE = re.compile(r"^\s*(\d+)\s+((?:(?:<?\d+\s*ms|\*)\s+){3})(.*)$")


def parse_tracert(text, target):
    """Sortie de tracert (Windows), quelle que soit sa langue : 3 essais par saut, puis l'adresse."""
    samples = []
    for line in text.splitlines():
        m = _TRACERT_LINE.match(line)
        if not m:
            continue
        ttl, tail = int(m.group(1)), m.group(3).strip()
        addr = tail.split()[-1].strip("[]") if tail else ""
        addr = addr if IPV4_RE.match(addr) else None
        for tok in re.findall(r"<?\d+\s*ms|\*", m.group(2)):
            if tok == "*":
                samples.append((ttl, None, None, None))
            else:
                ms = float(re.sub(r"[^\d]", "", tok)) or 0.5  # « <1 ms »
                samples.append((ttl, addr, ms if not tok.startswith("<") else 0.5, "dest" if addr == target else "hop"))
    return samples


def parse_traceroute(text, target):
    """Sortie de traceroute -n (BSD, macOS, Linux) : un saut par ligne, plusieurs répondants possibles."""
    samples = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if not m:
            continue
        ttl, addr = int(m.group(1)), None
        tokens = m.group(2).split()
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "*":
                samples.append((ttl, None, None, None))
            elif IPV4_RE.match(tok):
                addr = tok
            elif re.match(r"^\d+(\.\d+)?$", tok) and i + 1 < len(tokens) and tokens[i + 1] == "ms":
                samples.append((ttl, addr, float(tok), "dest" if addr == target else "hop"))
                i += 1
            i += 1
    return samples


def trace_native(address, rounds=ROUNDS, max_hops=MAX_HOPS, wait=WAIT_S):
    """Linux, sans privilège : UDP à TTL croissant, ICMP lus dans la file d'erreurs (msg_name = destination
    d'origine, donc le port identifie la sonde)."""
    import select
    ip = socket.gethostbyname(address)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    samples, limit = [], max_hops
    try:
        s.setsockopt(socket.IPPROTO_IP, IP_RECVERR, 1)
        s.setblocking(False)
        poller = select.poll()
        poller.register(s, select.POLLERR)
        for r in range(rounds):
            round_start, sent = time.monotonic(), {}
            for ttl in range(1, limit + 1):
                port = BASE_PORT + r * max_hops + ttl
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                sent[port] = (ttl, time.monotonic())
                try:
                    s.sendto(b"SYNTRAF-PATH", (ip, port))
                except OSError:
                    pass  # erreur immédiate (ICMP déjà en file) : lue plus bas
            got, deadline = {}, time.monotonic() + wait
            while len(got) < len(sent):
                left = deadline - time.monotonic()
                if left <= 0 or not poller.poll(left * 1000):
                    break
                while True:
                    try:
                        _data, anc, _flags, addr = s.recvmsg(64, 1024, MSG_ERRQUEUE)
                    except (BlockingIOError, InterruptedError):
                        break
                    parsed = parse_errqueue(anc)
                    if parsed and addr and addr[1] in sent and addr[1] not in got:
                        got[addr[1]] = (parsed, time.monotonic())
            for port, (ttl, t0) in sent.items():
                if port in got:
                    (kind, offender), t1 = got[port]
                    samples.append((ttl, offender, round((t1 - t0) * 1000, 2), kind))
                else:
                    samples.append((ttl, None, None, None))
            if r == 0:  # les tours suivants s'arrêtent à la destination
                ends = [t for t, a, _, k in samples if k in ("dest", "unreach")]
                limit = min(ends) if ends else limit
            if r < rounds - 1:
                time.sleep(max(0.0, ROUND_INTERVAL_S - (time.monotonic() - round_start)))
    finally:
        s.close()
    return samples


def trace(address, rounds=ROUNDS, max_hops=MAX_HOPS):
    """{"tool", "reached", "hops", "error"}."""
    ip = socket.gethostbyname(address)
    try:
        if sys.platform.startswith("linux"):
            tool, samples = "native", trace_native(ip, rounds, max_hops)
        elif sys.platform == "win32":
            r = subprocess.run(["tracert", "-d", "-w", "1000", "-h", str(max_hops), ip], capture_output=True,
                               encoding="oem", errors="replace", timeout=max_hops * 4 + 30)
            tool, samples = "tracert", parse_tracert(r.stdout, ip)
        else:
            r = subprocess.run(["traceroute", "-n", "-q", str(rounds), "-w", "1", "-m", str(max_hops), ip],
                               capture_output=True, text=True, errors="replace", timeout=max_hops * rounds * 2 + 30)
            tool, samples = "traceroute", parse_traceroute(r.stdout, ip)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"tool": None, "reached": False, "hops": [], "error": f"{type(exc).__name__}: {exc}"}
    hops, reached = aggregate(samples)
    return {"tool": tool, "reached": reached, "hops": hops, "error": None if hops else "no answer from any hop"}


def command_problem(c):
    """None si l'action PATH_TRACE reçue est sûre à exécuter, sinon la raison du refus."""
    if not isinstance(c, dict) or not ID_RE.match(str(c.get("ID", ""))):
        return "bad id"
    if not HOST_RE.match(str(c.get("ADDRESS", ""))):
        return "bad address"
    try:
        if not 1 <= int(c.get("MAX_HOPS", MAX_HOPS)) <= 64:
            return "bad max hops"
        if not 1 <= int(c.get("ROUNDS", ROUNDS)) <= 10:
            return "bad rounds"
    except (TypeError, ValueError):
        return "bad numbers"
    return None


def point(me, command, result, utime):
    return {"measurement": "SYNTRAF_PATH",
            "tags": {"SERVER": me, "CLIENT": command.get("PEER", ""), "TRACE_ID": command.get("ID", "")},
            "time": dt.datetime.fromtimestamp(utime, dt.timezone.utc),
            "fields": {"RESULT": json.dumps(result, separators=(",", ":"))}}


def run_command(me, command, queue, enqueue):
    """Exécute une action PATH_TRACE reçue du serveur, dans un fil à part (la boucle de contrôle continue)."""
    def work():
        start = time.time()
        try:
            result = trace(command["ADDRESS"], int(command.get("ROUNDS", ROUNDS)), int(command.get("MAX_HOPS", MAX_HOPS)))
        except Exception as exc:  # noqa: BLE001 - une trace ratée ne doit jamais gêner la sonde
            result = {"tool": None, "reached": False, "hops": [], "error": f"{type(exc).__name__}: {exc}"}
        log.info(f"PATH TO {command.get('PEER')} ({command.get('ADDRESS')}): {len(result['hops'])} HOPS, "
                 f"{'REACHED' if result['reached'] else 'NOT REACHED'}")
        enqueue(queue, point(me, command, result, int(start)))
    threading.Thread(target=work, name=f"PATH_TRACE:{command.get('ID')}", daemon=True).start()


# ----------------------------------------------------------------------------------------------- serveur

class PathStore:
    """Traces demandées et leurs résultats, les KEEP plus récentes, gardées sur disque (JSON)."""

    def __init__(self, path, keep=KEEP):
        self.path, self.keep, self.lock = str(path), keep, threading.RLock()
        self.records, self.last_auto = [], {}
        try:
            with open(self.path, encoding="utf-8") as f:
                self.records = [r for r in json.load(f) if isinstance(r, dict) and r.get("id")][-keep:]
        except (OSError, ValueError):
            pass

    def _save(self):
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.records, f)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning(f"PATHS NOT SAVED: {exc}")

    def request(self, source, destination, reason, now=None, alert=None):
        now = now if now is not None else time.time()
        rec = {"id": f"{int(now)}-{secrets.token_hex(3)}", "requested_at": now, "source": source,
               "destination": destination, "reason": reason, "alert": alert, "status": "pending", "address": None,
               "sent_at": None, "finished_at": None, "tool": None, "reached": None, "hops": [], "error": None}
        with self.lock:
            self.records = (self.records + [rec])[-self.keep:]
            self._save()
        return dict(rec)

    def update(self, rid, **values):
        with self.lock:
            for r in self.records:
                if r["id"] == rid:
                    r.update(values)
                    self._save()
                    return dict(r)
        return None

    def get(self, rid):
        with self.lock:
            return next((dict(r) for r in self.records if r["id"] == rid), None)

    def list(self, source=None, destination=None, both=False, limit=None):
        with self.lock:
            rows = sorted(reversed(self.records), key=lambda r: r["requested_at"], reverse=True)
        def match(r):
            direct = (source is None or r["source"] == source) and (destination is None or r["destination"] == destination)
            back = both and (source is None or r["destination"] == source) and (destination is None or r["source"] == destination)
            return direct or back
        rows = [dict(r) for r in rows if match(r)]
        return rows[:limit] if limit else rows


_STORE = []


def store():
    """Le carnet du serveur : <données>/paths.json."""
    if not _STORE:
        from lib.st_global import DefaultValues
        _STORE.append(PathStore(os.path.join(str(DefaultValues.SYNTRAF_DATA_DIR), "paths.json")))
    return _STORE[0]


AUTO = {"enabled": True}  # GLOBAL.PATH_TRACE_ON_ALERT, recopié à chaque passage de la surveillance


def on_alert_open(info, now, path_store=None):
    """Alerte ouverte sur le flux CLIENT → SERVER : on garde le chemin des deux sens, tel qu'il est maintenant."""
    path_store = path_store or store()
    a, b = info.get("CLIENT"), info.get("SERVER")
    if not AUTO["enabled"] or not a or not b or a == b:
        return []
    pair = tuple(sorted((a, b)))
    with path_store.lock:
        if now - path_store.last_auto.get(pair, -1e18) < AUTO_COOLDOWN_S:
            return []
        path_store.last_auto[pair] = now
    alert = {k: info.get(k) for k in ("MESH_GROUP", "METRIC", "CLIENT", "SERVER")}
    return [path_store.request(a, b, "alert", now, alert), path_store.request(b, a, "alert", now, alert)]


def tick(dict_of_clients, declared, commands, path_store=None, now=None):
    """Passage de la surveillance : demandes en attente → action PATH_TRACE à la sonde source ; traces sans
    réponse depuis RUNNING_TIMEOUT_S → échec."""
    path_store = path_store or store()
    now = now if now is not None else time.time()
    for rec in path_store.list():
        if rec["status"] == "running" and now - (rec["sent_at"] or now) > RUNNING_TIMEOUT_S:
            path_store.update(rec["id"], status="failed", error="no result from the probe", finished_at=now)
        if rec["status"] != "pending":
            continue
        src = dict_of_clients.get(rec["source"])
        if src is None or getattr(src, "status", "") != "CONNECTED":
            path_store.update(rec["id"], status="failed", error="source probe not connected", finished_at=now)
            continue
        dst = dict_of_clients.get(rec["destination"])
        address = (getattr(dst, "ip_address", None) if dst is not None else None) or \
            (declared.get(rec["destination"]) or {}).get("IP_ADDRESS")
        if not address or address == "0.0.0.0" or not HOST_RE.match(str(address)):
            path_store.update(rec["id"], status="failed", error="destination address unknown", finished_at=now)
            continue
        commands.setdefault(rec["source"], []).append(
            {"ACTION": "PATH_TRACE", "ID": rec["id"], "ADDRESS": address, "PEER": rec["destination"],
             "ROUNDS": ROUNDS, "MAX_HOPS": MAX_HOPS})
        path_store.update(rec["id"], status="running", sent_at=now, address=address)


def _clean_hops(hops):
    out = []
    for h in (hops if isinstance(hops, list) else [])[:64]:
        if not isinstance(h, dict):
            continue
        num = lambda v: round(float(v), 2) if isinstance(v, (int, float)) else None  # noqa: E731
        addr = h.get("address") if isinstance(h.get("address"), str) and IPV4_RE.match(h["address"]) else None
        out.append({"hop": int(h.get("hop") or 0), "address": addr, "sent": int(h.get("sent") or 0),
                    "received": int(h.get("received") or 0), "loss_pct": num(h.get("loss_pct")),
                    "rtt_avg": num(h.get("rtt_avg")), "rtt_min": num(h.get("rtt_min")), "rtt_max": num(h.get("rtt_max")),
                    "others": [a for a in (h.get("others") or []) if isinstance(a, str) and IPV4_RE.match(a)][:8]})
    return out


def receive(payload, path_store=None, reporter=None):
    """Mesures reçues d'une sonde : les traces sont rangées (seulement celles demandées à cette sonde) et remplacées
    par un résumé numérique pour la base ; le reste passe tel quel."""
    path_store = path_store or store()
    kept = []
    for p in payload or []:
        if not (isinstance(p, dict) and p.get("measurement") == "SYNTRAF_PATH" and "RESULT" in (p.get("fields") or {})):
            kept.append(p)
            continue
        rec = path_store.get((p.get("tags") or {}).get("TRACE_ID", ""))
        if rec is None or rec["source"] != reporter or rec["status"] not in ("pending", "running"):
            log.warning(f"PATH RESULT FROM {reporter} IGNORED: NOT REQUESTED")
            continue
        try:
            result = json.loads(p["fields"]["RESULT"])
        except (TypeError, ValueError):
            result = {}
        hops = _clean_hops(result.get("hops"))
        reached = bool(result.get("reached"))
        error = str(result.get("error"))[:200] if result.get("error") else None
        path_store.update(rec["id"], status="done" if hops else "failed", finished_at=time.time(), hops=hops,
                          reached=reached, tool=str(result.get("tool") or "")[:20] or None, error=error)
        rtts = [h["rtt_avg"] for h in hops if h["rtt_avg"] is not None]
        fields = {"HOP_COUNT": len(hops), "REACHED": 1 if reached else 0}
        if rtts:
            fields["RTT_MS"] = rtts[-1]
        kept.append({"measurement": "SYNTRAF_PATH", "time": p.get("time"),
                     "tags": {"SOURCE": rec["source"], "DESTINATION": rec["destination"], "REASON": rec["reason"]},
                     "fields": fields})
    return kept

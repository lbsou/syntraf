"""Accessibilité entrante d'une sonde : ce que ses pairs peuvent réellement joindre (NAT ou pare-feu).

Une sonde qui ne reçoit aucune connexion (NAT, pare-feu) se déclare BEHIND_NAT (« sortant seulement ») : elle n'ouvre
aucun port et mesure elle-même les deux sens. Le serveur ne voit un NAT qu'à l'adresse (lib/st_nat.py) ; un pare-feu
ne change pas l'adresse. Ce test le voit : la sonde testée ouvre un court instant les ports de ses services, et
quelques pairs (ou, à défaut, le serveur) essaient de les joindre depuis leur place dans le réseau.

Services testés :
- iperf3 : un port libre de la plage des listeners de la sonde, en TCP (contrôle) et en UDP (mesures) ;
- latency : le réflecteur TWAMP-Light (UDP GLOBAL.LATENCY_PORT), qui admet le testeur le temps du test ;
- tcp_test : le port des tests TCP planifiés (TCP GLOBAL.TCP_TEST_PORT), s'il y a des tests TCP.

Déroulement : action REACH_LISTEN à la sonde testée (ports ouverts dès réception, jusqu'à START_AT + DURATION_S),
action REACH_CHECK à chaque testeur (essais répétés de START_AT à START_AT + CHECK_WINDOW_S : un écart d'horloge entre
les sondes ne fait pas échouer le test). Chacun renvoie son résultat comme mesure SYNTRAF_REACH, rangée par le serveur
(ReachStore, sur disque) et jamais écrite dans la base. Par service : joignable si un testeur au moins l'a joint,
bloqué si tous ont échoué ; « refused » (RST, ICMP port unreachable : rejet) et « timeout » (paquets ignorés) sont
distingués. Verdict : open, partial (une partie des services bloqués), blocked, unknown.

Sécurité : la sonde testée ne renvoie en UDP que les datagrammes portant le jeton du test (128 bits, connu des seuls
testeurs), à l'identique (aucune amplification), et ferme ses ports après DURATION_S (MAX_DURATION_S au plus).
Automatique (GLOBAL.REACHABILITY_CHECK) : chaque sonde connectée non déclarée BEHIND_NAT est testée une minute après
sa connexion, puis toutes les AUTO_EVERY_S et à chaque changement d'adresse. Bibliothèque standard uniquement.
"""
import datetime as dt
import json
import logging
import os
import random
import re
import secrets
import select
import socket
import sys
import threading
import time

log = logging.getLogger("syntraf." + __name__)

MAGIC = b"SYNTRAF-REACH\0"
NONCE_BYTES = 16
START_DELAY_S = 10          # le temps que les deux actions arrivent (une action par échange du canal de contrôle)
DURATION_S = 30             # ports ouverts jusqu'à START_AT + DURATION_S
MAX_DURATION_S = 90         # au plus, depuis la réception de l'action
CHECK_WINDOW_S = 10         # le testeur réessaie pendant ce temps (horloges un peu décalées, action arrivée tard)
CONNECT_TIMEOUT_S = 3
RESULT_TIMEOUT_S = 90       # après START_AT : les résultats manquants deviennent « no result »
MAX_TESTERS = 3
SERVER_TESTER = "@server"   # le serveur teste lui-même quand aucun pair n'est connecté
AUTO_EVERY_S = 6 * 3600
AUTO_SETTLE_S = 60          # une sonde qui vient de se connecter installe d'abord ses flux
MAX_RUNNING = 2
KEEP = 300

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")

# service : (protocole, rôle du port)
SERVICES = {"iperf3_tcp": ("tcp", "iperf3"), "iperf3_udp": ("udp", "iperf3"), "latency": ("latency", "latency"),
            "tcp_test": ("tcp", "tcp_test")}


def _ports(value, limit=4):
    if not isinstance(value, list) or len(value) > limit:
        return None
    try:
        ports = [int(p) for p in value]
    except (TypeError, ValueError):
        return None
    return ports if all(1 <= p <= 65535 for p in ports) else None


def _common_problem(c):
    if not isinstance(c, dict) or not ID_RE.match(str(c.get("ID", ""))):
        return "bad id"
    if not NONCE_RE.match(str(c.get("NONCE", ""))):
        return "bad nonce"
    try:
        float(c.get("START_AT"))
    except (TypeError, ValueError):
        return "bad start time"
    if _ports(c.get("TCP_PORTS", [])) is None or _ports(c.get("UDP_PORTS", [])) is None:
        return "bad ports"
    return None


def listen_problem(c):
    """None si l'action REACH_LISTEN reçue est sûre à exécuter, sinon la raison du refus."""
    problem = _common_problem(c)
    if problem:
        return problem
    try:
        if not 1 <= int(c.get("DURATION_S", DURATION_S)) <= MAX_DURATION_S:
            return "bad duration"
    except (TypeError, ValueError):
        return "bad duration"
    return None


def check_problem(c):
    """None si l'action REACH_CHECK reçue est sûre à exécuter, sinon la raison du refus."""
    problem = _common_problem(c)
    if problem:
        return problem
    if not HOST_RE.match(str(c.get("ADDRESS", ""))):
        return "bad address"
    if c.get("LATENCY_PORT") and _ports([c.get("LATENCY_PORT")], 1) is None:
        return "bad latency port"
    return None


def echo_packet(nonce_hex, seq=0):
    return MAGIC + bytes.fromhex(nonce_hex) + bytes([seq & 0xFF])


def is_echo_request(data, nonce):
    return len(data) == len(MAGIC) + NONCE_BYTES + 1 and data.startswith(MAGIC) \
        and data[len(MAGIC):len(MAGIC) + NONCE_BYTES] == nonce


# ------------------------------------------------------------------------------------------- sonde testée

def listen(command, now=None, stop=None):
    """Ouvre les ports demandés jusqu'à START_AT + DURATION_S : TCP (connexions acceptées puis fermées), UDP (écho
    des datagrammes au jeton du test) ; le réflecteur TWAMP admet les paquets au jeton (lib/st_twamp.py).
    Renvoie l'état de chaque port (listening, in_use, error: …) et le nombre de contacts reçus."""
    now = now if now is not None else time.time()
    nonce = bytes.fromhex(command["NONCE"])
    end = min(float(command["START_AT"]) + int(command.get("DURATION_S", DURATION_S)), now + MAX_DURATION_S)
    result = {"tcp": {}, "udp": {}, "latency": None, "contacts": {}}
    socks = {}
    for proto, kind in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
        for port in _ports(command.get(f"{proto.upper()}_PORTS", [])) or []:
            s = socket.socket(socket.AF_INET, kind)
            try:
                if sys.platform != "win32":  # sous Windows, SO_REUSEADDR laisserait voler un port occupé
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                if proto == "tcp":
                    s.listen(16)
                s.setblocking(False)
                socks[s] = (proto, port)
                result[proto][str(port)] = "listening"
            except OSError as exc:
                s.close()
                in_use = getattr(exc, "errno", None) in (98, 48, 10048) or "in use" in str(exc).lower()
                # TCP : le service déjà à l'écoute sur ce port (iperf3, test TCP) répond à sa place
                result[proto][str(port)] = "in_use" if in_use else f"error: {exc}"[:120]
    if command.get("LATENCY_PORT"):
        try:
            from lib import st_twamp
            running = st_twamp.MANAGER.reflector is not None and st_twamp.MANAGER.reflector.port == int(command["LATENCY_PORT"])
            if running:
                st_twamp.admit_test(nonce, end)
            result["latency"] = "listening" if running else "off"
        except Exception as exc:  # noqa: BLE001
            result["latency"] = f"error: {exc}"[:120]
    try:
        while socks and time.time() < end and not (stop and stop.is_set()):
            ready, _, _ = select.select(list(socks), [], [], min(0.5, max(end - time.time(), 0.01)))
            for s in ready:
                proto, port = socks[s]
                key = f"{proto}:{port}"
                try:
                    if proto == "tcp":
                        conn, _ = s.accept()
                        conn.close()
                    else:
                        data, addr = s.recvfrom(256)
                        if not is_echo_request(data, nonce):
                            continue
                        s.sendto(data, addr)
                    result["contacts"][key] = result["contacts"].get(key, 0) + 1
                except OSError:
                    pass
        if not socks:  # rien à écouter soi-même (réflecteur seul) : rester joignable jusqu'à la fin
            while time.time() < end and not (stop and stop.is_set()):
                time.sleep(min(0.5, max(end - time.time(), 0.01)))
    finally:
        for s in socks:
            s.close()
    return result


# ------------------------------------------------------------------------------------------------ testeur

def _classify(exc):
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):  # Windows : ICMP port unreachable en UDP
        return "refused"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if getattr(exc, "errno", None) in (101, 113, 10051, 10065, 51, 65):  # réseau ou hôte injoignable (ICMP)
        return "unreachable"
    return f"error: {exc}"[:120]


def try_tcp(address, port, timeout=CONNECT_TIMEOUT_S):
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return "open"
    except OSError as exc:
        return _classify(exc)


def try_udp(address, port, nonce_hex, timeout=CONNECT_TIMEOUT_S, packet=None, valid=None):
    """Trois datagrammes, attente d'un écho. Socket connectée : un ICMP port unreachable devient « refused »."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((address, port))
        s.settimeout(timeout / 3)
        status = "timeout"
        for seq in range(3):
            pkt = packet(seq) if packet else echo_packet(nonce_hex, seq)
            try:
                s.send(pkt)
                data = s.recv(512)
                if (valid or (lambda d: d == pkt))(data):
                    return "open"
            except OSError as exc:
                status = _classify(exc)
                if status not in ("timeout", "refused"):
                    return status
        return status
    except OSError as exc:
        return _classify(exc)
    finally:
        s.close()


def try_latency(address, port, nonce_hex, timeout=CONNECT_TIMEOUT_S):
    from lib import st_twamp

    def packet(seq):
        return st_twamp.sender_packet(seq, time.time(), nonce=bytes.fromhex(nonce_hex))

    def valid(data):
        try:
            return st_twamp.parse_reply(data) is not None
        except Exception:  # noqa: BLE001
            return False
    return try_udp(address, port, nonce_hex, timeout, packet, valid)


def check(command, deadline=None):
    """Essaie chaque port jusqu'à l'ouvrir ou jusqu'à deadline : le dernier état vu de chacun."""
    address, nonce = command["ADDRESS"], command["NONCE"]
    deadline = deadline if deadline is not None else time.time() + CHECK_WINDOW_S
    result = {"tcp": {}, "udp": {}, "latency": None}
    todo = [("tcp", p) for p in _ports(command.get("TCP_PORTS", [])) or []] + \
        [("udp", p) for p in _ports(command.get("UDP_PORTS", [])) or []]
    if command.get("LATENCY_PORT"):
        todo.append(("latency", int(command["LATENCY_PORT"])))
    while todo:
        for proto, port in list(todo):
            if proto == "tcp":
                status = try_tcp(address, port)
            elif proto == "udp":
                status = try_udp(address, port, nonce)
            else:
                status = try_latency(address, port, nonce)
            if proto == "latency":
                result["latency"] = status
            else:
                result[proto][str(port)] = status
            if status == "open":
                todo.remove((proto, port))
        if time.time() >= deadline:
            break
        time.sleep(1)
    return result


# ---------------------------------------------------------------------------------- actions reçues (sonde)

def point(me, command, role, result, utime):
    return {"measurement": "SYNTRAF_REACH",
            "tags": {"SERVER": me, "ID": command.get("ID", ""), "ROLE": role},
            "time": dt.datetime.fromtimestamp(utime, dt.timezone.utc),
            "fields": {"RESULT": json.dumps(result, separators=(",", ":"))}}


def run_command(me, role, command, queue, enqueue):
    """Exécute REACH_LISTEN (role listen) ou REACH_CHECK (role check) dans un fil à part."""
    def work():
        start = time.time()
        try:
            if role == "listen":
                result = listen(command)
            else:
                time.sleep(max(float(command["START_AT"]) - time.time(), 0))
                result = check(command)
        except Exception as exc:  # noqa: BLE001 - un test raté ne doit jamais gêner la sonde
            result = {"error": f"{type(exc).__name__}: {exc}"[:200]}
        log.info(f"REACHABILITY TEST {command.get('ID')} ({role.upper()}): {json.dumps(result)[:300]}")
        enqueue(queue, point(me, command, role, result, int(start)))
    threading.Thread(target=work, name=f"REACH_{role.upper()}:{command.get('ID')}", daemon=True).start()


# ----------------------------------------------------------------------------------------------- serveur

def service_states(rec):
    """État de chaque service testé : open, blocked (avec la raison la plus fréquente), not_tested, unknown."""
    listener = rec.get("listener") or {}
    out = {}
    for service, (proto, role) in SERVICES.items():
        port = (rec.get("ports") or {}).get(role)
        if not port:
            continue
        if listener.get("error"):
            out[service] = {"port": port, "state": "unknown", "detail": "probe could not open its ports"}
            continue
        if listener:
            own = listener.get("latency") if proto == "latency" else (listener.get(proto) or {}).get(str(port))
            usable = own == "listening" or (own == "in_use" and proto == "tcp")
            if own is not None and not usable:
                out[service] = {"port": port, "state": "not_tested", "detail": str(own)}
                continue
        seen = []
        for t in (rec.get("testers") or {}).values():
            res = t.get("result") or {}
            status = res.get("latency") if proto == "latency" else (res.get(proto) or {}).get(str(port))
            if status:
                seen.append(status)
        if "open" in seen:
            out[service] = {"port": port, "state": "open", "detail": None}
        elif seen:
            out[service] = {"port": port, "state": "blocked", "detail": max(set(seen), key=seen.count)}
        else:
            out[service] = {"port": port, "state": "unknown", "detail": "no result from the testers"}
    return out


def verdict(services):
    known = [s["state"] for s in services.values() if s["state"] in ("open", "blocked")]
    if not known:
        return "unknown"
    if all(s == "blocked" for s in known):
        return "blocked"
    return "partial" if "blocked" in known else "open"


class ReachStore:
    """Tests demandés et leurs résultats, les KEEP plus récents, gardés sur disque (JSON)."""

    def __init__(self, path, keep=KEEP):
        self.path, self.keep, self.lock = str(path), keep, threading.RLock()
        self.records, self.connected_since = [], {}
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
            log.warning(f"REACHABILITY TESTS NOT SAVED: {exc}")

    def request(self, target, reason, now=None):
        now = now if now is not None else time.time()
        rec = {"id": f"{int(now)}-{secrets.token_hex(3)}", "target": target, "reason": reason, "requested_at": now,
               "status": "pending", "address": None, "ports": {}, "start_at": None, "finished_at": None,
               "listener": None, "testers": {}, "services": {}, "verdict": None, "error": None}
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
                    return json.loads(json.dumps(r))
        return None

    def get(self, rid):
        with self.lock:
            r = next((r for r in self.records if r["id"] == rid), None)
            return json.loads(json.dumps(r)) if r else None

    def list(self, target=None, limit=None):
        with self.lock:
            rows = [json.loads(json.dumps(r)) for r in reversed(self.records) if target is None or r["target"] == target]
        rows.sort(key=lambda r: r["requested_at"], reverse=True)
        return rows[:limit] if limit else rows

    def latest(self, target, finished=False):
        for r in self.list(target):
            if not finished or r["status"] == "done":
                return r
        return None

    def file(self, rid, reporter, role, result, now=None):
        """Résultat d'un côté du test ; le test se termine quand la sonde testée et tous les testeurs ont répondu."""
        now = now if now is not None else time.time()
        with self.lock:
            rec = next((r for r in self.records if r["id"] == rid), None)
            if rec is None or rec["status"] != "running":
                return False
            if role == "listen" and reporter == rec["target"]:
                rec["listener"] = result if isinstance(result, dict) else {"error": "bad result"}
            elif role == "check" and reporter in rec["testers"]:
                rec["testers"][reporter].update(status="done", result=result if isinstance(result, dict) else {})
            else:
                return False
            if rec["listener"] is not None and all(t["status"] == "done" for t in rec["testers"].values()):
                self._finish(rec, now)
            self._save()
            return True

    def _finish(self, rec, now, error=None):
        for t in rec["testers"].values():
            if t["status"] != "done":
                t["status"] = "no result"
        rec["services"] = service_states(rec)
        rec["verdict"] = verdict(rec["services"])
        rec.update(status="done", finished_at=now, error=error)
        log.info(f"REACHABILITY OF {rec['target']}: {rec['verdict'].upper()} "
                 + ", ".join(f"{k}={v['state']}" for k, v in rec["services"].items()))

    def expire(self, now):
        with self.lock:
            changed = False
            for rec in self.records:
                if rec["status"] == "running" and now > (rec["start_at"] or now) + RESULT_TIMEOUT_S:
                    self._finish(rec, now, None if rec["listener"] is not None else "no answer from the probe")
                    changed = True
            if changed:
                self._save()


_STORE = []


def store():
    """Le carnet du serveur : <données>/reachability.json."""
    if not _STORE:
        from lib.st_global import DefaultValues
        _STORE.append(ReachStore(os.path.join(str(DefaultValues.SYNTRAF_DATA_DIR), "reachability.json")))
    return _STORE[0]


def _bool(value, default=True):
    if value is None or value == "":
        return default
    return str(value).lower() not in ("false", "0", "no", "off")


def _port_range(text):
    m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", str(text or ""))
    return (int(m.group(1)), int(m.group(2))) if m and int(m.group(1)) <= int(m.group(2)) else None


def plan_ports(config, declared_client, generated_node, rng=random):
    """Ports à tester : un port libre de la plage des listeners (iperf3), le réflecteur, le port des tests TCP."""
    g = config.get("GLOBAL", {})
    rng_ports = _port_range(declared_client.get("MESH_LISTENERS_PORT_RANGE")) or \
        _port_range(config.get("SERVER", {}).get("MESH_LISTENERS_PORT_RANGE")) or (15000, 16000)
    used = set()
    for e in ((generated_node or {}).get("LISTENERS") or {}).values():
        try:
            used.add(int(e.get("PORT")))
        except (TypeError, ValueError):
            pass
    free = [p for p in range(rng_ports[0], rng_ports[1] + 1) if p not in used]
    ports = {"iperf3": rng.choice(free) if free else None, "iperf3_range": f"{rng_ports[0]}-{rng_ports[1]}",
             "latency": None, "tcp_test": None}
    if _bool(g.get("LATENCY"), True):
        try:
            ports["latency"] = int(g.get("LATENCY_PORT") or 8620)
        except (TypeError, ValueError):
            ports["latency"] = 8620
    if config.get("TCP_TEST"):
        try:
            ports["tcp_test"] = int(g.get("TCP_TEST_PORT") or 5201)
        except (TypeError, ValueError):
            ports["tcp_test"] = 5201
    return ports


def target_address(tester_uid, target_uid, declared, generated, dict_of_clients):
    """L'adresse de la cible telle que le testeur l'utilise pour ses flux (son connecteur), sinon celle de la config."""
    for e in (((generated or {}).get(tester_uid) or {}).get("CONNECTORS") or {}).values():
        if e.get("UID_SERVER") == target_uid and e.get("DESTINATION_ADDRESS") not in (None, "", "0.0.0.0"):
            return str(e["DESTINATION_ADDRESS"])
    override = ((declared.get(tester_uid) or {}).get("OVERRIDE_DST_NODE_IP") or {}).get(target_uid)
    if override:
        return str(override)
    ip = (declared.get(target_uid) or {}).get("IP_ADDRESS")
    if ip and ip != "0.0.0.0":
        return str(ip)
    obj = dict_of_clients.get(target_uid)
    return getattr(obj, "ip_address", None) if obj is not None else None


def choose_testers(target, declared, dict_of_clients, limit=MAX_TESTERS):
    """Sondes connectées (même derrière un NAT : il suffit qu'elles sortent), celles des mêmes mesh groups d'abord."""
    groups = set((declared.get(target) or {}).get("MESH_GROUP_UID_LIST") or [])
    out = []
    for uid, c in declared.items():
        obj = dict_of_clients.get(uid)
        if uid == target or obj is None or getattr(obj, "status", "") != "CONNECTED" or c.get("PAUSED") is True:
            continue
        out.append((0 if groups & set(c.get("MESH_GROUP_UID_LIST") or []) else 1, uid))
    return [uid for _, uid in sorted(out)[:limit]]


def _connected(dict_of_clients, uid):
    obj = dict_of_clients.get(uid)
    return obj is not None and getattr(obj, "status", "") == "CONNECTED"


def auto_requests(config, declared, dict_of_clients, reach_store, now):
    """Sondes à tester d'office : connectées depuis AUTO_SETTLE_S, non déclarées sortant seulement, jamais testées,
    testées il y a plus de AUTO_EVERY_S ou depuis une autre adresse. Une à la fois."""
    if not _bool(config.get("GLOBAL", {}).get("REACHABILITY_CHECK"), True):
        return []
    since = reach_store.connected_since
    for uid in list(since):
        if not _connected(dict_of_clients, uid):
            del since[uid]
    for uid, c in declared.items():
        if not _connected(dict_of_clients, uid):
            continue
        since.setdefault(uid, now)
        if c.get("BEHIND_NAT") or c.get("PAUSED") is True or now - since[uid] < AUTO_SETTLE_S:
            continue
        last = reach_store.latest(uid)
        address = getattr(dict_of_clients[uid], "ip_address", None)
        if last is not None and (last["status"] in ("pending", "running") or (
                now - last["requested_at"] < AUTO_EVERY_S and last.get("seen_address") == address)):
            continue
        rec = reach_store.request(uid, "auto", now)
        reach_store.update(rec["id"], seen_address=address)
        return [rec]
    return []


def tick(config, dict_of_clients, generated, commands, reach_store=None, now=None, server_check=None):
    """Passage de la surveillance : tests automatiques, tests en attente → actions REACH_LISTEN et REACH_CHECK,
    résultats manquants → fin du test."""
    reach_store = reach_store or store()
    now = now if now is not None else time.time()
    declared = {c.get("UID"): c for c in config.get("SERVER_CLIENT", [])}
    reach_store.expire(now)
    auto_requests(config, declared, dict_of_clients, reach_store, now)
    running = sum(1 for r in reach_store.list() if r["status"] == "running")
    for rec in sorted(reach_store.list(), key=lambda r: r["requested_at"]):
        if rec["status"] != "pending":
            continue
        if running >= MAX_RUNNING:
            break
        target = rec["target"]
        if target not in declared or not _connected(dict_of_clients, target):
            reach_store.update(rec["id"], status="failed", error="probe not connected", finished_at=now)
            continue
        ports = plan_ports(config, declared[target], (generated or {}).get(target))
        testers = choose_testers(target, declared, dict_of_clients) or [SERVER_TESTER]
        nonce = secrets.token_hex(NONCE_BYTES)
        start_at = now + START_DELAY_S
        tcp = [p for p in (ports["iperf3"], ports["tcp_test"]) if p]
        udp = [ports["iperf3"]] if ports["iperf3"] else []
        common = {"ID": rec["id"], "START_AT": start_at, "NONCE": nonce, "TCP_PORTS": tcp, "UDP_PORTS": udp,
                  "LATENCY_PORT": ports["latency"] or 0}
        tester_rec, address = {}, None
        for t in testers:
            addr = target_address(t, target, declared, generated, dict_of_clients) if t != SERVER_TESTER else \
                target_address(None, target, declared, generated, dict_of_clients)
            if not addr or not HOST_RE.match(str(addr)):
                continue
            address = address or addr
            tester_rec[t] = {"status": "waiting", "address": addr, "result": None}
        if not tester_rec:
            reach_store.update(rec["id"], status="failed", error="probe address unknown", finished_at=now)
            continue
        commands.setdefault(target, []).append(dict(common, ACTION="REACH_LISTEN", DURATION_S=DURATION_S))
        for t, info in tester_rec.items():
            check_cmd = dict(common, ADDRESS=info["address"], PEER=target)
            if t == SERVER_TESTER:
                (server_check or _server_check)(reach_store, rec["id"], check_cmd)
            else:
                commands.setdefault(t, []).append(dict(check_cmd, ACTION="REACH_CHECK"))
        reach_store.update(rec["id"], status="running", start_at=start_at, address=address, ports=ports,
                           testers=tester_rec, seen_address=getattr(dict_of_clients[target], "ip_address", None))
        running += 1


def _server_check(reach_store, rid, command):
    def work():
        time.sleep(max(float(command["START_AT"]) - time.time(), 0))
        try:
            result = check(command)
        except Exception as exc:  # noqa: BLE001
            result = {"error": f"{type(exc).__name__}: {exc}"[:200]}
        reach_store.file(rid, SERVER_TESTER, "check", result)
    threading.Thread(target=work, name=f"REACH_CHECK:{rid}", daemon=True).start()


def receive(payload, reach_store=None, reporter=None):
    """Mesures reçues d'une sonde : les résultats des tests d'accessibilité sont rangés (seulement ceux attendus de
    cette sonde) et retirés de ce qui va dans la base ; le reste passe tel quel."""
    reach_store = reach_store or store()
    kept = []
    for p in payload or []:
        if not (isinstance(p, dict) and p.get("measurement") == "SYNTRAF_REACH"):
            kept.append(p)
            continue
        tags = p.get("tags") or {}
        try:
            result = json.loads((p.get("fields") or {}).get("RESULT", "{}"))
        except (TypeError, ValueError):
            result = {}
        if not reach_store.file(tags.get("ID", ""), reporter, tags.get("ROLE"), result):
            log.warning(f"REACHABILITY RESULT FROM {reporter} IGNORED: NOT REQUESTED")
    return kept


def summary(rec):
    """Résumé d'un test pour la liste des clients."""
    if not rec:
        return None
    return {"id": rec["id"], "status": rec["status"], "verdict": rec.get("verdict"), "at": rec.get("finished_at")
            or rec.get("requested_at"), "reason": rec.get("reason"), "services": rec.get("services") or {},
            "iperf3_range": (rec.get("ports") or {}).get("iperf3_range"), "error": rec.get("error"),
            "testers": list(rec.get("testers") or {})}

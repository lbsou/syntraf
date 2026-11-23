"""Latence aller-retour entre sondes : TWAMP-Light (RFC 5357, paquets de test en mode non authentifié).

Chaque sonde ouvre un réflecteur UDP (GLOBAL.LATENCY_PORT) qui renvoie chaque paquet reçu, horodaté à la réception
et au renvoi. La sonde qui a le connecteur d'un pair l'interroge : c'est toujours celle qui est derrière un NAT
(elle n'a que des connecteurs), et sa requête sortante ouvre le passage de la réponse, comme pour iperf3 --bidir.
Le flux d'écho, continu et sortant, entretient lui-même la correspondance NAT.

RTT = (réception - envoi, horloge monotone de l'initiateur) - (renvoi - réception, horloge du réflecteur) : aucune
synchronisation d'horloges n'est nécessaire. Les paquets portent le DSCP du mesh group (même traitement que les
flux mesurés). Un paquet sans réponse dans le délai compte comme perdu.

Points écrits (une fois par intervalle du mesh group) : SYNTRAF_LATENCY{MESH_GROUP, CLIENT (pair), SERVER (sonde
qui mesure), UID} avec RTT_MS, RTT_MIN_MS, RTT_MAX_MS, LOSS_PCT (pertes des échos). Le serveur les accepte de la
sonde nommée SERVER, et s'en sert pour le MOS (lib/st_quality.py : latence d'un sens = RTT / 2).

Bibliothèque standard uniquement (la sonde légère n'a pas d'autre dépendance ici).
"""
import datetime as dt
import logging
import socket
import struct
import threading
import time

log = logging.getLogger("syntraf." + __name__)

NTP_OFFSET = 2208988800  # 1900 → 1970
PACKET_SIZE = 64          # envoi rembourré : la réponse (41 octets + bourrage) n'est jamais plus grande (RFC 5357 §4.2.1)
COUNT = 5                 # paquets par intervalle
TIMEOUT_S = 1.0
ERROR_ESTIMATE = 0x0001   # horloge non synchronisée (bit S à 0), échelle 0, multiplicateur 1
DEFAULT_PORT = 8620

_SENDER = struct.Struct("!IQH")                # numéro, horodatage, estimation d'erreur
_REPLY = struct.Struct("!IQHHQIQHHB")          # §4.2.1 : 41 octets


def to_ntp(t):
    secs = int(t) + NTP_OFFSET
    return (secs << 32) | int((t - int(t)) * (1 << 32))


def from_ntp(v):
    return (v >> 32) - NTP_OFFSET + (v & 0xFFFFFFFF) / (1 << 32)


def sender_packet(seq, t):
    return _SENDER.pack(seq & 0xFFFFFFFF, to_ntp(t), ERROR_ESTIMATE).ljust(PACKET_SIZE, b"\0")


def parse_sender(pkt):
    seq, ts, err = _SENDER.unpack_from(pkt)
    return {"seq": seq, "ts": from_ntp(ts), "error": err}


def reflect(pkt, received, sent, seq, ttl=255):
    s = parse_sender(pkt)
    body = _REPLY.pack(seq & 0xFFFFFFFF, to_ntp(sent), ERROR_ESTIMATE, 0, to_ntp(received), s["seq"],
                       to_ntp(s["ts"]), s["error"], 0, ttl & 0xFF)
    return body.ljust(min(len(pkt), PACKET_SIZE), b"\0")


def parse_reply(pkt):
    seq, sent, _, _, received, sseq, sts, _, _, _ = _REPLY.unpack_from(pkt)
    return {"seq": seq, "sent": from_ntp(sent), "received": from_ntp(received), "sender_seq": sseq,
            "sender_ts": from_ntp(sts)}


def rtt_ms(sent_mono, received_mono, reflector_received, reflector_sent):
    """RTT sans le temps passé dans le réflecteur (deux horloges, chacune pour ses propres intervalles)."""
    return max(((received_mono - sent_mono) - max(reflector_sent - reflector_received, 0.0)) * 1000, 0.0)


def stats(sent, rtts):
    loss = round(100.0 * (sent - len(rtts)) / sent, 1) if sent else 100.0
    if not rtts:
        return {"LOSS_PCT": 100.0}
    return {"RTT_MS": round(sum(rtts) / len(rtts), 2), "RTT_MIN_MS": round(min(rtts), 2),
            "RTT_MAX_MS": round(max(rtts), 2), "LOSS_PCT": loss}


def targets(config):
    """Pairs à interroger : ceux des connecteurs de cette sonde (une cible par pair, DSCP et mesh group)."""
    out, seen = [], set()
    me = config.get("CLIENT", {}).get("CLIENT_UID", "")
    for e in (config.get("CONNECTORS") or {}).values():
        address = str(e.get("DESTINATION_ADDRESS") or "")
        if not address or address == "0.0.0.0":
            continue
        try:
            dscp = int(e.get("DSCP") or 0)
            interval = float(e.get("INTERVAL") or 1)
        except (TypeError, ValueError):
            continue
        t = {"peer": e.get("UID_SERVER"), "me": e.get("UID_CLIENT") or me, "address": address, "dscp": dscp,
             "mesh_group": e.get("MESH_GROUP"), "interval": interval}
        key = (t["peer"], t["address"], t["dscp"], t["mesh_group"])
        if key not in seen:
            seen.add(key)
            out.append(t)
    return out


def point(target, fields, utime):
    peer, me = target["peer"], target["me"]
    return {"measurement": "SYNTRAF_LATENCY",
            "tags": {"MESH_GROUP": target["mesh_group"], "CLIENT": peer, "SERVER": me,
                     "UID": f"{peer}__TO__{me}__ON__DSCP{target['dscp']}"},
            "time": dt.datetime.fromtimestamp(utime, dt.timezone.utc), "fields": dict(fields)}


def _tos_socket(dscp):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, (int(dscp) & 0x3F) << 2)
    except OSError:
        pass  # Windows : le marquage peut être ignoré
    return s


def measure_once(target, port, count=COUNT, timeout=TIMEOUT_S):
    """Un intervalle de mesure : count échos espacés sur l'intervalle, puis attente des réponses en retard."""
    s = _tos_socket(target["dscp"])
    sent_at, rtts = {}, []
    spacing = max(float(target["interval"]) / count, 0.01)
    try:
        s.setblocking(False)
        deadline = None
        seq = int(time.monotonic() * 1000) & 0xFFFF0000
        for i in range(count):
            n = (seq + i) & 0xFFFFFFFF
            sent_at[n] = time.monotonic()
            try:
                s.sendto(sender_packet(n, time.time()), (target["address"], int(port)))
            except OSError:
                pass
            _collect(s, sent_at, rtts, time.monotonic() + spacing)
        deadline = time.monotonic() + timeout
        while len(rtts) < count and time.monotonic() < deadline:
            _collect(s, sent_at, rtts, min(deadline, time.monotonic() + 0.05))
    finally:
        s.close()
    return stats(count, rtts)


def _collect(s, sent_at, rtts, until):
    import select
    while True:
        left = until - time.monotonic()
        if left <= 0:
            return
        ready, _, _ = select.select([s], [], [], left)
        if not ready:
            return
        try:
            data, _ = s.recvfrom(2048)
        except (BlockingIOError, ConnectionResetError, OSError):
            continue  # Windows : ICMP « port injoignable » remonté en erreur sur la socket
        now = time.monotonic()
        if len(data) < _REPLY.size:
            continue
        r = parse_reply(data)
        start = sent_at.pop(r["sender_seq"], None)
        if start is not None:
            rtts.append(rtt_ms(start, now, r["received"], r["sent"]))


MAX_PACKET = 1500
LEARNED_TTL_S = 24 * 3600

# Pairs légitimes appris des sessions iperf3 acceptées par les récepteurs de cette sonde (authentifiées par RSA quand
# l'authentification iperf3 est active) : leur adresse telle que vue ici, donc l'adresse publique du NAT pour une
# sonde derrière un NAT. {adresse: dernière fois vue (monotone)}
LEARNED = {}
_LEARNED_LOCK = threading.Lock()


def learn_from_iperf3(line):
    """Ligne de sortie d'un récepteur iperf3 : « Accepted connection from X, port P »."""
    import re
    m = re.search(r"Accepted connection from ([0-9a-fA-F:.]+), port", line)
    if m:
        with _LEARNED_LOCK:
            LEARNED[m.group(1)] = time.monotonic()


def allowed_peers(config, now=None):
    """Adresses auxquelles le réflecteur répond : celles des connecteurs (pairs mesurés d'ici, qui mesurent aussi) et
    celles apprises des sessions iperf3 acceptées (pairs qui mesurent cette sonde, y compris derrière un NAT)."""
    now = now if now is not None else time.monotonic()
    out = set()
    for t in targets(config):
        try:
            out.add(socket.gethostbyname(t["address"]))
        except OSError:
            pass
    with _LEARNED_LOCK:
        for ip, seen in list(LEARNED.items()):
            if now - seen > LEARNED_TTL_S:
                del LEARNED[ip]
            else:
                out.add(ip)
    return out


def acceptable(data):
    """Paquet de test plausible : au moins l'en-tête d'un envoi TWAMP, pas plus grand qu'un datagramme courant."""
    return _SENDER.size <= len(data) <= MAX_PACKET


class RateLimiter:
    """Seaux à jetons par source et global, remplis chaque seconde. Un initiateur envoie COUNT paquets par
    intervalle et par mesh group : 20 par seconde laissent de la marge ; au-delà, le réflecteur se tait, ce qui
    rend inutile tout usage comme relais (en plus, la réponse n'est jamais plus grande que la requête)."""

    def __init__(self, per_source=20, total=200, max_sources=4096):
        self.per_source, self.total, self.max_sources = per_source, total, max_sources
        self._second, self._by_source, self._count = None, {}, 0

    def allow(self, source, now=None):
        second = int(now if now is not None else time.monotonic())
        if second != self._second:
            self._second, self._by_source, self._count = second, {}, 0
        n = self._by_source.get(source, 0)
        if n >= self.per_source or self._count >= self.total or (
                n == 0 and len(self._by_source) >= self.max_sources):
            return False
        self._by_source[source] = n + 1
        self._count += 1
        return True


class Reflector:
    """Renvoie chaque paquet de test reçu, avec le DSCP reçu quand le système le donne (Linux). Sécurité : réponse
    jamais plus grande que la requête (pas d'amplification), débit limité par source et au total, paquets mal
    formés ignorés. Aucune donnée de la sonde n'est révélée, hormis l'heure de son horloge."""

    def __init__(self, port, host="0.0.0.0"):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, int(port)))
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.5)
        self._stop = threading.Event()
        self._seq = 0
        self._limiter = RateLimiter()
        self._allowed = None  # None : toute source (tests) ; sinon, seulement ces adresses
        self._recv_tos = hasattr(socket, "IP_RECVTOS") and hasattr(self.sock, "recvmsg")
        if self._recv_tos:
            try:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
            except OSError:
                self._recv_tos = False
        self.thread = threading.Thread(target=self._run, name=f"LATENCY_REFLECTOR:{self.port}", daemon=True)

    def start(self):
        self.thread.start()
        return self

    def set_allowed(self, addresses):
        self._allowed = frozenset(addresses)

    def stop(self):
        self._stop.set()
        self.thread.join(timeout=2)
        self.sock.close()

    def _run(self):
        tos_now = None
        while not self._stop.is_set():
            try:
                if self._recv_tos:
                    data, anc, _, addr = self.sock.recvmsg(2048, socket.CMSG_SPACE(4))
                    tos = next((c[2][0] for c in anc if c[0] == socket.IPPROTO_IP and c[1] == socket.IP_TOS), None)
                else:
                    data, addr = self.sock.recvfrom(2048)
                    tos = None
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue
            received = time.time()
            allowed = self._allowed
            if not acceptable(data) or (allowed is not None and addr[0] not in allowed)                     or not self._limiter.allow(addr[0]):
                continue
            if tos is not None and tos != tos_now:
                try:
                    self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
                    tos_now = tos
                except OSError:
                    pass
            self._seq += 1
            try:
                self.sock.sendto(reflect(data, received, time.time(), self._seq), addr)
            except OSError:
                pass


class Manager:
    """Sur une sonde : un réflecteur, et une boucle de mesure par pair de ses connecteurs (réconciliés à chaque passe
    de la surveillance)."""

    def __init__(self):
        self.reflector = None
        self.loops = {}
        self.lock = threading.Lock()

    def sync(self, config, queue, enqueue):
        g = config.get("GLOBAL", {})
        enabled = str(g.get("LATENCY", True)).lower() not in ("false", "0", "no", "off")
        try:
            port = int(g.get("LATENCY_PORT") or DEFAULT_PORT)
        except (TypeError, ValueError):
            port = DEFAULT_PORT
        with self.lock:
            if not enabled:
                self._stop_all()
                return
            if self.reflector is None or self.reflector.port != port:
                if self.reflector is not None:
                    self.reflector.stop()
                try:
                    self.reflector = Reflector(port).start()
                    log.info(f"LATENCY REFLECTOR (TWAMP-LIGHT) LISTENING ON UDP {port}")
                except OSError as exc:
                    self.reflector = None
                    log.warning(f"LATENCY REFLECTOR CANNOT LISTEN ON UDP {port}: {exc}")
            if self.reflector is not None:
                self.reflector.set_allowed(allowed_peers(config))
            wanted = {(t["peer"], t["address"], t["dscp"], t["mesh_group"], t["interval"], port): t
                      for t in targets(config)}
            for key in [k for k in self.loops if k not in wanted]:
                self.loops.pop(key).set()
            for key, t in wanted.items():
                if key not in self.loops:
                    stop = threading.Event()
                    self.loops[key] = stop
                    threading.Thread(target=self._loop, args=(t, port, stop, queue, enqueue),
                                     name=f"LATENCY:{t['peer']}", daemon=True).start()

    def _stop_all(self):
        for stop in self.loops.values():
            stop.set()
        self.loops.clear()
        if self.reflector is not None:
            self.reflector.stop()
            self.reflector = None

    @staticmethod
    def _loop(target, port, stop, queue, enqueue):
        while not stop.is_set():
            start = time.time()
            try:
                fields = measure_once(target, port)
                enqueue(queue, point(target, fields, int(start)))
            except Exception as exc:  # noqa: BLE001 - une mesure ratée ne doit pas arrêter la boucle
                log.debug(f"LATENCY TO {target['peer']}: {type(exc).__name__}:{exc}")
            stop.wait(max(float(target["interval"]) - (time.time() - start), 0.05))


MANAGER = Manager()

"""Renvoi des journaux vers un collecteur syslog (SIEM), en RFC 5424 ou en CEF (ArcSight Common Event Format).

Sur le serveur : ses propres journaux, et ceux que les clients lui transmettent (l'hôte syslog est alors le client).
Transport UDP (RFC 5426), TCP (RFC 6587, cadrage par longueur) ou TLS (RFC 5425). L'envoi se fait dans un fil à part
depuis une file bornée : un collecteur lent ou injoignable ne bloque jamais SYNTRAF ; les messages en trop sont
abandonnés et comptés. Réglages dans la section GLOBAL (SYSLOG_*), appliqués à chaud.
"""
import dataclasses
import datetime as dt
import logging
import os
import queue
import re
import socket
import ssl
import threading
import time

from lib.st_log_search import LINE_RE, LEVELS, log_type, parse_time

log = logging.getLogger("syntraf." + __name__)

FACILITIES = {"user": 1, "daemon": 3, "auth": 4, "syslog": 5, **{f"local{i}": 16 + i for i in range(8)}}
SEVERITY = {"DEBUG": 7, "INFO": 6, "WARNING": 4, "ERROR": 3, "CRITICAL": 2}
CEF_SEVERITY = {"DEBUG": 1, "INFO": 3, "WARNING": 6, "ERROR": 8, "CRITICAL": 10}
PROTOCOLS = ("udp", "tcp", "tls")
FORMATS = ("rfc5424", "cef")
DEFAULT_PORT = {"udp": 514, "tcp": 514, "tls": 6514}
UDP_MAX_BYTES = 8192
APP_NAME = "syntraf"
HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]_]{1,253}$")
MESSAGES = {
    "SYSLOG_HOST": "A host name or an IP address",
    "SYSLOG_PORT": "A port between 1 and 65535 (empty: 514, or 6514 with TLS)",
    "SYSLOG_PROTOCOL": "udp, tcp or tls",
    "SYSLOG_FORMAT": "rfc5424 or cef",
    "SYSLOG_LEVEL": "DEBUG, INFO, WARNING, ERROR or CRITICAL",
    "SYSLOG_FACILITY": ", ".join(FACILITIES),
    "SYSLOG_TLS_CA": "Path of a CA file (PEM) on the server, or empty for the system CAs",
}
KEYS = ("SYSLOG_HOST", "SYSLOG_PORT", "SYSLOG_PROTOCOL", "SYSLOG_FORMAT", "SYSLOG_LEVEL", "SYSLOG_FACILITY",
        "SYSLOG_INCLUDE_CLIENTS", "SYSLOG_TLS_CA", "SYSLOG_TLS_VERIFY")


def _bool(value, default):
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes", "on")


@dataclasses.dataclass
class Settings:
    host: str = ""
    port: int = 0
    protocol: str = "udp"
    format: str = "rfc5424"
    level: str = "WARNING"
    facility: str = "local0"
    include_clients: bool = True
    tls_ca: str = ""
    tls_verify: bool = True

    def __post_init__(self):
        if not self.port:
            self.port = DEFAULT_PORT.get(self.protocol, 514)

    @property
    def enabled(self):
        return bool(self.host)

    @classmethod
    def from_global(cls, g):
        g = g or {}
        protocol = str(g.get("SYSLOG_PROTOCOL") or "udp").strip().lower()
        port = str(g.get("SYSLOG_PORT") or "").strip()
        return cls(host=str(g.get("SYSLOG_HOST") or "").strip(), port=int(port) if port.isdigit() else 0,
                   protocol=protocol, format=str(g.get("SYSLOG_FORMAT") or "rfc5424").strip().lower(),
                   level=str(g.get("SYSLOG_LEVEL") or "WARNING").strip().upper(),
                   facility=str(g.get("SYSLOG_FACILITY") or "local0").strip().lower(),
                   include_clients=_bool(g.get("SYSLOG_INCLUDE_CLIENTS"), True),
                   tls_ca=str(g.get("SYSLOG_TLS_CA") or "").strip(), tls_verify=_bool(g.get("SYSLOG_TLS_VERIFY"), True))


def setting_errors(values):
    """Erreurs par champ ; sans hôte, le renvoi est désactivé et rien d'autre n'est exigé."""
    v = {k: str(values.get(k, "") if values.get(k) is not None else "").strip() for k in KEYS}
    if not v["SYSLOG_HOST"]:
        return {}
    checks = {
        "SYSLOG_HOST": HOST_RE.match(v["SYSLOG_HOST"]) is not None,
        "SYSLOG_PORT": not v["SYSLOG_PORT"] or (v["SYSLOG_PORT"].isdigit() and 1 <= int(v["SYSLOG_PORT"]) <= 65535),
        "SYSLOG_PROTOCOL": not v["SYSLOG_PROTOCOL"] or v["SYSLOG_PROTOCOL"].lower() in PROTOCOLS,
        "SYSLOG_FORMAT": not v["SYSLOG_FORMAT"] or v["SYSLOG_FORMAT"].lower() in FORMATS,
        "SYSLOG_LEVEL": not v["SYSLOG_LEVEL"] or v["SYSLOG_LEVEL"].upper() in LEVELS,
        "SYSLOG_FACILITY": not v["SYSLOG_FACILITY"] or v["SYSLOG_FACILITY"].lower() in FACILITIES,
        "SYSLOG_TLS_CA": not v["SYSLOG_TLS_CA"] or os.path.isfile(v["SYSLOG_TLS_CA"]),
    }
    return {k: MESSAGES[k] for k, ok in checks.items() if not ok}


# ---------------------------------------------------------------------------------------------- formats

def _token(text):
    """Champ d'en-tête syslog : ASCII imprimable sans espace, « - » si vide."""
    text = re.sub(r"\s+", "_", str(text or "").strip())
    text = "".join(c for c in text if 33 <= ord(c) <= 126)
    return text[:255] or "-"


def _header(entry, facility, msgid):
    pri = FACILITIES.get(facility, 16) * 8 + SEVERITY.get(entry.get("level"), 6)
    when = entry.get("time")
    stamp = when.isoformat() if isinstance(when, dt.datetime) else "-"
    return f"<{pri}>1 {stamp} {_token(entry.get('node'))} {APP_NAME} - {_token(msgid)} -"


def _source(entry):
    where = entry.get("where")
    return f"{entry.get('module', '')} ({where})" if where else str(entry.get("module", ""))


def format_rfc5424(entry, facility="local0"):
    return f"{_header(entry, facility, entry.get('type'))} {_source(entry)} - {entry.get('message', '')}"


def cef_severity(level):
    return CEF_SEVERITY.get(level, 3)


def _cef_header(text):
    text = " ".join(str(text).split("\n"))
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ")


def _cef_value(text):
    return (str(text).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n"))


def format_cef(entry, facility="local0", version="-"):
    when = entry.get("time")
    rt = int(when.timestamp() * 1000) if isinstance(when, dt.datetime) else int(time.time() * 1000)
    message = str(entry.get("message", ""))
    ext = {"rt": rt, "dvchost": entry.get("node", ""), "cs1Label": "module", "cs1": _source(entry),
           "cs2Label": "level", "cs2": entry.get("level", ""), "msg": message}
    head = "|".join(_cef_header(x) for x in ("SYNTRAF", "SYNTRAF", version or "-",
                                              entry.get("type") or "system", message[:512]))
    extension = " ".join(f"{k}={_cef_value(v)}" for k, v in ext.items())
    return f"{_header(entry, facility, None)} CEF:0|{head}|{cef_severity(entry.get('level'))}|{extension}"


def render(entry, settings, version="-"):
    if settings.format == "cef":
        return format_cef(entry, settings.facility, version)
    return format_rfc5424(entry, settings.facility)


def frame(message, protocol):
    data = message.encode("utf-8", errors="replace")
    if protocol == "udp":
        return data[:UDP_MAX_BYTES]
    return str(len(data)).encode() + b" " + data  # RFC 6587 / 5425 : cadrage par nombre d'octets


# ---------------------------------------------------------------------------------------------- envoi

class Forwarder:
    def __init__(self, capacity=10_000, version="-"):
        self.settings = Settings()
        self.version = version  # version de SYNTRAF, dans l'en-tête CEF
        self._queue = queue.Queue(maxsize=capacity)
        self._lock = threading.Lock()
        self._stats = {"sent": 0, "dropped": 0, "last_error": "", "last_error_time": None, "connected": False}
        self._generation = 0
        self._stop = threading.Event()
        self._thread = None

    def configure(self, settings):
        with self._lock:
            self.settings = settings
            self._generation += 1
            self._stats.update(connected=False, last_error="")
            if settings.enabled and (self._thread is None or not self._thread.is_alive()):
                self._stop.clear()
                self._thread = threading.Thread(target=self._run, name="SYSLOG_FORWARDER", daemon=True)
                self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(2)

    def submit(self, entry, force=False):
        s = self.settings
        if not s.enabled:
            return
        level = entry.get("level")
        if not force and level in LEVELS and LEVELS.index(level) < LEVELS.index(s.level if s.level in LEVELS else "WARNING"):
            return
        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            with self._lock:
                self._stats["dropped"] += 1

    def forward_client_lines(self, uid, lines):
        """Lignes reçues d'un client (format des fichiers de journal) ; les lignes de suite rejoignent leur entrée."""
        if not (self.settings.enabled and self.settings.include_clients):
            return
        current = None
        for raw in lines or []:
            line = str(raw).rstrip("\n")
            m = LINE_RE.match(line)
            if m:
                if current:
                    self.submit(current)
                when = parse_time(m.group(1))
                current = {"time": when, "level": m.group(2), "node": uid, "module": m.group(3), "where": m.group(4),
                           "type": log_type(m.group(3)), "message": m.group(5)}
            elif current and line.strip():
                current["message"] += "\n" + line
        if current:
            self.submit(current)

    def status(self):
        s = self.settings
        with self._lock:
            out = dict(self._stats)
        out.update(enabled=s.enabled, queued=self._queue.qsize(),
                   target=f"{s.protocol}://{s.host}:{s.port}" if s.enabled else "")
        return out

    def send_test(self, actor="", wait_s=3.0):
        """Envoie un message d'essai (quel que soit le niveau) et attend son envoi ou une erreur."""
        before = self.status()
        self.submit({"time": dt.datetime.now().astimezone(), "level": "WARNING", "node": socket.gethostname(),
                     "module": "st_syslog", "where": "send_test", "type": "system",
                     "message": f"SYSLOG TEST MESSAGE FROM SYNTRAF{f' (REQUESTED BY {actor})' if actor else ''}"},
                    force=True)
        end = time.time() + wait_s
        while time.time() < end:
            now = self.status()
            if now["sent"] > before["sent"] or (now["last_error"] and now["last_error_time"] != before["last_error_time"]):
                return now
            time.sleep(0.05)
        return self.status()

    # -- fil d'envoi
    def _connect(self, s):
        if s.protocol == "udp":
            sock = socket.socket(socket.AF_INET6 if ":" in s.host.strip("[]") else socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((s.host.strip("[]"), s.port))
            return sock
        sock = socket.create_connection((s.host.strip("[]"), s.port), timeout=5)
        if s.protocol == "tls":
            ctx = ssl.create_default_context(cafile=s.tls_ca or None)
            if not s.tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(sock, server_hostname=s.host.strip("[]"))
            except Exception:
                sock.close()
                raise
        sock.settimeout(10)
        return sock

    def _fail(self, exc):
        with self._lock:
            self._stats.update(dropped=self._stats["dropped"] + 1, connected=False,
                               last_error=f"{type(exc).__name__}: {exc}",
                               last_error_time=dt.datetime.now(dt.timezone.utc).isoformat())

    def _run(self):
        sock, generation, backoff = None, None, 1.0
        while not self._stop.is_set():
            try:
                entry = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            s = self.settings
            if generation != self._generation:
                if sock:
                    sock.close()
                sock, generation, backoff = None, self._generation, 1.0
            if not s.enabled:
                continue
            try:
                data = frame(render(entry, s, self.version), s.protocol)
                if sock is None:
                    sock = self._connect(s)
                sock.sendall(data) if s.protocol != "udp" else sock.send(data)
                with self._lock:
                    self._stats["sent"] += 1
                    self._stats["connected"] = True
                backoff = 1.0
            except Exception as exc:  # noqa: BLE001 - le fil d'envoi ne doit jamais mourir
                if sock:
                    sock.close()
                sock = None
                self._fail(exc)
                self._stop.wait(backoff)  # pendant l'attente, la file se remplit puis abandonne : jamais de blocage
                backoff = min(backoff * 2, 30.0)
        if sock:
            sock.close()


class SyslogHandler(logging.Handler):
    """Journaux du serveur vers le Forwarder ; ceux du module syslog lui-même ne sont jamais renvoyés (boucle)."""

    def __init__(self, forwarder, node=None):
        super().__init__(logging.NOTSET)
        self.forwarder = forwarder
        self.node = node or socket.gethostname()

    def emit(self, record):
        if record.name.startswith(log.name) or not self.forwarder.settings.enabled:
            return
        try:
            message = record.getMessage()
            if record.exc_info:
                message += "\n" + logging.Formatter().formatException(record.exc_info)
            self.forwarder.submit({
                "time": dt.datetime.fromtimestamp(record.created).astimezone(), "level": record.levelname,
                "node": self.node, "module": record.module, "where": f"{record.funcName},{record.lineno}",
                "type": log_type(record.module), "message": message})
        except Exception:  # noqa: BLE001 - un message mal formé ne doit pas casser l'application
            pass


FORWARDER = Forwarder()
_HANDLER = []


def install(global_section, version=None, logger_name="syntraf"):
    """Sur le serveur : applique les réglages SYSLOG_* et branche le handler (une seule fois)."""
    if version:
        FORWARDER.version = version
    FORWARDER.configure(Settings.from_global(global_section))
    if not _HANDLER:
        _HANDLER.append(SyslogHandler(FORWARDER))
        logging.getLogger(logger_name).addHandler(_HANDLER[0])

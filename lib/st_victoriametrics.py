"""
Moteur de base de données VictoriaMetrics pour SYNTRAF (DB_ENGINE = "VictoriaMetrics").

Même interface publique que InfluxObj (lib/st_influxdb.py) :
    status, status_time, database_uid,
    save_metrics_to_database_with_buffer(payload, address, client_uid) -> "OK" | "ERROR",
    force_status_check(), get_Database_UID()

Les mesures sont écrites en line protocol InfluxDB sur /api/v2/write, que VictoriaMetrics
accepte nativement : la mesure SYNTRAF et le champ RX_PCT_LOSS deviennent la métrique
SYNTRAF_RX_PCT_LOSS{UID=..., CLIENT=..., SERVER=..., MESH_GROUP=...}.

Chaque lot est écrit en une requête synchrone : "OK" n'est renvoyé que si VictoriaMetrics
a répondu 2xx. En cas d'échec, "ERROR" permet au client de garder ses mesures en tampon.

Bibliothèque standard uniquement.
"""
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("syntraf." + __name__)

HTTP_TIMEOUT_S = 10
INTEGER_FIELDS = {"RX_PACKET_TOTAL", "RX_PACKET_LOSS"}


def _escape_key(s) -> str:
    return str(s).replace("\\", "\\\\").replace(",", "\\,").replace("=", "\\=").replace(" ", "\\ ")


def _escape_measurement(s) -> str:
    return str(s).replace("\\", "\\\\").replace(",", "\\,").replace(" ", "\\ ")


def _field_value(key: str, value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if key in INTEGER_FIELDS or isinstance(value, int):
        return f"{int(value)}i"
    if isinstance(value, float):
        return repr(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _timestamp_ns(t) -> int:
    if isinstance(t, int):
        return t
    if isinstance(t, datetime):
        dt = t
    else:
        dt = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp()) * 1_000_000_000 + dt.microsecond * 1_000


def to_line_protocol(points: list) -> str:
    """Convertit les dicts produits par generate_json (st_influxdb) en line protocol."""
    lines = []
    for p in points:
        tags = "".join(f",{_escape_key(k)}={_escape_key(v)}" for k, v in sorted(p.get("tags", {}).items())
                       if v is not None and str(v) != "")
        fields = ",".join(f"{_escape_key(k)}={_field_value(k, v)}" for k, v in p["fields"].items())
        line = f"{_escape_measurement(p['measurement'])}{tags} {fields}"
        if p.get("time") is not None:
            line += f" {_timestamp_ns(p['time'])}"
        lines.append(line)
    return "\n".join(lines)


class VictoriaMetricsObj(object):
    def __init__(self, _config, database_uid):
        self.database_uid = database_uid
        self.DB_UID = database_uid
        self.status = "FAIL"
        self.status_time = datetime.now()
        database = next((d for d in _config.get('DATABASE', []) if d.get('DB_UID') == database_uid), None)
        if database is None:
            log.error(f"DATABASE '{database_uid}' NOT FOUND IN CONFIG")
            return
        self.prefix = "https" if database.get('DB_SERVER_USE_SSL') else "http"
        self.DB_SERVER = database['DB_SERVER']
        self.DB_PORT = database['DB_PORT']
        self.base_url = f"{self.prefix}://{self.DB_SERVER}:{self.DB_PORT}"
        self._headers = {}
        if database.get('DB_TOKEN'):
            self._headers["Authorization"] = f"Bearer {database['DB_TOKEN']}"
        handlers = []
        if database.get('DB_USE_WEB_PROXY'):
            proxy = database['DB_USE_WEB_PROXY']
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        else:
            handlers.append(urllib.request.ProxyHandler({}))
        self._opener = urllib.request.build_opener(*handlers)

        if self._healthy():
            self.status = "ONLINE"
            log.info(f"CONNECTION TO DATABASE '{database_uid}', '{self.base_url}' (VICTORIAMETRICS) SUCCESSFUL")
        else:
            self.status = "OFFLINE"
            log.error(f"CONNECTION TO DATABASE '{database_uid}', '{self.base_url}' (VICTORIAMETRICS) FAILED")
        self.status_time = datetime.now()

    def _request(self, method: str, path: str, data: bytes | None = None) -> int:
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers=dict(self._headers, **({"Content-Type": "text/plain; charset=utf-8"} if data else {})))
        with self._opener.open(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.status

    def _healthy(self) -> bool:
        try:
            return self._request("GET", "/health") == 200
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.debug(f"VICTORIAMETRICS HEALTH CHECK FAILED FOR '{self.database_uid}': {type(exc).__name__}:{exc}")
            return False

    def _set_status(self, new_status: str) -> None:
        if self.status != new_status:
            self.status = new_status
            self.status_time = datetime.now()
            if new_status == "ONLINE":
                log.info(f"DATABASE '{self.DB_UID}', '{self.base_url}' IS NOW ONLINE")
            else:
                log.warning(f"DATABASE '{self.DB_UID}', '{self.base_url}' IS NOW {new_status}")

    def force_status_check(self):
        self._set_status("ONLINE" if self._healthy() else "OFFLINE")

    def save_metrics_to_database_with_buffer(self, payload, address, client_uid):
        try:
            body = to_line_protocol(payload).encode("utf-8")
            if not body:
                return "OK"
            code = self._request("POST", "/api/v2/write", body)
            if 200 <= code < 300:
                self._set_status("ONLINE")
                return "OK"
            log.error(f"VICTORIAMETRICS '{self.DB_UID}' ANSWERED HTTP {code} TO A WRITE FROM {client_uid}")
        except urllib.error.HTTPError as exc:
            log.error(f"VICTORIAMETRICS '{self.DB_UID}' ANSWERED HTTP {exc.code} TO A WRITE FROM {client_uid}")
        except Exception as exc:
            log.error(f"UNABLE TO WRITE {len(payload)} METRICS FROM {client_uid} TO VICTORIAMETRICS '{self.DB_UID}': {type(exc).__name__}:{exc}")
        self._set_status("OFFLINE")
        return "ERROR"

    def get_Database_UID(self):
        return self.database_uid

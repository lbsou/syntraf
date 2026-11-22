"""Administration des données SYNTRAF dans VictoriaMetrics (version libre) : état, rétention, instantanés, purge.

La rétention de VictoriaMetrics est l'option -retentionPeriod, fixée au démarrage : SYNTRAF la lit (/flags), la
compare à la rétention cible de la base (DB_RETENTION) et explique comment l'aligner, mais ne la change pas.
La version libre ne supprime pas une plage de dates : la purge porte sur des séries entières (un client ou un
mesh group retiré).
"""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from lib.st_mesh_group_ops import parse_retention

HTTP_TIMEOUT_S = 10
SAFE_VALUE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
PURGE_LABELS = {"client": ("CLIENT", "SERVER"), "mesh_group": ("MESH_GROUP",)}
METRIC_MATCH = '__name__=~"SYNTRAF_.*"'


class VmError(Exception):
    pass


class VmAdmin:
    def __init__(self, db, http=None, now=time.time):
        self.db = db
        self.uid = db["DB_UID"]
        self._http = http or self._urllib
        self._now = now
        scheme = "https" if db.get("DB_SERVER_USE_SSL") else "http"
        self.base_url = f"{scheme}://{db['DB_SERVER']}:{db['DB_PORT']}"

    # ------------------------------------------------------------------------------------------------- état

    def status(self):
        flags = self._get_text("/flags")
        m = re.search(r'-retentionPeriod="?([^"\s]+)"?', flags)
        retention = m.group(1) if m else "1"  # défaut de VictoriaMetrics : 1 mois
        target = self.db.get("DB_RETENTION") or None
        matches = None if target is None else parse_retention(target) == parse_retention(retention)
        metrics = _parse_metrics(self._get_text("/metrics"))
        retention_hours = parse_retention(retention) or 31 * 24
        return {
            "uid": self.uid,
            "retention": retention,
            "retention_target": target,
            "retention_matches": matches,
            "retention_advice": None if matches in (None, True) else (
                f"VictoriaMetrics keeps data for {retention}, the target is {target}. Restart VictoriaMetrics with "
                f"-retentionPeriod={target} (data older than the new period is then removed progressively)."),
            "data_size_bytes": int(sum(v for k, v in metrics.items() if k.startswith("vm_data_size_bytes"))),
            "free_disk_bytes": int(sum(v for k, v in metrics.items() if k.startswith("vm_free_disk_space_bytes"))),
            "rows": int(sum(v for k, v in metrics.items() if k.startswith("vm_rows{"))),
            "oldest_day": self._oldest_day(retention_hours),
        }

    def _oldest_day(self, retention_hours):
        """Début de la plus ancienne journée qui contient des mesures SYNTRAF (epoch), ou None."""
        end = int(self._now())
        start = end - retention_hours * 3600
        data = self._get_json("/api/v1/query_range", {
            "query": f"count(count_over_time({{{METRIC_MATCH}}}[1d]))", "start": start, "end": end, "step": "1d"})
        values = [v for r in data.get("result", []) for v in r.get("values", [])]
        return min((int(float(t)) for t, _ in values), default=None)

    # -------------------------------------------------------------------------------------------- orphelins

    def orphans(self, clients, mesh_groups):
        """Clients et mesh groups présents dans les données mais plus déclarés dans la configuration."""
        seen_clients = set(self._label_values("CLIENT")) | set(self._label_values("SERVER"))
        return {"clients": sorted(seen_clients - set(clients)),
                "mesh_groups": sorted(set(self._label_values("MESH_GROUP")) - set(mesh_groups))}

    def _label_values(self, label):
        return self._get_json(f"/api/v1/label/{label}/values", {"match[]": f"{{{METRIC_MATCH}}}"}) or []

    # ------------------------------------------------------------------------------------------------ purge

    def purge(self, kind, value, dry_run=False):
        """Supprime toutes les séries SYNTRAF d'un client (comme émetteur et comme récepteur) ou d'un mesh group.
        dry_run : compte seulement les séries concernées."""
        if kind not in PURGE_LABELS:
            raise ValueError(f"unknown purge kind '{kind}'")
        if not SAFE_VALUE.match(value or ""):
            raise ValueError(f"invalid name '{value}'")
        matchers = [f'{{{METRIC_MATCH},{label}="{value}"}}' for label in PURGE_LABELS[kind]]
        start = int(self._now()) - 10 * 365 * 24 * 3600
        series = self._get_json("/api/v1/series", {"match[]": matchers, "start": start})
        result = {"kind": kind, "value": value, "series": len(series or []), "dry_run": dry_run}
        if not dry_run:
            status, _ = self._http("POST", "/api/v1/admin/tsdb/delete_series", {"match[]": matchers})
            if status not in (200, 204):
                raise VmError(f"delete_series answered HTTP {status}")
        return result

    # ------------------------------------------------------------------------------------------ instantanés

    def snapshots(self):
        return self._get_json_raw("/snapshot/list").get("snapshots", [])

    def create_snapshot(self):
        data = self._get_json_raw("/snapshot/create")
        if data.get("status") != "ok":
            raise VmError(data.get("msg") or "snapshot creation failed")
        return data["snapshot"]

    def delete_snapshot(self, name):
        if not SAFE_VALUE.match(name or ""):
            raise ValueError(f"invalid snapshot name '{name}'")
        data = self._get_json_raw("/snapshot/delete", {"snapshot": name})
        if data.get("status") != "ok":
            raise VmError(data.get("msg") or "snapshot deletion failed")

    # ------------------------------------------------------------------------------------------------- HTTP

    def _get_text(self, path, params=None):
        status, body = self._http("GET", path, params)
        if status != 200:
            raise VmError(f"{path} answered HTTP {status}")
        return body

    def _get_json_raw(self, path, params=None):
        try:
            return json.loads(self._get_text(path, params))
        except ValueError as exc:
            raise VmError(f"{path}: invalid JSON ({exc})")

    def _get_json(self, path, params=None):
        data = self._get_json_raw(path, params)
        if data.get("status") not in ("success", "ok"):
            raise VmError(f"{path}: {data.get('error') or data}")
        return data.get("data")

    def _urllib(self, method, path, params=None):
        query = urllib.parse.urlencode(params or {}, doseq=True)
        url = self.base_url + path
        data = None
        if method == "POST":
            data = query.encode()
        elif query:
            url += "?" + query
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if data is not None else {}
        if self.db.get("DB_TOKEN"):
            headers["Authorization"] = f"Bearer {self.db['DB_TOKEN']}"
        proxy = self.db.get("DB_USE_WEB_PROXY")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {}))
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with opener.open(req, timeout=HTTP_TIMEOUT_S) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as exc:
            raise VmError(f"{self.base_url} unreachable: {exc}")


def _parse_metrics(text):
    out = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.rpartition(" ")
        try:
            out[name] = out.get(name, 0.0) + float(value)
        except ValueError:
            continue
    return out

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

    def query(self, query, time=None):
        """Requête instantanée : liste de séries {metric, value} ; time (secondes Unix) : à cet instant passé."""
        params = {"query": query} if time is None else {"query": query, "time": time}
        return (self._get_json("/api/v1/query", params) or {}).get("result", [])

    def query_range(self, query, start, end, step):
        """Requête PromQL/MetricsQL sur une plage : liste de séries {metric, values}."""
        data = self._get_json("/api/v1/query_range", {"query": query, "start": start, "end": end, "step": step})
        return (data or {}).get("result", [])

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

    # ------------------------------------------------------------------------------------------- renommage

    def rename_node(self, old, new, window_s=3600, max_import_bytes=1_000_000, since_s=None):
        """Déplace l'historique d'un client renommé : chaque série où il apparaît (émetteur, récepteur, hub) est
        exportée heure par heure, réécrite sous le nouveau nom et réimportée par lots d'au plus max_import_bytes (une
        série longue est découpée) : la mémoire de SYNTRAF et de VictoriaMetrics reste bornée (un import d'une journée
        entière a fait tomber un VictoriaMetrics limité à 256 Mio). Les anciennes séries sont supprimées à la fin,
        une fois tout réimporté."""
        for name in (old, new):
            if not SAFE_VALUE.match(name or ""):
                raise ValueError(f"invalid name '{name}'")
        matchers = [f'{{{METRIC_MATCH},CLIENT="{old}"}}', f'{{{METRIC_MATCH},SERVER="{old}"}}',
                    f'{{{METRIC_MATCH},HUBS=~"(.*, )?{re.escape(old)}(, .*)?"}}']
        m = re.search(r'-retentionPeriod="?([^"\s]+)"?', self._get_text("/flags"))
        hours = parse_retention(m.group(1) if m else "1") or 31 * 24
        end = int(self._now())
        start = end - int(hours * 3600) - 86400  # un jour de marge
        if since_s is not None:  # seconde passe : les mesures arrivées en retard sous l'ancien nom
            start = end - int(since_s)
        series = points = 0
        t = start
        while t < end:
            status, body = self._http("GET", "/api/v1/export",
                                      {"match[]": matchers, "start": t, "end": min(t + window_s, end) - 0.001})
            if status != 200:
                raise VmError(f"export answered HTTP {status}")
            batch, size = [], 0
            for line in body.splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                metric = rename_labels(item["metric"], old, new)
                series += 1
                values, stamps = item.get("values") or [], item.get("timestamps") or []
                points += len(values)
                per_chunk = max(1, int(len(values) * max_import_bytes / max(len(line), 1)))
                for i in range(0, max(len(values), 1), per_chunk):
                    text = json.dumps({"metric": metric, "values": values[i:i + per_chunk],
                                       "timestamps": stamps[i:i + per_chunk]})
                    if batch and size + len(text) > max_import_bytes:
                        self._import(batch)
                        batch, size = [], 0
                    batch.append(text)
                    size += len(text) + 1
            if batch:
                self._import(batch)
            t += window_s
        status, _ = self._http("POST", "/api/v1/admin/tsdb/delete_series", {"match[]": matchers})
        if status not in (200, 204):
            raise VmError(f"delete_series answered HTTP {status}")
        return {"old": old, "new": new, "series": series, "points": points}

    def _import(self, lines):
        status, _ = self._http("POST", "/api/v1/import", None, body="\n".join(lines) + "\n")
        if status not in (200, 204):
            raise VmError(f"import answered HTTP {status}")

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

    def _urllib(self, method, path, params=None, body=None):
        query = urllib.parse.urlencode(params or {}, doseq=True)
        url = self.base_url + path
        data = None
        if body is not None:  # corps brut (import) : les paramètres vont dans l'URL
            data = body.encode("utf-8")
            url += ("?" + query) if query else ""
        elif method == "POST":
            data = query.encode()
        elif query:
            url += "?" + query
        headers = {}
        if data is not None:
            headers["Content-Type"] = "application/json" if body is not None else "application/x-www-form-urlencoded"
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


def rename_labels(metric, old, new):
    """Étiquettes d'une série avec old remplacé par new : valeurs égales, segments d'un UID de flux
    (A__TO__B__ON__DSCP0), éléments de la liste des hubs (« H1, H2 »)."""
    out = dict(metric)
    for key, value in metric.items():
        if key == "__name__" or not isinstance(value, str):
            continue
        if value == old:
            out[key] = new
        elif key == "UID":
            out[key] = "".join(new if part == old else part for part in re.split(r"(__TO__|__ON__)", value))
        elif key == "HUBS":
            out[key] = ", ".join(new if hub == old else hub for hub in value.split(", "))
    return out


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

"""Déploie dans un Grafana (API HTTP, jeton d'un compte de service avec le rôle Admin : créer une source de données
l'exige ; Editor ne suffit pas) la source de données
VictoriaMetrics de SYNTRAF (uid « syntraf-vm », celle qu'utilisent les tableaux de bord) et les tableaux de bord
(lib/st_grafana_dashboards.py), dans un dossier. Idempotent : un nouveau déploiement met à jour en place.

Réglages (section [GRAFANA] de la configuration, page Grafana de l'interface) : URL, TOKEN (secret), FOLDER,
DATASOURCE_URL (adresse de VictoriaMetrics vue par Grafana ; par défaut celle de la première base VictoriaMetrics),
VERIFY_TLS. Bibliothèque standard uniquement.
"""
import json
import re
import ssl
import urllib.error
import urllib.request

DATASOURCE_UID = "syntraf-vm"
DATASOURCE_NAME = "SYNTRAF VictoriaMetrics"
DEFAULT_FOLDER = "SYNTRAF"


class GrafanaError(Exception):
    pass


def _urllib(verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE

    def call(method, url, headers, body):
        req = urllib.request.Request(url, data=body.encode() if body else None, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"null")
            except ValueError:
                return exc.code, {"message": exc.reason}
    return call


def default_datasource_url(config):
    for db in (config or {}).get("DATABASE", []) or []:
        if str(db.get("DB_ENGINE", "")).lower() == "victoriametrics":
            scheme = "https" if db.get("DB_SERVER_USE_SSL") else "http"
            return f"{scheme}://{db.get('DB_SERVER')}:{db.get('DB_PORT')}"
    return ""


def folder_uid(name):
    return re.sub(r"[^a-z0-9_-]", "-", (name or DEFAULT_FOLDER).lower())[:40] or "syntraf"


class Client:
    def __init__(self, settings, http=None):
        self.base = str(settings.get("URL") or "").rstrip("/")
        if not re.match(r"^https?://", self.base):
            raise GrafanaError("Grafana URL missing or not http(s)")
        self.headers = {"Authorization": f"Bearer {settings.get('TOKEN') or ''}", "Content-Type": "application/json",
                        "Accept": "application/json"}
        self.http = http or _urllib(settings.get("VERIFY_TLS", True) is not False)

    def call(self, method, path, body=None):
        try:
            status, data = self.http(method, f"{self.base}/{path}", self.headers,
                                     json.dumps(body) if body is not None else None)
        except OSError as exc:
            raise GrafanaError(f"Grafana unreachable: {exc}")
        if status in (401, 403):
            raise GrafanaError("Grafana refused the token or its role (a service account with the Admin role is needed to manage the data source)")
        return status, data


def test(settings, http=None):
    c = Client(settings, http)
    status, health = c.call("GET", "api/health")
    if status != 200:
        raise GrafanaError(f"Grafana answered HTTP {status}")
    status, _ = c.call("GET", "api/search?limit=1")  # le jeton est-il accepté ?
    if status != 200:
        raise GrafanaError(f"Grafana answered HTTP {status} to an authenticated request")
    return {"version": (health or {}).get("version", "?")}


def deploy(settings, http=None, dry_run=False, dashboards=None):
    """{datasource, folder, dashboards: [{uid, title, status}]} ; dry_run : rien n'est écrit."""
    c = Client(settings, http)
    test(settings, http=c.http)
    result = {}
    ds_url = str(settings.get("DATASOURCE_URL") or "").strip()
    if not ds_url:
        raise GrafanaError("Address of VictoriaMetrics as seen by Grafana missing")
    datasource = {"uid": DATASOURCE_UID, "name": DATASOURCE_NAME, "type": "prometheus", "access": "proxy",
                  "url": ds_url, "isDefault": False, "jsonData": {"timeInterval": "1s", "httpMethod": "POST"}}
    status, _ = c.call("GET", f"api/datasources/uid/{DATASOURCE_UID}")
    exists = status == 200
    if dry_run:
        result["datasource"] = "would be updated" if exists else "would be created"
    else:
        status, data = (c.call("PUT", f"api/datasources/uid/{DATASOURCE_UID}", datasource) if exists
                        else c.call("POST", "api/datasources", datasource))
        if status != 200:
            raise GrafanaError(f"Data source not saved: {(data or {}).get('message', status)}")
        result["datasource"] = "updated" if exists else "created"
    fname = str(settings.get("FOLDER") or DEFAULT_FOLDER)
    fuid = folder_uid(fname)
    status, _ = c.call("GET", f"api/folders/{fuid}")
    if status == 200:
        result["folder"] = "exists"
    elif dry_run:
        result["folder"] = "would be created"
    else:
        status, data = c.call("POST", "api/folders", {"uid": fuid, "title": fname})
        if status != 200:
            raise GrafanaError(f"Folder not created: {(data or {}).get('message', status)}")
        result["folder"] = "created"
    if dashboards is None:
        from lib import st_grafana_dashboards
        dashboards = [d for _, d in st_grafana_dashboards.all_dashboards()]
    out = []
    for d in dashboards:
        d = dict(d, id=None, tags=[t for t in d.get("tags", []) if t != "lab"])
        if dry_run:
            out.append({"uid": d["uid"], "title": d["title"], "status": "would be deployed"})
            continue
        status, data = c.call("POST", "api/dashboards/db", {"dashboard": d, "folderUid": fuid, "overwrite": True,
                                                            "message": "Deployed by SYNTRAF"})
        out.append({"uid": d["uid"], "title": d["title"],
                    "status": "deployed" if status == 200 else f"failed: {(data or {}).get('message', status)}",
                    "url": f"{c.base}{(data or {}).get('url', '')}" if status == 200 else ""})
    result["dashboards"] = out
    return result

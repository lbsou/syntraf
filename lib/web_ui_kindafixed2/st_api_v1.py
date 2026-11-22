"""API REST v1 de la webui (/api/v1/...), plus /healthz et /metrics pour la supervision.

Erreurs : {"error": {"message": "...", "fields": {"CHAMP": "message"}}} avec le code HTTP correspondant.
Toute requête qui modifie la configuration accepte ?dry_run=1 : rien n'est écrit, la réponse donne le diff du
fichier et les clients qui se reconnecteraient.
"""
import collections
import datetime as dt
import json
import os
import re
import time

from flask import Blueprint, Response, current_app, g, jsonify, request, send_file

from lib import st_config_store as store
from lib import st_mesh_group_ops as ops
from lib import st_log_search
from lib.web_ui_kindafixed2 import st_status
from lib.st_vm_admin import VmAdmin, VmError

try:
    from gevent import sleep as _sleep  # la webui tourne dans un WSGIServer gevent : ne pas bloquer son hub
except ImportError:  # pragma: no cover
    _sleep = time.sleep

st_api_v1 = Blueprint("st_api_v1", __name__, url_prefix="/api/v1")
st_ops_bp = Blueprint("st_ops_bp", __name__)

EVENTS_PERIOD_SECONDS = 3
EVENTS_STREAM_SECONDS = 300  # le navigateur rouvre le flux tout seul (EventSource)


def _state():
    return current_app.config


def _actor():
    return request.remote_addr or "unknown"


def _dry_run():
    return request.args.get("dry_run", "").lower() in ("1", "true", "yes")


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else request.values.to_dict()


def _error(status, message, fields=None):
    return jsonify({"error": {"message": message, "fields": fields or {}}}), status


@st_api_v1.before_request
def _large_change_confirmation():
    # ?confirm=1 : l'utilisateur a confirmé un changement qui franchit le seuil d'alerte de capacité
    g._st_confirm_token = ops.CONFIRMED.set(request.args.get("confirm") == "1")


@st_api_v1.teardown_request
def _large_change_confirmation_reset(_exc):
    token = g.pop("_st_confirm_token", None)
    if token is not None:
        ops.CONFIRMED.reset(token)


@st_api_v1.errorhandler(ops.OpError)
def _op_error(exc):
    return _error(exc.status, exc.message, exc.fields)


@st_api_v1.errorhandler(404)
def _not_found(_exc):
    return _error(404, "Not found")


@st_api_v1.errorhandler(405)
def _not_allowed(_exc):
    return _error(405, "Method not allowed")


# ------------------------------------------------------------------------------------------------------ mesh groups

@st_api_v1.get("/mesh-groups")
def list_mesh_groups():
    return jsonify(ops.list_groups(_state()))


@st_api_v1.get("/mesh-groups/<uid>")
def get_mesh_group(uid):
    return jsonify(ops.get_group(_state(), uid))


@st_api_v1.post("/mesh-groups")
def create_mesh_group():
    result = ops.create(_state(), _body(), _actor(), _dry_run())
    return jsonify(result), (200 if result["dry_run"] else 201)


@st_api_v1.put("/mesh-groups/<uid>")
def update_mesh_group(uid):
    return jsonify(ops.update(_state(), uid, _body(), _actor(), _dry_run()))


@st_api_v1.patch("/mesh-groups/<uid>")
def patch_mesh_group(uid):
    body = _body()
    disabled = body.get("DISABLED")
    if isinstance(disabled, str):
        disabled = {"true": True, "false": False}.get(disabled.lower())
    if not isinstance(disabled, bool):
        return _error(400, "Only DISABLED (true or false) can be patched", {"DISABLED": "Must be true or false"})
    return jsonify(ops.set_disabled(_state(), uid, disabled, _actor(), _dry_run()))


@st_api_v1.delete("/mesh-groups/<uid>")
def delete_mesh_group(uid):
    return jsonify(ops.delete(_state(), uid, _actor(), _dry_run()))


@st_api_v1.post("/mesh-groups/<uid>/duplicate")
def duplicate_mesh_group(uid):
    result = ops.duplicate(_state(), uid, _actor(), _dry_run())
    return jsonify(result), (200 if result["dry_run"] else 201)


# ------------------------------------------------------------------------------- clients et bases (configuration)

def _created(result):
    return jsonify(result), (200 if result["dry_run"] else 201)


@st_api_v1.get("/config/clients")
def list_client_configs():
    return jsonify(ops.list_clients(_state()))


@st_api_v1.get("/config/clients/<uid>")
def get_client_config(uid):
    row = next((c for c in ops.list_clients(_state()) if c["UID"] == uid), None)
    return jsonify(row) if row else _error(404, f"Client '{uid}' not found")


@st_api_v1.post("/config/clients")
def create_client_config():
    return _created(ops.create_client(_state(), _body(), _actor(), _dry_run()))


@st_api_v1.put("/config/clients/<uid>")
def update_client_config(uid):
    return jsonify(ops.update_client(_state(), uid, _body(), _actor(), _dry_run()))


@st_api_v1.delete("/config/clients/<uid>")
def delete_client_config(uid):
    return jsonify(ops.delete_client(_state(), uid, _actor(), _dry_run()))


@st_api_v1.get("/updates")
def updates():
    return jsonify(ops.updates_overview(_state()))


@st_api_v1.post("/updates")
def request_updates():
    body = _body()
    clients = body.get("CLIENTS") or []
    if isinstance(clients, str):
        clients = [c for c in clients.split(",") if c]
    if not clients:
        return _error(400, "Choose at least one client", {"CLIENTS": "Choose at least one client"})
    return jsonify(ops.request_updates(_state(), clients, _actor(), force=str(body.get("FORCE", "")).lower() in
                                       ("1", "true", "yes")))


@st_api_v1.get("/clients/pending")
def pending_clients():
    return jsonify(ops.list_pending(_state()))


@st_api_v1.post("/clients/pending/<uid>/approve")
def approve_pending_client(uid):
    return _created(ops.approve_client(_state(), uid, _body(), _actor(), _dry_run()))


@st_api_v1.post("/clients/pending/<uid>/reject")
def reject_pending_client(uid):
    return jsonify(ops.reject_client(_state(), uid, _actor()))


@st_api_v1.delete("/clients/rejected/<uid>")
def forgive_rejected_client(uid):
    return jsonify(ops.forgive_client(_state(), uid, _actor()))


@st_api_v1.post("/config/clients/<uid>/secure")
def secure_client(uid):
    return jsonify(ops.secure_client(_state(), uid, _actor(), _dry_run()))


@st_api_v1.post("/config/clients/<uid>/rotate-token")
def rotate_client_token(uid):
    return jsonify(ops.rotate_client_token(_state(), uid, _actor(), _dry_run()))


@st_api_v1.get("/config/server")
def get_server_config():
    return jsonify(ops.get_server(_state()))


@st_api_v1.put("/config/server")
def update_server_config():
    return jsonify(ops.update_server(_state(), _body(), _actor(), _dry_run()))


@st_api_v1.get("/config/tokens")
def list_tokens():
    return jsonify(ops.list_tokens(_state()))


@st_api_v1.post("/config/tokens")
def create_token():
    return _created(ops.create_token(_state(), _body(), _actor(), _dry_run()))


@st_api_v1.post("/config/tokens/<name>/reveal")
def reveal_token(name):
    """POST : chaque consultation de la valeur d'un jeton est inscrite au journal d'audit."""
    return jsonify({"name": name, "token": ops.reveal_token(_state(), name, _actor())})


@st_api_v1.delete("/config/tokens/<name>")
def delete_token(name):
    return jsonify(ops.delete_token(_state(), name, _actor(), _dry_run()))


@st_api_v1.get("/config/profiles")
def list_profile_configs():
    return jsonify(ops.list_profiles(_state()))


@st_api_v1.get("/config/profiles/<uid>")
def get_profile_config(uid):
    row = next((p for p in ops.list_profiles(_state()) if p["UID"] == uid), None)
    return jsonify(row) if row else _error(404, f"Profile '{uid}' not found")


@st_api_v1.post("/config/profiles")
def create_profile_config():
    return _created(ops.create_profile(_state(), _body(), _actor(), _dry_run()))


@st_api_v1.put("/config/profiles/<uid>")
def update_profile_config(uid):
    return jsonify(ops.update_profile(_state(), uid, _body(), _actor(), _dry_run()))


@st_api_v1.delete("/config/profiles/<uid>")
def delete_profile_config(uid):
    return jsonify(ops.delete_profile(_state(), uid, _actor(), _dry_run()))


@st_api_v1.get("/config/databases")
def list_database_configs():
    return jsonify(ops.list_databases(_state()))


@st_api_v1.get("/config/databases/<uid>")
def get_database_config(uid):
    row = next((d for d in ops.list_databases(_state()) if d["DB_UID"] == uid), None)
    return jsonify(row) if row else _error(404, f"Database '{uid}' not found")


@st_api_v1.post("/config/databases")
def create_database_config():
    return _created(ops.create_database(_state(), _body(), _actor(), _dry_run()))


@st_api_v1.post("/config/databases/test")
def test_database_config():
    return jsonify(ops.test_database(_state(), _body()))


@st_api_v1.put("/config/databases/<uid>")
def update_database_config(uid):
    return jsonify(ops.update_database(_state(), uid, _body(), _actor(), _dry_run()))


@st_api_v1.delete("/config/databases/<uid>")
def delete_database_config(uid):
    return jsonify(ops.delete_database(_state(), uid, _actor(), _dry_run()))


# ------------------------------------------------------------------------------- données dans VictoriaMetrics

def _vm_admin(uid):
    db = next((d for d in ops.read_disk(_state()).get("DATABASE", []) if d["DB_UID"] == uid), None)
    if db is None:
        raise ops.OpError(404, f"Database '{uid}' not found")
    if db.get("DB_ENGINE", "").upper() != "VICTORIAMETRICS":
        raise ops.OpError(409, f"Data management is available for VictoriaMetrics only ('{uid}' is {db.get('DB_ENGINE')})")
    return _state().get("vm_admin_factory", VmAdmin)(db)


def _vm_call(fn):
    try:
        return fn()
    except ValueError as exc:
        raise ops.OpError(400, str(exc))
    except VmError as exc:
        raise ops.OpError(502, f"VictoriaMetrics: {exc}")


@st_api_v1.get("/data")
def data_status():
    """Par base : rétention réelle et cible, espace disque, plus ancienne donnée, instantanés, données orphelines."""
    cfg = ops.read_disk(_state())
    clients = {c["UID"] for c in cfg.get("SERVER_CLIENT", [])}
    groups = {g["UID"] for g in cfg.get("MESH_GROUP", [])}
    rows = []
    for db in cfg.get("DATABASE", []):
        if db.get("DB_ENGINE", "").upper() != "VICTORIAMETRICS":
            rows.append({"uid": db["DB_UID"], "engine": db.get("DB_ENGINE"), "supported": False})
            continue
        admin = _state().get("vm_admin_factory", VmAdmin)(db)
        try:
            row = dict(admin.status(), engine=db["DB_ENGINE"], supported=True, snapshots=admin.snapshots(),
                       orphans=admin.orphans(clients, groups))
        except VmError as exc:
            row = {"uid": db["DB_UID"], "engine": db["DB_ENGINE"], "supported": True, "error": str(exc)}
        rows.append(row)
    return jsonify(rows)


@st_api_v1.post("/data/<uid>/snapshots")
def data_create_snapshot(uid):
    name = _vm_call(lambda: _vm_admin(uid).create_snapshot())
    store.log_event(_state()["config_file_path"], _actor(), "CREATE_SNAPSHOT", f"Snapshot '{name}' created on '{uid}'")
    return jsonify({"snapshot": name}), 201


@st_api_v1.delete("/data/<uid>/snapshots/<name>")
def data_delete_snapshot(uid, name):
    _vm_call(lambda: _vm_admin(uid).delete_snapshot(name))
    store.log_event(_state()["config_file_path"], _actor(), "DELETE_SNAPSHOT", f"Snapshot '{name}' deleted on '{uid}'")
    return jsonify({"snapshot": name})


@st_api_v1.post("/data/<uid>/purge")
def data_purge(uid):
    """Supprime les séries d'un client ou d'un mesh group ({"kind": "client"|"mesh_group", "value": nom})."""
    body = _body()
    kind, value = str(body.get("kind", "")), str(body.get("value", ""))
    result = _vm_call(lambda: _vm_admin(uid).purge(kind, value, dry_run=_dry_run()))
    if not result["dry_run"]:
        store.log_event(_state()["config_file_path"], _actor(), "PURGE_DATA",
                        f"{result['series']} series of {kind.replace('_', ' ')} '{value}' deleted from '{uid}'")
    return jsonify(result)


# ------------------------------------------------------------------------------------------- état et supervision

@st_api_v1.get("/status")
def status():
    return jsonify(st_status.snapshot(_state(), refresh_databases=request.args.get("refresh") == "1"))


@st_api_v1.get("/clients")
def clients():
    return jsonify(st_status.clients(_state()))


@st_api_v1.get("/databases")
def databases():
    return jsonify(st_status.databases(_state(), refresh=request.args.get("refresh") == "1"))


@st_api_v1.get("/events")
def events():
    """Server-Sent Events : un instantané de /status toutes les EVENTS_PERIOD_SECONDS secondes."""
    app = current_app._get_current_object()
    max_events = request.args.get("max", type=int)

    def stream():
        yield f"retry: {EVENTS_PERIOD_SECONDS * 1000}\n\n"
        sent, deadline = 0, time.monotonic() + EVENTS_STREAM_SECONDS
        while time.monotonic() < deadline and (max_events is None or sent < max_events):
            with app.app_context():
                payload = json.dumps(st_status.snapshot(app.config))
            yield f"event: status\ndata: {payload}\n\n"
            sent += 1
            if max_events is not None and sent >= max_events:
                break
            _sleep(EVENTS_PERIOD_SECONDS)

    return Response(stream(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@st_ops_bp.get("/healthz")
def healthz():
    code, body = st_status.health(_state())
    return jsonify(body), code


@st_ops_bp.get("/metrics")
def metrics():
    return Response(st_status.metrics(_state()), mimetype="text/plain; version=0.0.4")


# ------------------------------------------------------------------------------------------ audit et versions

@st_api_v1.get("/audit")
def audit():
    limit = min(max(request.args.get("limit", 100, type=int), 1), 1000)
    return jsonify(store.audit_entries(_state()["config_file_path"], limit))


@st_api_v1.get("/config/versions")
def config_versions():
    return jsonify(store.versions(_state()["config_file_path"]))


@st_api_v1.get("/config/versions/<version>")
def config_version(version):
    try:
        text = store.read_version(_state()["config_file_path"], version)
    except KeyError:
        return _error(404, f"Version '{version}' not found")
    return Response(store.redact(text), mimetype="text/plain")


@st_api_v1.get("/config/versions/<version>/diff")
def config_version_diff(version):
    """Ce que la restauration de cette version changerait dans le fichier actuel."""
    path = _state()["config_file_path"]
    try:
        text = store.read_version(path, version)
    except KeyError:
        return _error(404, f"Version '{version}' not found")
    with open(path, encoding="utf-8") as f:
        current = f.read()
    return Response(store.redacted_diff(current, text, "current", version), mimetype="text/plain")


@st_api_v1.post("/config/versions/<version>/restore")
def config_restore(version):
    return jsonify(ops.restore(_state(), version, _actor(), _dry_run()))


# ------------------------------------------------------------------------------------------------------- journaux

def log_files():
    logdir = _state()["config"].get("GLOBAL", {}).get("LOGDIR", "")
    if not logdir or not os.path.isdir(logdir):
        return logdir, []
    return logdir, sorted(f for f in os.listdir(logdir) if os.path.isfile(os.path.join(logdir, f)))


@st_api_v1.get("/config/logging")
def get_logging_config():
    return jsonify(ops.get_logging(_state()))


@st_api_v1.put("/config/logging")
def update_logging_config():
    return jsonify(ops.update_logging(_state(), _body(), _actor(), _dry_run()))


@st_api_v1.get("/logs/nodes")
def log_nodes():
    logdir, _ = log_files()
    return jsonify({"nodes": st_log_search.nodes(logdir) if logdir else [], "types": list(st_log_search.TYPES),
                    "levels": list(st_log_search.LEVELS)})


_RELATIVE = re.compile(r"^(\d+)([mhd])$")


def _when(value):
    """« 15m », « 6h », « 2d » (avant maintenant) ou une date ISO ; None si vide."""
    value = (value or "").strip()
    if not value:
        return None
    m = _RELATIVE.match(value)
    if m:
        seconds = int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]
        return dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=seconds)
    try:
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return t if t.tzinfo else t.astimezone()
    except ValueError:
        raise ops.OpError(400, f"Invalid time '{value}' (use 15m, 6h, 2d or an ISO date)")


@st_api_v1.get("/logs/search")
def log_search():
    """Journaux du serveur et des clients, filtrés : nodes, types (séparés par des virgules), level (minimum),
    q (mots, "expression", -exclu), since / until (15m, 6h, 2d ou ISO), limit ; format=text pour l'export."""
    logdir, _ = log_files()
    if not logdir:
        return jsonify([])
    split = lambda name: [x for x in request.args.get(name, "").split(",") if x]  # noqa: E731
    entries = st_log_search.search(logdir, nodes=split("nodes") or None, types=split("types") or None,
                                   level=request.args.get("level", ""), query=request.args.get("q", ""),
                                   since=_when(request.args.get("since")), until=_when(request.args.get("until")),
                                   limit=min(max(request.args.get("limit", 1000, type=int), 1), 20000))
    if request.args.get("format") == "text":
        text = "".join(f"{e['time']} [{e['node']}] {e['level']} {e['module']} ({e['where']}) - {e['message']}\n{e['detail']}"
                       for e in reversed(entries))
        return Response(text, mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=syntraf-logs.txt"})
    return jsonify(entries)


@st_api_v1.get("/logs")
def logs():
    logdir, names = log_files()
    return jsonify([{"name": n, "size": os.path.getsize(os.path.join(logdir, n)),
                     "modified": time.strftime("%Y-%m-%d %H:%M:%S",
                                               time.localtime(os.path.getmtime(os.path.join(logdir, n))))}
                    for n in names])


@st_api_v1.get("/logs/<name>")
def log_file(name):
    logdir, names = log_files()
    if name not in names:
        return _error(404, f"Unknown log file '{name}'")
    path = os.path.join(logdir, name)
    if request.args.get("download") == "1":
        return send_file(path, mimetype="text/plain", as_attachment=True, download_name=name)
    lines = min(max(request.args.get("lines", 500, type=int), 1), 20000)
    level, query = request.args.get("level", ""), request.args.get("q", "")
    with open(path, encoding="utf-8", errors="replace") as f:
        if level or query:
            kept = collections.deque(st_status.filter_log_lines(f, level, query), maxlen=lines)
        else:
            kept = collections.deque(f, maxlen=lines)
    return Response("".join(kept), mimetype="text/plain")


# -------------------------------------------------------------------------------------------------------- OpenAPI

def _op(summary, body=False, dry_run=False, params=()):
    o = {"summary": summary, "responses": {"200": {"description": "OK"}, "4XX": {"$ref": "#/components/responses/Error"}}}
    p = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}} for n in params]
    if dry_run:
        p.append({"name": "dry_run", "in": "query", "schema": {"type": "boolean"},
                  "description": "Preview only: nothing is written, the diff and affected clients are returned"})
    if p:
        o["parameters"] = p
    if body:
        o["requestBody"] = {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/MeshGroupInput"}}}}
    return o


OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "SYNTRAF server API", "version": "1"},
    "paths": {
        "/api/v1/mesh-groups": {"get": _op("List mesh groups"), "post": _op("Create a mesh group", True, True)},
        "/api/v1/mesh-groups/{uid}": {
            "get": _op("Get a mesh group", params=("uid",)),
            "put": _op("Update a mesh group", True, True, ("uid",)),
            "patch": _op("Enable or disable a mesh group ({\"DISABLED\": true|false})", False, True, ("uid",)),
            "delete": _op("Delete an unused mesh group", False, True, ("uid",))},
        "/api/v1/mesh-groups/{uid}/duplicate": {"post": _op("Duplicate a mesh group", False, True, ("uid",))},
        "/api/v1/config/clients": {"get": _op("Declared clients (SERVER_CLIENT)"),
                                   "post": _op("Declare a client", False, True)},
        "/api/v1/config/clients/{uid}": {"get": _op("Get a client declaration", params=("uid",)),
                                         "put": _op("Update a client declaration", False, True, ("uid",)),
                                         "delete": _op("Remove a client", False, True, ("uid",))},
        "/api/v1/updates": {"get": _op("This server's release and where each client stands"),
                            "post": _op("Send this server's release to clients ({CLIENTS: [...], FORCE})")},
        "/api/v1/clients/pending": {"get": _op("Clients waiting for approval, and rejected clients")},
        "/api/v1/clients/pending/{uid}/approve": {"post": _op("Approve a pending client ({MESH_GROUP_UID_LIST, "
                                                              "IP_MODE: static|dynamic}): its key is pinned, a token "
                                                              "of its own is issued", False, True, ("uid",))},
        "/api/v1/clients/pending/{uid}/reject": {"post": _op("Reject a pending client", params=("uid",))},
        "/api/v1/clients/rejected/{uid}": {"delete": _op("Allow a rejected client to ask again", params=("uid",))},
        "/api/v1/config/clients/{uid}/secure": {"post": _op("Pin the key of a connected client and issue its own "
                                                            "token", False, True, ("uid",))},
        "/api/v1/config/clients/{uid}/rotate-token": {"post": _op("Issue a new token to a client (sent to it if "
                                                                  "connected)", False, True, ("uid",))},
        "/api/v1/config/server": {"get": _op("Server settings (tokens excluded) and the values in service"),
                                  "put": _op("Update server settings; the response lists those that need a restart",
                                             False, True)},
        "/api/v1/config/tokens": {"get": _op("Shared token names (values are never listed)"),
                                  "post": _op("Create a random token ({NAME}); its value is returned once", False, True)},
        "/api/v1/config/tokens/{name}": {"delete": _op("Revoke a token", False, True, ("name",))},
        "/api/v1/config/tokens/{name}/reveal": {"post": _op("Value of a token (audited)", params=("name",))},
        "/api/v1/config/profiles": {"get": _op("iperf3 profiles and the mesh groups using them"),
                                    "post": _op("Create a profile", False, True)},
        "/api/v1/config/profiles/{uid}": {"get": _op("Get a profile", params=("uid",)),
                                          "put": _op("Update a profile (applied live to its mesh groups)",
                                                     False, True, ("uid",)),
                                          "delete": _op("Delete an unused profile", False, True, ("uid",))},
        "/api/v1/config/databases": {"get": _op("Declared databases (tokens are never returned)"),
                                     "post": _op("Declare a database", False, True)},
        "/api/v1/config/databases/test": {"post": _op("Test database parameters without saving them")},
        "/api/v1/config/databases/{uid}": {"get": _op("Get a database declaration", params=("uid",)),
                                           "put": _op("Update a database (empty DB_TOKEN keeps the current one)",
                                                      False, True, ("uid",)),
                                           "delete": _op("Remove a database", False, True, ("uid",))},
        "/api/v1/data": {"get": _op("Per database: actual and target retention, disk usage, oldest data, snapshots, orphan data")},
        "/api/v1/data/{uid}/snapshots": {"post": _op("Create a VictoriaMetrics snapshot", params=("uid",))},
        "/api/v1/data/{uid}/snapshots/{name}": {"delete": _op("Delete a snapshot", params=("uid", "name"))},
        "/api/v1/data/{uid}/purge": {"post": _op("Delete the series of a client or mesh group ({kind, value})",
                                                 False, True, ("uid",))},
        "/api/v1/status": {"get": _op("Server status snapshot (clients, databases, threads, queue)")},
        "/api/v1/events": {"get": _op("Status snapshots as Server-Sent Events")},
        "/api/v1/clients": {"get": _op("Clients and their state")},
        "/api/v1/databases": {"get": _op("Databases and their state (?refresh=1 to check now)")},
        "/api/v1/audit": {"get": _op("Configuration changes, newest first (?limit=)")},
        "/api/v1/config/versions": {"get": _op("Saved versions of the configuration file")},
        "/api/v1/config/versions/{version}": {"get": _op("Content of a saved version", params=("version",))},
        "/api/v1/config/versions/{version}/diff": {"get": _op("Diff between the current file and a version",
                                                              params=("version",))},
        "/api/v1/config/versions/{version}/restore": {"post": _op("Restore a version", False, True, ("version",))},
        "/api/v1/config/logging": {"get": _op("Logging settings (levels, file size and count, retention in days)"),
                                   "put": _op("Update logging settings", False, True)},
        "/api/v1/logs/nodes": {"get": _op("Nodes with logs (server, clients), log types and levels")},
        "/api/v1/logs/search": {"get": _op("Search the server and client logs (nodes, types, level, q, since, until, "
                                           "limit; format=text to export)")},
        "/api/v1/logs": {"get": _op("Log files")},
        "/api/v1/logs/{name}": {"get": _op("Tail of a log file (?lines=&level=&q=, ?download=1)", params=("name",))},
        "/healthz": {"get": _op("Health check: 200 ok, 503 degraded")},
        "/metrics": {"get": _op("Prometheus metrics")},
    },
    "components": {
        "schemas": {"MeshGroupInput": {"type": "object", "required": ["BANDWIDTH", "DSCP", "PACKET_SIZE", "INTERVAL"],
                                       "properties": {"UID": {"type": "string", "description": "Create only"},
                                                      "DESCRIPTION": {"type": "string"},
                                                      "BANDWIDTH": {"type": "string", "example": "200K"},
                                                      "DSCP": {"type": "string", "example": "0"},
                                                      "PACKET_SIZE": {"type": "string", "example": "218"},
                                                      "INTERVAL": {"type": "string", "example": "1"}}}},
        "responses": {"Error": {"description": "Error", "content": {"application/json": {"schema": {
            "type": "object", "properties": {"error": {"type": "object", "properties": {
                "message": {"type": "string"}, "fields": {"type": "object"}}}}}}}}},
    },
}


@st_api_v1.get("/openapi.json")
def openapi():
    return jsonify(OPENAPI)

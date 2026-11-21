"""API REST v1 de la webui (/api/v1/...), plus /healthz et /metrics pour la supervision.

Erreurs : {"error": {"message": "...", "fields": {"CHAMP": "message"}}} avec le code HTTP correspondant.
Toute requête qui modifie la configuration accepte ?dry_run=1 : rien n'est écrit, la réponse donne le diff du
fichier et les clients qui se reconnecteraient.
"""
import collections
import json
import os
import time

from flask import Blueprint, Response, current_app, jsonify, request, send_file

from lib import st_config_store as store
from lib import st_mesh_group_ops as ops
from lib.web_ui_kindafixed2 import st_status

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

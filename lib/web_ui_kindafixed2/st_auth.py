"""Authentification de l'interface web et de l'API REST.

- Comptes administrateurs (mot de passe haché scrypt) et jetons d'API (pour les scripts, Prometheus, Grafana),
  dans <config>.access.json (permissions 0600). Un jeton n'est montré qu'à sa création ; seule son empreinte
  SHA-256 est gardée.
- Tout est protégé, sauf /healthz, /login et les fichiers statiques : session (navigateur) ou
  « Authorization: Bearer <jeton> » (API).
- CSRF : avec une session, une écriture (POST, PUT, PATCH, DELETE) exige l'en-tête X-Requested-With: syntraf,
  qu'un autre site ne peut pas ajouter sans pré-vol CORS (refusé : aucun en-tête CORS), et une origine
  identique quand le navigateur l'indique. Un jeton Bearer n'est pas envoyé automatiquement : pas de CSRF.
- Échecs de connexion limités par adresse ; cookie de session HttpOnly, SameSite=Strict (Secure en HTTPS) ;
  en-têtes de sécurité sur chaque réponse.
- Premier démarrage : un compte « admin » est créé. Son mot de passe vient de SYNTRAF_ADMIN_PASSWORD
  (automatisation), sinon il est tiré au hasard et écrit dans <config>.initial_admin_password (0600), jamais
  dans le journal.
"""
import datetime as dt
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import threading
import time
from urllib.parse import urlparse

from flask import Blueprint, current_app, g, jsonify, redirect, render_template, request, session, url_for

log = logging.getLogger("syntraf." + __name__)

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,40}$")
MIN_PASSWORD = 12
MAX_FAILURES = 5
FAILURE_WINDOW_S = 300
BLOCK_S = 300
SESSION_HOURS = 12
CSRF_HEADER = ("X-Requested-With", "syntraf")
PUBLIC_PATHS = ("/healthz", "/login")
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'self'; form-action 'self'")


class AccessError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message, self.status = message, status


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return salt.hex(), digest.hex()


def _token_digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def write_private(path, text):
    """Écriture atomique, lisible par le seul propriétaire."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except Exception:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


class AccessStore:
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {}
        data.setdefault("users", {})
        data.setdefault("tokens", {})
        return data

    def _save(self, data):
        write_private(self.path, json.dumps(data, indent=1, sort_keys=True))

    # -------------------------------------------------------------------------------------------- comptes
    def users(self):
        return [{"NAME": n, "CREATED": u.get("created"), "PASSWORD_CHANGED": u.get("changed")}
                for n, u in sorted(self._load()["users"].items())]

    def has_users(self):
        return bool(self._load()["users"])

    def add_user(self, name, password):
        if not NAME_RE.match(name or ""):
            raise AccessError("2 to 40 characters: letters, digits, '_', '.' or '-'")
        self._check_password_rules(password)
        with self._lock:
            data = self._load()
            if name in data["users"]:
                raise AccessError(f"User '{name}' already exists", 409)
            salt, digest = _hash_password(password)
            data["users"][name] = {"salt": salt, "hash": digest, "created": _now(), "changed": _now(), "epoch": 1}
            self._save(data)

    def set_password(self, name, password):
        self._check_password_rules(password)
        with self._lock:
            data = self._load()
            user = data["users"].get(name)
            if user is None:
                raise AccessError(f"User '{name}' not found", 404)
            user["salt"], user["hash"] = _hash_password(password)
            user["changed"] = _now()
            user["epoch"] = user.get("epoch", 1) + 1  # les sessions ouvertes avec l'ancien mot de passe tombent
            self._save(data)

    def delete_user(self, name):
        with self._lock:
            data = self._load()
            if name not in data["users"]:
                raise AccessError(f"User '{name}' not found", 404)
            if len(data["users"]) == 1:
                raise AccessError("The last user cannot be deleted", 409)
            del data["users"][name]
            self._save(data)

    def check_password(self, name, password):
        user = self._load()["users"].get(name)
        if user is None:
            _hash_password(password or "", b"\0" * 16)  # même durée qu'un compte existant
            return False
        _, digest = _hash_password(password or "", bytes.fromhex(user["salt"]))
        return hmac.compare_digest(digest, user["hash"])

    def epoch(self, name):
        user = self._load()["users"].get(name)
        return None if user is None else user.get("epoch", 1)

    @staticmethod
    def _check_password_rules(password):
        if len(password or "") < MIN_PASSWORD:
            raise AccessError(f"At least {MIN_PASSWORD} characters")

    # -------------------------------------------------------------------------------------- jetons d'API
    def tokens(self):
        return [{"NAME": n, "CREATED": t.get("created"), "LAST_USED": t.get("last_used")}
                for n, t in sorted(self._load()["tokens"].items())]

    def create_token(self, name):
        if not NAME_RE.match(name or ""):
            raise AccessError("2 to 40 characters: letters, digits, '_', '.' or '-'")
        value = secrets.token_urlsafe(32)
        with self._lock:
            data = self._load()
            if name in data["tokens"]:
                raise AccessError(f"API token '{name}' already exists", 409)
            data["tokens"][name] = {"sha256": _token_digest(value), "created": _now(), "last_used": None}
            self._save(data)
        return value

    def revoke_token(self, name):
        with self._lock:
            data = self._load()
            if data["tokens"].pop(name, None) is None:
                raise AccessError(f"API token '{name}' not found", 404)
            self._save(data)

    def check_token(self, value):
        digest = _token_digest(value or "")
        for name, t in self._load()["tokens"].items():
            if hmac.compare_digest(digest, t["sha256"]):
                return name
        return None

    def touch_token(self, name):
        with self._lock:
            data = self._load()
            t = data["tokens"].get(name)
            if t is not None and (t.get("last_used") or "")[:13] != _now()[:13]:  # au plus une écriture par heure
                t["last_used"] = _now()
                self._save(data)


# ------------------------------------------------------------------------------------------- démarrage

def bootstrap(store, config_file_path):
    """Crée le compte « admin » s'il n'y a aucun compte ; renvoie le fichier du mot de passe tiré au hasard."""
    if store.has_users():
        return None
    password = os.environ.get("SYNTRAF_ADMIN_PASSWORD")
    if password:
        store.add_user("admin", password)
        log.warning("ADMIN ACCOUNT 'admin' CREATED WITH THE PASSWORD OF SYNTRAF_ADMIN_PASSWORD")
        return None
    password = secrets.token_urlsafe(18)
    store.add_user("admin", password)
    path = config_file_path + ".initial_admin_password"
    write_private(path, password + "\n")
    log.warning(f"ADMIN ACCOUNT 'admin' CREATED: ITS PASSWORD IS IN {path} (READABLE BY THIS ACCOUNT ONLY). "
                f"LOG IN, CHANGE IT ON THE SERVER PAGE, THEN DELETE THE FILE")
    return path


def secret_key(config_file_path):
    """Clé de signature des sessions, gardée d'un démarrage à l'autre (<config>.secret_key, 0600)."""
    path = config_file_path + ".secret_key"
    try:
        with open(path, encoding="utf-8") as f:
            key = f.read().strip()
        if len(key) >= 32:
            return key
    except FileNotFoundError:
        pass
    key = secrets.token_hex(32)
    write_private(path, key)
    return key


def store_of(app):
    return app.extensions["st_access"]


def actor():
    """Qui fait la requête, pour l'audit : « admin (10.0.0.5) », « token:grafana (10.0.0.9) »."""
    who = g.get("actor") or "anonymous"
    return f"{who} ({request.remote_addr or 'unknown'})"


# ------------------------------------------------------------------------------- échecs de connexion

class _Failures:
    def __init__(self):
        self._by_ip = {}
        self._lock = threading.Lock()

    def blocked(self, ip):
        with self._lock:
            entry = self._by_ip.get(ip)
            return bool(entry and entry.get("until", 0) > time.monotonic())

    def fail(self, ip):
        now = time.monotonic()
        with self._lock:
            entry = self._by_ip.setdefault(ip, {"times": []})
            entry["times"] = [t for t in entry["times"] if now - t < FAILURE_WINDOW_S] + [now]
            if len(entry["times"]) >= MAX_FAILURES:
                entry["until"] = now + BLOCK_S
                entry["times"] = []
            if len(self._by_ip) > 10_000:  # bornée : les plus anciennes adresses sont oubliées
                self._by_ip.pop(next(iter(self._by_ip)))

    def succeed(self, ip):
        with self._lock:
            self._by_ip.pop(ip, None)


# --------------------------------------------------------------------------------------- application

def _same_origin(value):
    if not value:
        return True
    parsed = urlparse(value)
    return parsed.netloc == request.host


def _wants_json():
    return request.path.startswith(("/api", "/metrics")) or request.accept_mimetypes.best == "application/json"


def _unauthorized():
    if _wants_json():
        r = jsonify({"error": {"message": "Authentication required", "fields": {}}})
        r.status_code = 401
        r.headers["WWW-Authenticate"] = 'Bearer realm="syntraf"'
        return r
    return redirect(url_for("st_auth.login", next=request.full_path if request.query_string else request.path))


def _allowed_scraper(address):
    """Collecteur autorisé à lire /metrics sans jeton (SERVER.METRICS_ALLOW) : la configuration en service."""
    import ipaddress
    from lib.st_mesh_group_ops import metrics_allow_networks
    allow = (current_app.config.get("config") or {}).get("SERVER", {}).get("METRICS_ALLOW")
    nets = metrics_allow_networks(allow) or []
    try:
        ip = ipaddress.ip_address(address or "")
    except ValueError:
        return False
    return any(ip in n for n in nets)


def _gate():
    path = request.path
    if path in PUBLIC_PATHS or path.startswith("/static/"):
        return None
    if path == "/metrics" and _allowed_scraper(request.remote_addr):
        g.actor = "scraper"
        return None
    store = store_of(current_app)
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        name = store.check_token(header[7:].strip())
        if name is None:
            return _unauthorized()
        g.actor = f"token:{name}"
        store.touch_token(name)
        return None
    user = session.get("user")
    if not user or store.epoch(user) != session.get("epoch"):
        session.clear()
        return _unauthorized()
    g.actor = user
    if request.method not in SAFE_METHODS:
        if request.headers.get(CSRF_HEADER[0]) != CSRF_HEADER[1] or not _same_origin(request.headers.get("Origin")):
            r = jsonify({"error": {"message": "Request refused: cross-site request", "fields": {}}})
            r.status_code = 403
            return r
    return None


def _headers(response):
    h = response.headers
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "same-origin")
    h.setdefault("Content-Security-Policy", CSP)
    if request.is_secure:
        h.setdefault("Strict-Transport-Security", "max-age=31536000")
    if request.path.startswith("/api"):
        h.setdefault("Cache-Control", "no-store")
    return response


st_auth_bp = Blueprint("st_auth", __name__)


@st_auth_bp.route("/login", methods=["GET", "POST"])
def login():
    failures = current_app.extensions["st_failures"]
    ip = request.remote_addr or "unknown"
    nxt = request.values.get("next", "")
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/home.html"  # pas de redirection vers un autre site
    error = None
    if request.method == "POST":
        if not _same_origin(request.headers.get("Origin")):
            return "Cross-site login refused", 403
        if failures.blocked(ip):
            return render_template("login.html", error="Too many failed attempts: try again in a few minutes.",
                                   next=nxt), 429
        store = store_of(current_app)
        name = request.form.get("username", "")
        if store.check_password(name, request.form.get("password", "")):
            failures.succeed(ip)
            session.clear()
            session.permanent = True
            session["user"], session["epoch"] = name, store.epoch(name)
            log.info(f"LOGIN OF '{name}' FROM {ip}")
            return redirect(nxt)
        failures.fail(ip)
        log.warning(f"FAILED LOGIN FOR '{re.sub(r'[^A-Za-z0-9_.-]', '?', name)[:40]}' FROM {ip}")
        if failures.blocked(ip):
            return render_template("login.html", error="Too many failed attempts: try again in a few minutes.",
                                   next=nxt), 429
        error = "Wrong user name or password."
    return render_template("login.html", error=error, next=nxt), (401 if error else 200)


@st_auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


def _api_error(exc):
    return jsonify({"error": {"message": exc.message, "fields": {}}}), exc.status


def _audit(action, summary):
    from lib import st_config_store
    st_config_store.log_event(current_app.config["config_file_path"], actor(), action, summary)


@st_auth_bp.get("/api/v1/auth/me")
def me():
    return jsonify({"actor": g.get("actor"), "user": session.get("user")})


@st_auth_bp.get("/api/v1/auth/users")
def list_users():
    return jsonify(store_of(current_app).users())


@st_auth_bp.post("/api/v1/auth/users")
def create_user():
    body = request.get_json(silent=True) or {}
    try:
        store_of(current_app).add_user(str(body.get("NAME", "")).strip(), str(body.get("PASSWORD", "")))
    except AccessError as exc:
        return _api_error(exc)
    _audit("CREATE_USER", f"User '{body.get('NAME')}' created")
    return jsonify({"ok": True})


@st_auth_bp.put("/api/v1/auth/users/<name>")
def change_password(name):
    body = request.get_json(silent=True) or {}
    try:
        store_of(current_app).set_password(name, str(body.get("PASSWORD", "")))
    except AccessError as exc:
        return _api_error(exc)
    if name == session.get("user"):
        session["epoch"] = store_of(current_app).epoch(name)  # la session en cours reste valide
    _audit("CHANGE_PASSWORD", f"Password of '{name}' changed")
    return jsonify({"ok": True})


@st_auth_bp.delete("/api/v1/auth/users/<name>")
def delete_user(name):
    try:
        store_of(current_app).delete_user(name)
    except AccessError as exc:
        return _api_error(exc)
    _audit("DELETE_USER", f"User '{name}' deleted")
    return jsonify({"ok": True})


@st_auth_bp.get("/api/v1/auth/tokens")
def list_tokens():
    return jsonify(store_of(current_app).tokens())


@st_auth_bp.post("/api/v1/auth/tokens")
def create_api_token():
    body = request.get_json(silent=True) or {}
    name = str(body.get("NAME", "")).strip()
    try:
        value = store_of(current_app).create_token(name)
    except AccessError as exc:
        return _api_error(exc)
    _audit("CREATE_API_TOKEN", f"API token '{name}' created")
    return jsonify({"name": name, "value": value})


@st_auth_bp.delete("/api/v1/auth/tokens/<name>")
def revoke_api_token(name):
    try:
        store_of(current_app).revoke_token(name)
    except AccessError as exc:
        return _api_error(exc)
    _audit("REVOKE_API_TOKEN", f"API token '{name}' revoked")
    return jsonify({"ok": True})


def init_app(app, config_file_path, tls=False):
    store = AccessStore(config_file_path + ".access.json")
    bootstrap(store, config_file_path)
    app.extensions["st_access"] = store
    app.extensions["st_failures"] = _Failures()
    app.config.update(SECRET_KEY=secret_key(config_file_path), SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=bool(tls),
                      SESSION_COOKIE_NAME="syntraf_session",
                      PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=SESSION_HOURS))
    app.before_request(_gate)
    app.after_request(_headers)
    app.register_blueprint(st_auth_bp)

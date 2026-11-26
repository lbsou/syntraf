"""Authentification de l'interface et de l'API (lib/webui/st_auth.py) : comptes, jetons d'API,
contrôle d'accès, protection CSRF, limitation des échecs, en-têtes de sécurité.
Tourne dans l'image du lab (dépendances de SYNTRAF).
"""
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    import toml
    from lib.webui import st_auth
    from test_webui_api import env  # noqa: F401 - fixture réutilisée
except (ImportError, SystemExit):
    pytest.skip("dépendances de SYNTRAF absentes (lancer dans l'image du lab)", allow_module_level=True)

PASSWORD = "correct horse battery staple"


# ---------------------------------------------------------------------------------- comptes et jetons

def test_passwords_are_hashed_and_checked(tmp_path):
    store = st_auth.AccessStore(str(tmp_path / "access.json"))
    store.add_user("admin", PASSWORD)
    raw = (tmp_path / "access.json").read_text()
    assert PASSWORD not in raw
    assert store.check_password("admin", PASSWORD) and not store.check_password("admin", "wrong password!")
    assert not store.check_password("nobody", PASSWORD)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(tmp_path / "access.json").st_mode) == 0o600


def test_short_passwords_and_bad_names_are_refused(tmp_path):
    store = st_auth.AccessStore(str(tmp_path / "access.json"))
    with pytest.raises(st_auth.AccessError):
        store.add_user("admin", "short")
    with pytest.raises(st_auth.AccessError):
        store.add_user("bad name!", PASSWORD)


def test_the_last_user_cannot_be_deleted(tmp_path):
    store = st_auth.AccessStore(str(tmp_path / "access.json"))
    store.add_user("admin", PASSWORD)
    with pytest.raises(st_auth.AccessError):
        store.delete_user("admin")


def test_api_tokens_are_shown_once_and_stored_hashed(tmp_path):
    store = st_auth.AccessStore(str(tmp_path / "access.json"))
    value = store.create_token("grafana")
    assert value not in (tmp_path / "access.json").read_text()
    assert store.check_token(value) == "grafana" and store.check_token("nope") is None
    store.revoke_token("grafana")
    assert store.check_token(value) is None


def test_bootstrap_creates_one_admin_and_writes_its_password_to_a_private_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SYNTRAF_ADMIN_PASSWORD", raising=False)
    store = st_auth.AccessStore(str(tmp_path / "access.json"))
    secret_file = st_auth.bootstrap(store, str(tmp_path / "config.toml"))
    password = Path(secret_file).read_text().strip()
    assert store.check_password("admin", password)
    assert st_auth.bootstrap(store, str(tmp_path / "config.toml")) is None  # une seule fois


def test_bootstrap_can_take_the_password_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SYNTRAF_ADMIN_PASSWORD", PASSWORD)
    store = st_auth.AccessStore(str(tmp_path / "access.json"))
    assert st_auth.bootstrap(store, str(tmp_path / "config.toml")) is None
    assert store.check_password("admin", PASSWORD)


# ---------------------------------------------------------------------------------- application

@pytest.fixture
def app_env(monkeypatch, request):
    monkeypatch.setenv("SYNTRAF_ADMIN_PASSWORD", PASSWORD)  # avant la création de l'application (premier compte)
    return request.getfixturevalue("env")


def login(client, password=PASSWORD, origin=None):
    headers = {"Origin": origin} if origin else {}
    return client.post("/login", data={"username": "admin", "password": password}, headers=headers)


def test_everything_needs_authentication_except_health_and_login(app_env):
    c = app_env["client"].application.test_client()
    assert c.get("/healthz").status_code in (200, 503)
    assert c.get("/login").status_code == 200
    assert c.get("/api/v1/mesh-groups").status_code == 401
    assert c.post("/api/v1/server/restart").status_code == 401
    assert c.post("/api/v1/config/tokens/T1/reveal").status_code == 401
    assert c.get("/metrics").status_code == 401
    r = c.get("/home.html")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_a_session_unlocks_the_api_but_writes_need_the_custom_header(app_env):
    c = app_env["client"].application.test_client()
    assert login(c).status_code == 302
    assert c.get("/api/v1/mesh-groups").status_code == 200
    # écriture sans l'en-tête de l'interface : refusée (un autre site ne peut pas l'ajouter sans pré-vol CORS)
    assert c.post("/api/v1/server/restart").status_code == 403
    r = c.put("/api/v1/mesh-groups/GROUP1?dry_run=1", json={"BANDWIDTH": "120K", "DSCP": "0", "PACKET_SIZE": "218",
                                                             "INTERVAL": "1"}, headers={"X-Requested-With": "syntraf"})
    assert r.status_code == 200


def test_a_write_from_another_origin_is_refused(app_env):
    c = app_env["client"].application.test_client()
    login(c)
    r = c.put("/api/v1/mesh-groups/GROUP1?dry_run=1", json={"BANDWIDTH": "120K"},
              headers={"X-Requested-With": "syntraf", "Origin": "https://evil.example"})
    assert r.status_code == 403


def test_form_bodies_are_no_longer_accepted_by_the_api(app_env):
    c = app_env["client"].application.test_client()
    login(c)
    r = c.post("/api/v1/config/tokens", data={"NAME": "FORMTOKEN"}, headers={"X-Requested-With": "syntraf"})
    assert r.status_code == 400  # le corps de formulaire est ignoré : NAME manquant


def test_a_bearer_token_works_without_session_and_without_the_custom_header(app_env):
    app = app_env["client"].application
    store = st_auth.store_of(app)
    value = store.create_token("ci")
    c = app.test_client()
    h = {"Authorization": f"Bearer {value}"}
    assert c.get("/api/v1/mesh-groups", headers=h).status_code == 200
    assert c.put("/api/v1/mesh-groups/GROUP1?dry_run=1", json={"BANDWIDTH": "120K", "DSCP": "0",
                                                               "PACKET_SIZE": "218", "INTERVAL": "1"},
                 headers=h).status_code == 200
    assert c.get("/api/v1/mesh-groups", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_repeated_login_failures_are_slowed_down(app_env):
    c = app_env["client"].application.test_client()
    codes = [login(c, password="wrong password!!").status_code for _ in range(st_auth.MAX_FAILURES + 1)]
    assert codes[-1] == 429
    assert login(c).status_code == 429  # même le bon mot de passe, le temps du blocage


def test_audit_names_the_user(app_env):
    c = app_env["client"].application.test_client()
    login(c)
    c.put("/api/v1/mesh-groups/GROUP1", json={"BANDWIDTH": "120K", "DSCP": "0", "PACKET_SIZE": "218",
                                             "INTERVAL": "1"}, headers={"X-Requested-With": "syntraf"})
    entry = c.get("/api/v1/audit?limit=1").json[0]
    assert entry["actor"].startswith("admin")


def test_security_headers_are_set(app_env):
    r = app_env["client"].application.test_client().get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]


def test_session_cookie_is_http_only_and_same_site(app_env):
    c = app_env["client"].application.test_client()
    r = login(c)
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie


def test_users_and_tokens_are_managed_through_the_api(app_env):
    c = app_env["client"].application.test_client()
    login(c)
    h = {"X-Requested-With": "syntraf"}
    assert c.post("/api/v1/auth/users", json={"NAME": "alice", "PASSWORD": PASSWORD}, headers=h).status_code == 200
    assert [u["NAME"] for u in c.get("/api/v1/auth/users").json] == ["admin", "alice"]
    r = c.post("/api/v1/auth/tokens", json={"NAME": "grafana"}, headers=h)
    assert r.status_code == 200 and len(r.json["value"]) > 30
    assert "value" not in str(c.get("/api/v1/auth/tokens").json)
    assert c.delete("/api/v1/auth/users/alice", headers=h).status_code == 200

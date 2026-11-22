"""Opérations de la webui sur les mesh groups et sur les versions de la configuration.

Indépendant de Flask : chaque fonction reçoit `state`, le dictionnaire partagé avec le reste du serveur
(app.config dans la webui) :
  config, config_file_path, _dict_by_node_generated_config, _dict_by_group_of_generated_tuple_for_map,
  dict_of_clients, dict_of_commands_for_network_clients

Principe de chaque changement :
  1. on part du fichier de configuration (la vérité sur disque) et on y applique le changement ;
  2. on revalide tous les mesh groups comme au démarrage (champs calculés : paquets par seconde, espacement) ;
  3. on génère la config des clients sur une copie : refus si un client dépasse son MAX_BANDWIDTH ;
  4. aperçu (dry_run) : on s'arrête là et on renvoie le diff et les clients touchés ;
  5. sinon : écriture du fichier (version + audit), application à la config en mémoire, puis demande de
     reconnexion aux clients connectés dont la config a changé (chacun ne relance que les flux modifiés).
"""
import contextlib
import contextvars
import copy
import ipaddress
import logging
import os
import re
import threading
import time

import toml

from lib import st_config_store as store
from lib import st_capacity
from lib import st_flow_catalog
from lib import st_syslog
from lib import st_topology

# Confirmation explicite d'un changement qui franchit le seuil d'alerte de capacité (posée par l'API, ?confirm=1)
CONFIRMED = contextvars.ContextVar("syntraf_large_change_confirmed", default=False)
from lib.st_conf_validation import (PortExhausted, validate_bandwidth, validate_dscp, validate_packet_size, validate_interval,
                                    validate_uid, validate_group, generate_client_config_mesh,
                                    validate_excluded_client, validate_override_dst_node_ip,
                                    config_validation_database, explode_profile, FQDN)

log = logging.getLogger("syntraf." + __name__)

EDITABLE_FIELDS = ("BANDWIDTH", "DSCP", "PACKET_SIZE", "INTERVAL")
FIELD_MESSAGES = {
    "UID": "4 to 50 characters: letters, digits, '_' or '-'",
    "BANDWIDTH": "A positive rate, e.g. 200K or 1.5M (bits per second)",
    "DSCP": "An integer between 0 and 63",
    "PACKET_SIZE": "An integer between 16 and 65507 (bytes)",
    "INTERVAL": "An integer between 1 and 60 (seconds)",
}


class OpError(Exception):
    """Refus d'une opération : status suit la sémantique HTTP (400, 404, 409, 422, 500)."""

    def __init__(self, status, message, fields=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.fields = fields or {}


# ---------------------------------------------------------------------------------------------------------- lecture

def read_disk(state):
    try:
        return toml.load(state["config_file_path"])
    except (OSError, toml.TomlDecodeError) as exc:
        raise OpError(500, f"Unable to read the configuration file: {exc}")


def list_groups(state):
    """Mesh groups tels qu'écrits dans le fichier, avec le nombre de membres, le débit sortant par membre, et les
    valeurs effectives (EFFECTIVE) : celles du profil quand le groupe en utilise un."""
    cfg = read_disk(state)
    groups = copy.deepcopy(cfg.get("MESH_GROUP", []))
    for g in groups:
        effective = copy.deepcopy(g)
        if effective.get("IPERF3_PROFILE"):
            explode_profile(effective, cfg)
        g["EFFECTIVE"] = {k: effective.get(k) for k in EDITABLE_FIELDS}
        g["MEMBER_UIDS"] = _members(cfg, g["UID"])
        g["MEMBERS"] = n = len(g["MEMBER_UIDS"])
        bandwidth = _ok(lambda x: validate_bandwidth(x) >= 0, effective.get("BANDWIDTH")) and validate_bandwidth(effective["BANDWIDTH"])
        g["TOPOLOGY"], g["HUBS"] = st_topology.topology(g), st_topology.hubs(g)
        g["FLOWS"] = st_topology.flow_count(g, n)
        g["KBPS_OUT"] = {role: count * (bandwidth or 0) / 1000 for role, count in st_topology.outgoing(g, n).items()}
        g["BW_PER_NODE_KBPS"] = max(g["KBPS_OUT"].values()) if n else 0
        g["DISABLED"] = g.get("DISABLED", False) is True
    return groups


def get_group(state, uid):
    for g in list_groups(state):
        if g["UID"] == uid:
            return g
    raise OpError(404, f"Mesh group '{uid}' not found")


class _QuietFilter(logging.Filter):
    """Pendant la validation d'une saisie, les messages des fonctions de validation du démarrage (ERROR pour toute
    valeur invalide) ne vont pas au journal : un champ refusé est déjà signalé dans le formulaire."""
    local = threading.local()

    def filter(self, record):
        return not getattr(self.local, "quiet", False)


_VALIDATION_LOGGER = logging.getLogger("syntraf.lib.st_conf_validation")
_QUIET = _QuietFilter()
_VALIDATION_LOGGER.addFilter(_QUIET)


@contextlib.contextmanager
def _quiet():
    previous = getattr(_QUIET.local, "quiet", False)
    _QUIET.local.quiet = True
    try:
        yield
    finally:
        _QUIET.local.quiet = previous


def field_errors(values, with_uid=False, optional=False):
    """Erreurs par champ du formulaire : {"BANDWIDTH": "message", ...} (vide si tout est valide).
    optional : un champ vide est accepté (groupe dont un profil fournit les valeurs)."""
    v = {k: str(values.get(k, "")).strip() for k in ("UID",) + EDITABLE_FIELDS}
    checks = {
        "BANDWIDTH": lambda x: validate_bandwidth(x) > 0,
        "DSCP": validate_dscp,
        "PACKET_SIZE": validate_packet_size,
        "INTERVAL": lambda x: x.isdigit() and validate_interval(x),
    }
    if with_uid:
        checks["UID"] = validate_uid
    errors = {}
    for name, check in checks.items():
        if optional and name != "UID" and not v[name]:
            continue
        try:
            with _quiet():
                ok = bool(v[name]) and check(v[name])
        except Exception:  # noqa: BLE001 - les fonctions de validation lèvent parfois sur une entrée invalide
            ok = False
        if not ok:
            errors[name] = FIELD_MESSAGES[name]
    return errors


# ----------------------------------------------------------------------------------------------------- mesh groups

def create(state, values, actor, dry_run=False):
    uid = str(values.get("UID", "")).strip()
    _raise_on_field_errors(values, with_uid=True, optional=bool(str(values.get("IPERF3_PROFILE", "") or "").strip()))
    cfg = read_disk(state)
    _check_profile_reference(cfg, values)
    if _find(cfg, uid) is not None:
        raise OpError(409, f"Mesh group '{uid}' already exists", {"UID": "This name is already used"})
    new = {"UID": uid}
    _apply_form(new, values)
    _apply_topology(cfg, new, values)
    cfg["MESH_GROUP"].append(new)
    return dict(_commit(state, cfg, actor, "CREATE_MESH_GROUP", f"Mesh group '{uid}' created", dry_run), uid=uid)


def update(state, uid, values, actor, dry_run=False):
    _raise_on_field_errors(values, optional=bool(str(values.get("IPERF3_PROFILE", "") or "").strip()))
    cfg = read_disk(state)
    _check_profile_reference(cfg, values)
    g = _require(cfg, uid)
    _apply_form(g, values)
    _apply_topology(cfg, g, values)
    return dict(_commit(state, cfg, actor, "UPDATE_MESH_GROUP", f"Mesh group '{uid}' updated", dry_run), uid=uid)


def set_disabled(state, uid, disabled, actor, dry_run=False):
    cfg = read_disk(state)
    g = _require(cfg, uid)
    if disabled:
        g["DISABLED"] = True
    else:
        g.pop("DISABLED", None)
    action = "DISABLE_MESH_GROUP" if disabled else "ENABLE_MESH_GROUP"
    # deux phrases entières (et non un verbe inséré) : chacune a sa traduction dans l'interface
    summary = f"Mesh group '{uid}' disabled" if disabled else f"Mesh group '{uid}' enabled"
    return dict(_commit(state, cfg, actor, action, summary, dry_run), uid=uid)


def delete(state, uid, actor, dry_run=False):
    cfg = read_disk(state)
    g = _require(cfg, uid)
    members = _members(cfg, uid)
    if members:
        raise OpError(409, f"Mesh group '{uid}' is used by {len(members)} client(s): {', '.join(members)}")
    cfg["MESH_GROUP"].remove(g)
    return dict(_commit(state, cfg, actor, "DELETE_MESH_GROUP", f"Mesh group '{uid}' deleted", dry_run), uid=uid)


def duplicate(state, uid, actor, dry_run=False):
    cfg = read_disk(state)
    clone = copy.deepcopy(_require(cfg, uid))
    names = {g["UID"] for g in cfg["MESH_GROUP"]}
    new_uid, n = f"{uid}_COPY", 0
    while new_uid in names:
        n += 1
        new_uid = f"{uid}_COPY{n}"
    clone["UID"] = new_uid
    for hub in clone.get("HUBS") or []:  # les hubs sont membres de leur groupe : ils rejoignent la copie
        client = _find_by(cfg.get("SERVER_CLIENT", []), "UID", hub)
        if client is not None and new_uid not in client.setdefault("MESH_GROUP_UID_LIST", []):
            client["MESH_GROUP_UID_LIST"].append(new_uid)
    cfg["MESH_GROUP"].append(clone)
    result = _commit(state, cfg, actor, "DUPLICATE_MESH_GROUP", f"Mesh group '{uid}' duplicated as '{new_uid}'",
                     dry_run)
    return dict(result, uid=new_uid)


def save_map(state, uid, cyto_json, actor):
    cfg = read_disk(state)
    _require(cfg, uid)["WEBUI_JSON"] = cyto_json
    return _commit(state, cfg, actor, "SAVE_MAP", f"Map of mesh group '{uid}' saved", False)


# ------------------------------------------------------------------------------------------------ profils iperf3

PROFILE_FIELDS = ("BANDWIDTH", "DSCP", "PACKET_SIZE", "INTERVAL")


def list_profiles(state):
    """Profils iperf3 tels qu'écrits dans le fichier, avec les mesh groups qui les utilisent (USED_BY)."""
    cfg = read_disk(state)
    rows = copy.deepcopy(cfg.get("IPERF3_PROFILE", []))
    for p in rows:
        p["USED_BY"] = [g["UID"] for g in cfg.get("MESH_GROUP", []) if g.get("IPERF3_PROFILE") == p.get("UID")]
    return rows


def create_profile(state, values, actor, dry_run=False):
    cfg = read_disk(state)
    uid = str(values.get("UID", "")).strip()
    _raise(_profile_field_errors(values, with_uid=True))
    if _find_by(cfg.get("IPERF3_PROFILE", []), "UID", uid) is not None:
        raise OpError(409, f"Profile '{uid}' already exists", {"UID": "This name is already used"})
    p = {"UID": uid}
    _apply_profile_form(p, values)
    cfg.setdefault("IPERF3_PROFILE", []).append(p)
    return dict(_commit(state, cfg, actor, "CREATE_PROFILE", f"Profile '{uid}' created", dry_run), uid=uid)


def update_profile(state, uid, values, actor, dry_run=False):
    """Modifie un profil : les mesh groups qui l'utilisent sont régénérés et leurs membres se reconnectent."""
    cfg = read_disk(state)
    p = _find_by(cfg.get("IPERF3_PROFILE", []), "UID", uid)
    if p is None:
        raise OpError(404, f"Profile '{uid}' not found")
    _raise(_profile_field_errors(values))
    _apply_profile_form(p, values)
    return dict(_commit(state, cfg, actor, "UPDATE_PROFILE", f"Profile '{uid}' updated", dry_run), uid=uid)


def delete_profile(state, uid, actor, dry_run=False):
    cfg = read_disk(state)
    p = _find_by(cfg.get("IPERF3_PROFILE", []), "UID", uid)
    if p is None:
        raise OpError(404, f"Profile '{uid}' not found")
    used_by = [g["UID"] for g in cfg.get("MESH_GROUP", []) if g.get("IPERF3_PROFILE") == uid]
    if used_by:
        raise OpError(409, f"Profile '{uid}' is used by mesh group(s): {', '.join(used_by)}")
    cfg["IPERF3_PROFILE"].remove(p)
    return dict(_commit(state, cfg, actor, "DELETE_PROFILE", f"Profile '{uid}' deleted", dry_run), uid=uid)


def _profile_field_errors(values, with_uid=False):
    """Chaque valeur est facultative (le mesh group garde alors la sienne), mais il en faut au moins une."""
    present = {k for k in PROFILE_FIELDS if str(values.get(k, "") or "").strip()}
    # Seules les valeurs données sont validées (avant : les autres étaient remplacées par une valeur fictive « 1 »,
    # invalide pour une taille de paquet, et le validateur l'écrivait en ERROR dans le journal du serveur)
    errors = field_errors(values, with_uid, optional=True)
    if not present and not errors:
        raise OpError(400, "A profile needs at least one value (bandwidth, DSCP, packet size or interval)",
                      {k: "At least one value is needed" for k in PROFILE_FIELDS})
    return errors


def _apply_profile_form(p, values):
    for key in PROFILE_FIELDS + ("DESCRIPTION",):
        value = str(values.get(key, "") or "").strip()
        if value:
            p[key] = value
        else:
            p.pop(key, None)
    p.pop("PACKET_PER_SECOND", None)  # recalculé depuis le débit et la taille, comme pour les mesh groups


def _check_profile_reference(cfg, values):
    """Le profil existe, et aucune valeur n'est donnée pour un champ qu'il fixe : le profil a priorité, une telle
    valeur serait ignorée en silence (elle est donc refusée, avec la valeur du profil dans le message)."""
    profile = str(values.get("IPERF3_PROFILE", "") or "").strip()
    if not profile:
        return
    p = _find_by(cfg.get("IPERF3_PROFILE", []), "UID", profile)
    if p is None:
        raise OpError(400, "Some fields are invalid", {"IPERF3_PROFILE": f"Profile '{profile}' does not exist"})
    conflicts = {k: f"Set by profile {profile} ({p[k]}): leave it empty, or change the profile"
                 for k in EDITABLE_FIELDS if p.get(k) and str(values.get(k, "") or "").strip()}
    if conflicts:
        raise OpError(400, "Some fields are set by the profile", conflicts)


# --------------------------------------------------------------------------------------------- section SERVER

SERVER_FIELDS = ("BIND_ADDRESS", "SERVER_PORT", "MESH_LISTENERS_PORT_RANGE", "SERVER_X509_CERTIFICATE",
                 "SERVER_X509_PRIVATE_KEY", "WEBUI_BIND_ADDRESS", "WEBUI_PORT", "WEBUI_X509_CERTIFICATE",
                 "WEBUI_X509_PRIVATE_KEY")
SERVER_BOOL_FIELDS = ("WEBUI_TLS",  # interface web en HTTPS (certificat donné, sinon autosigné)
                      "REQUIRE_KEY_PROOF")  # refuser un client qui ne prouve pas détenir sa clé (versions anciennes)
SERVER_LIVE_KEYS = ("TOKEN", "MESH_LISTENERS_PORT_RANGE",  # appliquées à chaud ; les autres au redémarrage
                    "MAX_FLOWS_PER_CLIENT", "MAX_TOTAL_FLOWS", "FLOW_ALERT_ADDED", "FLOW_ALERT_RATIO",
                    "REQUIRE_KEY_PROOF")
SERVER_MESSAGES = {
    "BIND_ADDRESS": "An IP address of this server, or 0.0.0.0 for all interfaces",
    "SERVER_PORT": "A port between 1 and 65534",
    "MESH_LISTENERS_PORT_RANGE": "A port range such as 15000-15100",
    "SERVER_X509_CERTIFICATE": "Path of a readable certificate file on the server; empty for a self-signed certificate",
    "SERVER_X509_PRIVATE_KEY": "Path of a readable private key file, given together with the certificate",
    "WEBUI_BIND_ADDRESS": "An IP address of this server, or 0.0.0.0 for all interfaces (127.0.0.1: this host only)",
    "WEBUI_PORT": "A port between 1 and 65535, other than the control port",
    "WEBUI_X509_CERTIFICATE": "Path of a readable certificate file on the server; empty for a self-signed certificate",
    "WEBUI_X509_PRIVATE_KEY": "Path of a readable private key file, given together with the certificate",
}
TOKEN_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,50}$")


def get_server(state):
    """Réglages de la section SERVER tels qu'écrits (sans les jetons), et ceux en service (RUNNING)."""
    disk_server = read_disk(state).get("SERVER", {})
    live_server = state["config"].get("SERVER", {})
    row = {k: disk_server.get(k, "") for k in SERVER_FIELDS + tuple(st_capacity.DEFAULTS)}
    row.update({k: bool(disk_server.get(k)) for k in SERVER_BOOL_FIELDS})
    row["CAPACITY_DEFAULTS"] = {k: str(v) for k, v in st_capacity.DEFAULTS.items()}
    row["RUNNING"] = {k: live_server.get(k, "") for k in SERVER_FIELDS if not isinstance(live_server.get(k), bytes)}
    row["LIVE_KEYS"] = list(SERVER_LIVE_KEYS)
    row["CONTROL_KEY_SHA256"] = _control_key_fingerprint(live_server)
    return row


def _control_key_fingerprint(live_server):
    """Empreinte de la clé du canal de contrôle, à recopier dans CLIENT.SERVER_CERT_SHA256."""
    try:
        from lib import st_identity
        with open(live_server.get("SERVER_X509_CERTIFICATE", ""), "rb") as f:
            return st_identity.spki_sha256(st_identity.pem_to_der(f.read()))
    except Exception:  # noqa: BLE001 - simple information
        return ""


def update_server(state, values, actor, dry_run=False):
    cfg = read_disk(state)
    _raise(dict(_server_field_errors(values), **st_capacity.limit_errors(values)))
    server = cfg.setdefault("SERVER", {})
    for key in SERVER_FIELDS + tuple(st_capacity.DEFAULTS):
        value = str(values.get(key, "") or "").strip()
        if value:
            server[key] = value
        else:
            server.pop(key, None)
    for key in SERVER_BOOL_FIELDS:
        if key in values:  # absent d'un ancien appel : inchangé
            if _bool_text(values.get(key)):
                server[key] = True
            else:
                server.pop(key, None)
    return _commit(state, cfg, actor, "UPDATE_SERVER", "Server settings updated", dry_run)


def _server_field_errors(values):
    v = {k: str(values.get(k, "") or "").strip() for k in SERVER_FIELDS}
    errors = {}
    if v["BIND_ADDRESS"]:
        try:
            ipaddress.ip_address(v["BIND_ADDRESS"])
        except ValueError:
            errors["BIND_ADDRESS"] = SERVER_MESSAGES["BIND_ADDRESS"]
    if v["SERVER_PORT"] and not (v["SERVER_PORT"].isdigit() and 1 <= int(v["SERVER_PORT"]) <= 65534):
        errors["SERVER_PORT"] = SERVER_MESSAGES["SERVER_PORT"]
    if v["WEBUI_BIND_ADDRESS"]:
        try:
            ipaddress.ip_address(v["WEBUI_BIND_ADDRESS"])
        except ValueError:
            errors["WEBUI_BIND_ADDRESS"] = SERVER_MESSAGES["WEBUI_BIND_ADDRESS"]
    if v["WEBUI_PORT"] and not (v["WEBUI_PORT"].isdigit() and 1 <= int(v["WEBUI_PORT"]) <= 65535
                                and v["WEBUI_PORT"] != (v["SERVER_PORT"] or "6531")):
        errors["WEBUI_PORT"] = SERVER_MESSAGES["WEBUI_PORT"]
    wcert, wkey = v["WEBUI_X509_CERTIFICATE"], v["WEBUI_X509_PRIVATE_KEY"]
    if wcert or wkey:
        if not (wcert and os.path.isfile(wcert)):
            errors["WEBUI_X509_CERTIFICATE"] = SERVER_MESSAGES["WEBUI_X509_CERTIFICATE"]
        if not (wkey and os.path.isfile(wkey)):
            errors["WEBUI_X509_PRIVATE_KEY"] = SERVER_MESSAGES["WEBUI_X509_PRIVATE_KEY"]
    if v["MESH_LISTENERS_PORT_RANGE"] and not _valid_port_range(v["MESH_LISTENERS_PORT_RANGE"]):
        errors["MESH_LISTENERS_PORT_RANGE"] = SERVER_MESSAGES["MESH_LISTENERS_PORT_RANGE"]
    cert, key = v["SERVER_X509_CERTIFICATE"], v["SERVER_X509_PRIVATE_KEY"]
    if cert or key:  # le certificat et sa clé vont ensemble
        if not (cert and os.path.isfile(cert)):
            errors["SERVER_X509_CERTIFICATE"] = SERVER_MESSAGES["SERVER_X509_CERTIFICATE"]
        if not (key and os.path.isfile(key)):
            errors["SERVER_X509_PRIVATE_KEY"] = SERVER_MESSAGES["SERVER_X509_PRIVATE_KEY"]
    return errors


def _apply_live_server(live, old_disk, new_disk):
    """Reporte à chaud les clés de SERVER_LIVE_KEYS ; renvoie les clés qui attendent un redémarrage."""
    old_server, new_server = old_disk.get("SERVER", {}), new_disk.get("SERVER", {})
    live_server = live.setdefault("SERVER", {})
    if old_server.get("TOKEN") != new_server.get("TOKEN"):
        tokens = live_server.setdefault("TOKEN", {})
        tokens.clear()  # sur place : la boucle d'authentification garde une référence à ce dictionnaire
        tokens.update(copy.deepcopy(new_server.get("TOKEN", {})))
    if bool(old_server.get("REQUIRE_KEY_PROOF")) != bool(new_server.get("REQUIRE_KEY_PROOF")):
        live_server["REQUIRE_KEY_PROOF"] = bool(new_server.get("REQUIRE_KEY_PROOF"))
    if old_server.get("MESH_LISTENERS_PORT_RANGE") != new_server.get("MESH_LISTENERS_PORT_RANGE"):
        from lib.st_global import DefaultValues
        live_server["MESH_LISTENERS_PORT_RANGE"] = new_server.get("MESH_LISTENERS_PORT_RANGE",
                                                                  DefaultValues.DEFAULT_PORT_RANGE)
    return _restart_keys(old_disk, new_disk)


def _restart_keys(old_disk, new_disk):
    """Réglages modifiés qui ne prennent effet qu'au redémarrage du serveur : ["SERVER.SERVER_PORT", "GLOBAL", ...]."""
    keys = []
    for section in sorted(set(old_disk) | set(new_disk)):
        if section in LIVE_SECTIONS:
            continue
        old, new = old_disk.get(section), new_disk.get(section)
        live_keys = {"SERVER": SERVER_LIVE_KEYS, "GLOBAL": GLOBAL_LIVE_KEYS}.get(section)
        if live_keys is not None and isinstance(old or {}, dict) and isinstance(new or {}, dict):
            old, new = old or {}, new or {}
            keys += [f"{section}.{k}" for k in sorted(set(old) | set(new))
                     if k not in live_keys and old.get(k) != new.get(k)]
        elif old != new:
            keys.append(section)
    return keys


# ---------------------------------------------------------------------------------------- journalisation

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
LOGGING_FIELDS = ("LOG_LEVEL", "LOG_FORWARD_LEVEL", "LOG_MAX_SIZE_PER_FILE_MB", "LOG_FILE_TO_KEEP", "LOG_RETENTION_DAYS")
LOGGING_DEFAULTS = {"LOG_LEVEL": "INFO", "LOG_FORWARD_LEVEL": "INFO", "LOG_MAX_SIZE_PER_FILE_MB": "10",
                    "LOG_FILE_TO_KEEP": "5", "LOG_RETENTION_DAYS": ""}
GLOBAL_LIVE_KEYS = ("LOG_LEVEL", "LOG_FORWARD_LEVEL", "LOG_RETENTION_DAYS", "WATCHDOG_CHECK_RATE",
                    "IPERF3_TIME_SKEW_THRESHOLD") + st_syslog.KEYS
# Réglages transmis aux clients à leur connexion : un changement les fait se reconnecter pour les recevoir
GLOBAL_SENT_TO_CLIENTS = (("LOG_FORWARD_LEVEL", "INFO"), ("IPERF3_TIME_SKEW_THRESHOLD", None))
LOGGING_MESSAGES = {
    "LOG_LEVEL": "DEBUG, INFO, WARNING, ERROR or CRITICAL",
    "LOG_FORWARD_LEVEL": "DEBUG, INFO, WARNING, ERROR or CRITICAL",
    "LOG_MAX_SIZE_PER_FILE_MB": "An integer between 1 and 100",
    "LOG_FILE_TO_KEEP": "An integer between 1 and 50",
    "LOG_RETENTION_DAYS": "Empty (no age limit), or a number of days between 1 and 3650",
}


def get_logging(state):
    g = read_disk(state).get("GLOBAL", {})
    row = {k: str(g.get(k, LOGGING_DEFAULTS[k])) for k in LOGGING_FIELDS}
    row["LIVE_KEYS"] = list(GLOBAL_LIVE_KEYS)
    return row


def update_logging(state, values, actor, dry_run=False):
    v = {k: str(values.get(k, "") or "").strip() for k in LOGGING_FIELDS}
    errors = {}
    for key in ("LOG_LEVEL", "LOG_FORWARD_LEVEL"):
        if v[key].upper() not in LOG_LEVELS:
            errors[key] = LOGGING_MESSAGES[key]
    for key, low, high in (("LOG_MAX_SIZE_PER_FILE_MB", 1, 100), ("LOG_FILE_TO_KEEP", 1, 50)):
        if not (v[key].isdigit() and low <= int(v[key]) <= high):
            errors[key] = LOGGING_MESSAGES[key]
    if v["LOG_RETENTION_DAYS"] and not (v["LOG_RETENTION_DAYS"].isdigit() and 1 <= int(v["LOG_RETENTION_DAYS"]) <= 3650):
        errors["LOG_RETENTION_DAYS"] = LOGGING_MESSAGES["LOG_RETENTION_DAYS"]
    _raise(errors)
    cfg = read_disk(state)
    g = cfg.setdefault("GLOBAL", {})
    for key in LOGGING_FIELDS:
        value = v[key].upper() if key in ("LOG_LEVEL", "LOG_FORWARD_LEVEL") else v[key]
        if value == LOGGING_DEFAULTS[key] and key not in g:
            continue  # valeur par défaut d'un réglage absent du fichier : il reste absent
        if value:
            g[key] = value
        else:
            g.pop(key, None)
    return _commit(state, cfg, actor, "UPDATE_LOGGING", "Logging settings updated", dry_run)


def _apply_live_global(live, old_disk, new_disk):
    """Reporte à chaud les réglages de journalisation ; renvoie True si le niveau transmis par les clients change."""
    old_g, new_g = old_disk.get("GLOBAL", {}), new_disk.get("GLOBAL", {})
    live_g = live.setdefault("GLOBAL", {})
    for key in GLOBAL_LIVE_KEYS:
        if old_g.get(key) != new_g.get(key):
            if key in new_g:
                live_g[key] = new_g[key]
            else:
                live_g.pop(key, None)
    if old_g.get("LOG_LEVEL") != new_g.get("LOG_LEVEL") and new_g.get("LOG_LEVEL"):
        level = logging.getLevelName(str(new_g["LOG_LEVEL"]).upper())
        if isinstance(level, int):
            syntraf_logger = logging.getLogger("syntraf")
            syntraf_logger.setLevel(level)
            for handler in syntraf_logger.handlers:
                if not handler.__class__.__name__ == "ForwardHandler":
                    handler.setLevel(level)
    if any(old_g.get(k) != new_g.get(k) for k in st_syslog.KEYS):
        st_syslog.install(live_g)
    return old_g.get("LOG_FORWARD_LEVEL", "INFO") != new_g.get("LOG_FORWARD_LEVEL", "INFO")


# ---------------------------------------------------------------------------------------- renvoi syslog

SYSLOG_BOOLS = ("SYSLOG_INCLUDE_CLIENTS", "SYSLOG_TLS_VERIFY")


def get_syslog(state):
    g = read_disk(state).get("GLOBAL", {})
    row = {k: "" if g.get(k) is None else str(g.get(k)) for k in st_syslog.KEYS}
    row["STATUS"] = st_syslog.FORWARDER.status()
    return row


def update_syslog(state, values, actor, dry_run=False):
    """Collecteur syslog (SIEM) ; sans hôte, le renvoi est désactivé. Appliqué à chaud."""
    v = {k: str(values.get(k, "") if values.get(k) is not None else "").strip() for k in st_syslog.KEYS}
    _raise(st_syslog.setting_errors(v))
    cfg = read_disk(state)
    g = cfg.setdefault("GLOBAL", {})
    for key in st_syslog.KEYS:
        value = v[key]
        if key in SYSLOG_BOOLS:
            value = _bool_text(value) if value else None
        elif key in ("SYSLOG_PROTOCOL", "SYSLOG_FORMAT", "SYSLOG_FACILITY"):
            value = value.lower()
        elif key == "SYSLOG_LEVEL":
            value = value.upper()
        if value is None or value == "":
            g.pop(key, None)
        else:
            g[key] = value
    return _commit(state, cfg, actor, "UPDATE_SYSLOG", "Syslog forwarding updated", dry_run)


def syslog_test(state, actor):
    if not st_syslog.FORWARDER.settings.enabled:
        raise OpError(409, "Syslog forwarding is not configured: set a collector first")
    return st_syslog.FORWARDER.send_test(actor)


# ------------------------------------------------------------------------------------------ section GLOBAL

def _bool_text(v):
    return str(v).strip().lower() in ("true", "1", "yes", "on")


def _check_float_range(low, high):
    def check(v):
        try:
            return low <= float(v) <= high
        except ValueError:
            return False
    return check


GLOBAL_FIELDS = {
    # clé : (contrôle, message, booléen ?)
    "WATCHDOG_CHECK_RATE": (_check_float_range(0.1, 86400), "Seconds between two watchdog passes, 0.1 to 86400", False),
    "IPERF3_TIME_SKEW_THRESHOLD": (lambda v: v.isdigit() and 1 <= int(v) <= 86400,
                                   "Seconds of clock difference tolerated by iperf3 authentication, 1 to 86400", False),
    "LOG_TO": (lambda v: v.lower() in ("stdout", "file", "all"), "stdout, file or all", False),
    "IPERF3_AUTH": (lambda v: True, "", True),
    "LOG_PURGE_ON_START": (lambda v: True, "", True),
}
GLOBAL_READ_ONLY = ("LOGDIR",)  # imposé par l'option -l au démarrage
# Un programme exécuté par le serveur et le dossier où il écrit ses clés : jamais modifiables à distance (un
# appelant de l'API ferait exécuter n'importe quel fichier) ; seulement dans le fichier de configuration
GLOBAL_FILE_ONLY = ("IPERF3_BINARY_PATH", "IPERF3_RSA_KEY_DIRECTORY")
FILE_ONLY_MESSAGE = "Set in the configuration file on the server only"



def get_global(state):
    g = read_disk(state).get("GLOBAL", {})
    live = state["config"].get("GLOBAL", {})
    row = {k: ("" if g.get(k) is None else str(g.get(k))) for k in GLOBAL_FIELDS}
    row["RUNNING"] = {k: str(live.get(k)) for k in GLOBAL_FIELDS if live.get(k) is not None}
    row["READ_ONLY"] = {k: live.get(k) for k in GLOBAL_READ_ONLY if live.get(k)}
    row["FILE_ONLY"] = {k: str(g.get(k) or live.get(k) or "") for k in GLOBAL_FILE_ONLY}
    row["LIVE_KEYS"] = [k for k in GLOBAL_FIELDS if k in GLOBAL_LIVE_KEYS]
    return row


def update_global(state, values, actor, dry_run=False):
    """Réglages GLOBAL hors journalisation (celle-ci : update_logging). Vides : valeur par défaut au démarrage."""
    v = {k: str(values.get(k, "") or "").strip() for k in GLOBAL_FIELDS}
    errors = {k: GLOBAL_FIELDS[k][1] for k in GLOBAL_FIELDS
              if v[k] and not GLOBAL_FIELDS[k][2] and not _ok(GLOBAL_FIELDS[k][0], v[k])}
    cfg = read_disk(state)
    current = cfg.get("GLOBAL", {})
    for key in GLOBAL_FILE_ONLY:  # absent ou inchangé : accepté (anciens appels) ; autre valeur : refusée
        given = str(values.get(key, "") or "").strip()
        if given and given != str(current.get(key, "") or ""):
            errors[key] = FILE_ONLY_MESSAGE
    _raise(errors)
    g = cfg.setdefault("GLOBAL", {})
    live = state["config"].get("GLOBAL", {})
    for key, (_, _, is_bool) in GLOBAL_FIELDS.items():
        running = live.get(key)
        same_as_running = running is not None and (
            (is_bool and _bool_text(v[key]) == (running if isinstance(running, bool) else _bool_text(running)))
            or (not is_bool and v[key].lower() == str(running).lower()))
        if key not in g and same_as_running:
            continue  # valeur par défaut en service d'un réglage absent du fichier : il reste absent
        if not v[key]:
            g.pop(key, None)
        elif is_bool:
            g[key] = _bool_text(v[key])
        else:
            g[key] = v[key].lower() if key == "LOG_TO" else v[key]
    return _commit(state, cfg, actor, "UPDATE_GLOBAL", "Global settings updated", dry_run)


# ------------------------------------------------------------------------------------------ redémarrage

def restart_server(state, actor):
    """Demande au superviseur (st_updater) d'arrêter proprement SYNTRAF et de le relancer, dans les 5 s.
    La réponse part avant : la webui se reconnecte quand le serveur est revenu."""
    from lib import st_updater
    from lib.st_global import DefaultValues
    if not os.environ.get(st_updater.ENV_CHILD):
        raise OpError(409, "This server is not started through its supervisor (syntraf.py run by the service): "
                           "restart the service itself (systemctl restart, or the Windows service)")
    store.log_event(state["config_file_path"], actor, "RESTART_SERVER", "Server restart requested")
    st_updater.request_restart(str(DefaultValues.SYNTRAF_DATA_DIR))
    log.warning(f"SERVER RESTART REQUESTED BY {actor}")
    return {"message": "Restarting: the server will be back in a few seconds"}


# --------------------------------------------------------------------------------------- jetons partagés

def list_tokens(state):
    """Jetons partagés ([SERVER.TOKEN]) : noms seulement, jamais les valeurs."""
    tokens = read_disk(state).get("SERVER", {}).get("TOKEN", {})
    return [{"NAME": name} for name in tokens]


def create_token(state, values, actor, dry_run=False):
    """Crée un jeton aléatoire ; sa valeur n'est renvoyée qu'ici, une seule fois."""
    import secrets
    name = str(values.get("NAME", "") or "").strip()
    if not TOKEN_NAME.match(name):
        raise OpError(400, "Some fields are invalid", {"NAME": "1 to 50 characters: letters, digits, '_', '.' or '-'"})
    cfg = read_disk(state)
    tokens = cfg.setdefault("SERVER", {}).setdefault("TOKEN", {})
    if name in tokens:
        raise OpError(409, f"Token '{name}' already exists", {"NAME": "This name is already used"})
    value = secrets.token_urlsafe(32)
    tokens[name] = value
    result = _commit(state, cfg, actor, "CREATE_TOKEN", f"Token '{name}' created", dry_run)
    return dict(result, name=name, token=None if dry_run else value)


def delete_token(state, name, actor, dry_run=False):
    cfg = read_disk(state)
    tokens = cfg.get("SERVER", {}).get("TOKEN", {})
    if name not in tokens:
        raise OpError(404, f"Token '{name}' not found")
    relying = [c["UID"] for c in cfg.get("SERVER_CLIENT", []) if not c.get("TOKEN")]
    if len(tokens) == 1 and relying:
        raise OpError(409, f"'{name}' is the last shared token and {len(relying)} client(s) still use a shared token: "
                           f"{', '.join(relying)}. Give them their own token first.")
    del tokens[name]
    return _commit(state, cfg, actor, "DELETE_TOKEN", f"Token '{name}' revoked", dry_run)


def reveal_token(state, name, actor):
    """Valeur d'un jeton, pour configurer un client ; chaque consultation est inscrite au journal d'audit."""
    tokens = read_disk(state).get("SERVER", {}).get("TOKEN", {})
    if name not in tokens:
        raise OpError(404, f"Token '{name}' not found")
    store.log_event(state["config_file_path"], actor, "REVEAL_TOKEN", f"Token '{name}' revealed")
    return tokens[name]


# ------------------------------------------------------------------------------------------ mises à jour

def builtin_release():
    from lib import st_release
    from lib.st_global import DefaultValues
    return st_release.builtin(DefaultValues.SYNTRAF_ROOT_DIR, DefaultValues.SYNTRAF_DATA_DIR,
                              DefaultValues.SYNTRAF_VERSION)


def updates_overview(state):
    """Release intégrée du serveur et, pour chaque client déclaré, où il en est."""
    release = builtin_release()
    rows = []
    for c in read_disk(state).get("SERVER_CLIENT", []):
        obj = state["dict_of_clients"].get(c["UID"])
        connected = obj is not None and obj.status == "CONNECTED"
        running = getattr(obj, "release_id", None) if obj is not None else None
        status = getattr(obj, "update_status", None) if obj is not None else None
        failed = getattr(obj, "update_failed", None) if obj is not None else None
        if running == release["id"]:
            stage, detail = "UP_TO_DATE", ""
        elif failed and failed.get("id") == release["id"]:
            stage, detail = "ROLLED_BACK", failed.get("reason", "")
        elif status and status.get("RELEASE") == release["id"] and status.get("STATE") == "FAILED":
            stage, detail = "FAILED", status.get("MESSAGE", "")
        elif status and status.get("RELEASE") == release["id"] and status.get("STATE") == "STAGED":
            stage, detail = "SWITCHING", status.get("AT", "")
        elif not connected:
            stage, detail = "OFFLINE", ""
        elif running is None:
            stage, detail = "NOT_SUPPORTED", "this client version cannot be updated remotely: install once by hand"
        else:
            stage, detail = "OUTDATED", ""
        rows.append({"uid": c["UID"], "connected": connected, "release": running, "stage": stage, "detail": detail})
    return {"release": {k: release[k] for k in ("id", "version", "sha256", "size", "has_wheelhouse")}, "clients": rows}


def request_updates(state, uids, actor, force=False):
    """Envoie la release intégrée aux clients demandés qui sont connectés, compatibles et pas encore à jour."""
    release = builtin_release()
    overview = {r["uid"]: r for r in updates_overview(state)["clients"]}
    queued, skipped = [], {}
    for uid in uids:
        row = overview.get(uid)
        if row is None:
            skipped[uid] = "unknown client"
        elif row["stage"] in ("OFFLINE", "NOT_SUPPORTED", "UP_TO_DATE", "SWITCHING"):
            skipped[uid] = row["stage"].lower().replace("_", " ")
        elif row["stage"] == "ROLLED_BACK" and not force:
            skipped[uid] = "rolled back from this release; force to try again"
        else:
            state["dict_of_commands_for_network_clients"].setdefault(uid, []).append(
                {"ACTION": "UPDATE", "RELEASE": release["id"], "SHA256": release["sha256"], "SIZE": release["size"],
                 "FORCE": bool(force)})
            obj = state["dict_of_clients"].get(uid)
            if obj is not None:
                obj.update_status = None
            queued.append(uid)
    if queued:
        store.log_event(state["config_file_path"], actor, "REQUEST_UPDATE",
                        f"Release {release['id']} sent to {', '.join(queued)}")
    return {"release": release["id"], "queued": queued, "skipped": skipped}


# --------------------------------------------------------------------------------------------------------- clients

LIVE_SECTIONS = ("MESH_GROUP", "IPERF3_PROFILE", "SERVER_CLIENT", "DATABASE")
DYNAMIC_IP = "0.0.0.0"
CLIENT_MESSAGES = {
    "UID": FIELD_MESSAGES["UID"],
    "IP_ADDRESS": "An IP address or a host name, or 0.0.0.0 for a client with a dynamic IP",
    "MESH_GROUP_UID_LIST": "Existing mesh groups only",
    "MAX_BANDWIDTH": "Empty, or a positive rate such as 10M",
    "MESH_LISTENERS_PORT_RANGE": "Empty, or a port range such as 15000-15100",
}


def list_clients(state):
    """Clients tels que déclarés dans le fichier (SERVER_CLIENT)."""
    rows = copy.deepcopy(read_disk(state).get("SERVER_CLIENT", []))
    for c in rows:
        c["DYNAMIC"] = c.get("IP_ADDRESS") == DYNAMIC_IP
        c.setdefault("MESH_GROUP_UID_LIST", [])
        c["PINNED"] = bool(c.get("PUBLIC_KEY_SHA256"))
        c["OWN_TOKEN"] = bool(c.pop("TOKEN", None))  # jamais la valeur du jeton
        c["BEHIND_NAT"] = bool(c.get("BEHIND_NAT"))
        # NAT constaté à la dernière connexion : adresse vue par le serveur ≠ adresses du client
        c["NAT_DETECTED"] = getattr(state["dict_of_clients"].get(c["UID"]), "nat_detected", None)
    return rows


def create_client(state, values, actor, dry_run=False):
    cfg = read_disk(state)
    uid = str(values.get("UID", "")).strip()
    _raise(_client_field_errors(values, cfg, with_uid=True))
    if _find_by(cfg.get("SERVER_CLIENT", []), "UID", uid) is not None:
        raise OpError(409, f"Client '{uid}' already exists", {"UID": "This name is already used"})
    c = {"UID": uid}
    _apply_client_form(c, values)
    cfg.setdefault("SERVER_CLIENT", []).append(c)
    return dict(_commit(state, cfg, actor, "CREATE_CLIENT", f"Client '{uid}' created", dry_run), uid=uid)


def update_client(state, uid, values, actor, dry_run=False):
    cfg = read_disk(state)
    c = _find_by(cfg.get("SERVER_CLIENT", []), "UID", uid)
    if c is None:
        raise OpError(404, f"Client '{uid}' not found")
    _raise(_client_field_errors(values, cfg))
    left = _hub_groups_left(cfg, uid, _as_list(values.get("MESH_GROUP_UID_LIST")))
    if left:
        raise OpError(409, f"'{uid}' is a hub of {', '.join(left)}: choose another hub for it first",
                      {"MESH_GROUP_UID_LIST": f"Hub of {', '.join(left)}"})
    _apply_client_form(c, values)
    return dict(_commit(state, cfg, actor, "UPDATE_CLIENT", f"Client '{uid}' updated", dry_run), uid=uid)


def delete_client(state, uid, actor, dry_run=False):
    """Retire un client ; s'il est connecté, il est invité à se reconnecter et sera alors refusé."""
    cfg = read_disk(state)
    c = _find_by(cfg.get("SERVER_CLIENT", []), "UID", uid)
    if c is None:
        raise OpError(404, f"Client '{uid}' not found")
    left = _hub_groups_left(cfg, uid, [])
    if left:
        raise OpError(409, f"'{uid}' is a hub of {', '.join(left)}: choose another hub for it first")
    cfg["SERVER_CLIENT"].remove(c)
    return dict(_commit(state, cfg, actor, "DELETE_CLIENT", f"Client '{uid}' deleted", dry_run), uid=uid)


MAX_PREVIOUS_UIDS = 5


def rename_client(state, uid, values, actor, dry_run=False):
    """Renomme un client sans perdre son historique :
    - la configuration suit (hubs des mesh groups, adresses forcées des autres clients) ;
    - l'ancien nom reste reconnu (PREVIOUS_UIDS) : le client, même hors ligne pendant le renommage, est admis
      sous son nouveau nom à sa prochaine connexion et le reçoit (SET_UID) ;
    - les séries VictoriaMetrics sont réécrites sous le nouveau nom, en arrière-plan (journal d'audit)."""
    new = str(values.get("NEW_UID", "") or "").strip()
    cfg = read_disk(state)
    clients = cfg.get("SERVER_CLIENT", [])
    c = _find_by(clients, "UID", uid)
    if c is None:
        raise OpError(404, f"Client '{uid}' not found")
    if not new or new == uid or not validate_uid(new):
        raise OpError(400, "Invalid new name", {"NEW_UID": FIELD_MESSAGES["UID"] if new != uid else "Same name"})
    taken = next((o["UID"] for o in clients if o is not c and (o["UID"] == new or new in (o.get("PREVIOUS_UIDS") or []))),
                 None)
    if taken:
        raise OpError(409, f"'{new}' is already used by '{taken}'", {"NEW_UID": f"Used by '{taken}'"})
    c["UID"] = new
    c["PREVIOUS_UIDS"] = ([p for p in (c.get("PREVIOUS_UIDS") or []) if p not in (uid, new)] + [uid])[-MAX_PREVIOUS_UIDS:]
    for g in cfg.get("MESH_GROUP", []):
        if g.get("HUBS"):
            g["HUBS"] = [new if h == uid else h for h in g["HUBS"]]
    for other in clients:
        overrides = other.get("OVERRIDE_DST_NODE_IP")
        if isinstance(overrides, dict) and uid in overrides:
            overrides[new] = overrides.pop(uid)
    result = _commit(state, cfg, actor, "RENAME_CLIENT", f"Client '{uid}' renamed '{new}'", dry_run)
    history = []
    if not dry_run:
        # Le client connecté sous l'ancien nom reçoit le nouveau, l'écrit et se reconnecte
        # (en tête : avant la reconnexion demandée par _commit)
        state.setdefault("dict_of_commands_for_network_clients", {}).setdefault(uid, []).insert(
            0, {"ACTION": "SET_UID", "UID": new})
        objs = state.get("dict_of_clients")
        if objs is not None and uid in objs:  # l'état de connexion suit le client (sinon une ligne « fantôme »)
            obj = objs.pop(uid)
            obj.client_uid = new
            objs.setdefault(new, obj)
        history = _rename_history(state, cfg, uid, new, actor)
    return dict(result, uid=new, previous_uid=uid, history=history)


def _rename_history(state, cfg, old, new, actor):
    """Réécrit l'historique dans chaque base VictoriaMetrics ; renvoie leurs noms. Après un délai, pour que le client
    ait reçu son nouveau nom et que les points écrits sous l'ancien soient compris dans l'export."""
    dbs = [d for d in cfg.get("DATABASE", []) if str(d.get("DB_ENGINE", "")).lower() == "victoriametrics"]
    if not dbs:
        return []
    path = state["config_file_path"]

    def run():
        from lib.st_vm_admin import VmAdmin
        factory = state.get("vm_admin_factory", VmAdmin)
        for db in dbs:
            try:
                admin = factory(db)
                r = admin.rename_node(old, new)
                # Seconde passe : un client garde ses mesures en tampon ; celles prises sous l'ancien nom peuvent
                # arriver après la suppression des anciennes séries
                time.sleep(state.get("history_sweep_delay_s", 60) or 0)
                late = admin.rename_node(old, new, since_s=7200)
                store.log_event(path, actor, "RENAME_HISTORY",
                                f"History of '{old}' moved to '{new}' in {db['DB_UID']}: "
                                f"{r['points'] + late['points']} points")
            except Exception as exc:  # noqa: BLE001 - signalé dans l'audit, l'ancien historique reste en place
                store.log_event(path, actor, "RENAME_HISTORY_FAILED",
                                f"History of '{old}' not moved in {db.get('DB_UID')}: {type(exc).__name__}: {exc}")

    delay = state.get("history_rename_delay_s", 20)
    if delay is None:
        run()
    else:
        threading.Timer(delay, run).start()
    return [d["DB_UID"] for d in dbs]


# --------------------------------------------------------------------------- admission : approbation et jetons

def _enrollment(state):
    from lib.st_enrollment import Enrollment
    return Enrollment(state["config_file_path"] + ".pending.json")


def _drop_stale_requests(state, e):
    """Une demande d'admission d'un client déclaré depuis (fichier modifié, page Clients) est caduque : le client
    se connecte normalement. Seules restent, pour un client déclaré, les demandes de changement de clé."""
    declared = {c.get("UID") for c in read_disk(state).get("SERVER_CLIENT", [])}
    for p in e.pending():
        if p["UID"] in declared and not p.get("KEY_CHANGE"):
            e.take(p["UID"])


def list_pending(state):
    """Demandes d'admission en attente (sans la clé complète) et clients refusés."""
    e = _enrollment(state)
    _drop_stale_requests(state, e)
    pending = [{k: v for k, v in p.items() if k != "PUBLIC_KEY"} for p in e.pending()]
    return {"pending": pending, "rejected": e.rejected()}


def approve_client(state, uid, values, actor, dry_run=False):
    """Déclare un client en attente : sa clé est épinglée et un jeton propre est généré ; il lui est remis à sa
    prochaine tentative (il se présente encore avec le jeton partagé, sa clé prouve son identité)."""
    import secrets
    _drop_stale_requests(state, _enrollment(state))
    request = next((p for p in _enrollment(state).pending() if p["UID"] == uid), None)
    if request is None:
        raise OpError(404, f"No pending request for '{uid}'")
    cfg = read_disk(state)
    existing = _find_by(cfg.get("SERVER_CLIENT", []), "UID", uid)
    if request.get("KEY_CHANGE") and existing is not None:
        # Client déclaré qui s'est présenté avec une nouvelle clé : on ré-épingle, le reste de sa déclaration est gardé
        existing["PUBLIC_KEY_SHA256"] = request["PUBLIC_KEY_SHA256"]
        existing["TOKEN"] = secrets.token_urlsafe(32)
        result = _commit(state, cfg, actor, "APPROVE_KEY_CHANGE",
                         f"New key of client '{uid}' approved ({request['PUBLIC_KEY_SHA256'][:19]}…)", dry_run)
        if not dry_run:
            _enrollment(state).take(uid)
        return dict(result, uid=uid)
    if existing is not None:
        raise OpError(409, f"Client '{uid}' is already declared")
    dynamic = str(values.get("IP_MODE", "static")).lower() == "dynamic"
    form = {"IP_ADDRESS": DYNAMIC_IP if dynamic else request.get("IP_ADDRESS", ""),
            "MESH_GROUP_UID_LIST": values.get("MESH_GROUP_UID_LIST")}
    _raise(_client_field_errors(form, cfg))
    client = {"UID": uid}
    _apply_client_form(client, form)
    client["PUBLIC_KEY_SHA256"] = request["PUBLIC_KEY_SHA256"]
    client["TOKEN"] = secrets.token_urlsafe(32)
    cfg.setdefault("SERVER_CLIENT", []).append(client)
    result = _commit(state, cfg, actor, "APPROVE_CLIENT",
                     f"Client '{uid}' approved (key {request['PUBLIC_KEY_SHA256'][:19]}…)", dry_run)
    if not dry_run:
        _enrollment(state).take(uid)
    return dict(result, uid=uid)


def reject_client(state, uid, actor):
    _enrollment(state).reject(uid, actor)
    store.log_event(state["config_file_path"], actor, "REJECT_CLIENT", f"Client '{uid}' rejected")
    return {"uid": uid}


def forgive_client(state, uid, actor):
    _enrollment(state).forgive(uid)
    store.log_event(state["config_file_path"], actor, "FORGIVE_CLIENT", f"Client '{uid}' may ask again")
    return {"uid": uid}


def secure_client(state, uid, actor, dry_run=False):
    """Client déclaré à l'ancienne (jeton partagé, clé non épinglée) : épingle la clé de sa connexion actuelle et lui
    remet un jeton propre."""
    connected = state["dict_of_clients"].get(uid)
    fp = getattr(connected, "public_key_sha256", None)
    if not fp:
        raise OpError(409, f"Client '{uid}' must be connected once with this version so that its key is known")
    return _issue_token(state, uid, actor, dry_run, "SECURE_CLIENT", f"Client '{uid}' secured (key {fp[:19]}…)", pin=fp)


def rotate_client_token(state, uid, actor, dry_run=False):
    cfg = read_disk(state)
    c = _find_by(cfg.get("SERVER_CLIENT", []), "UID", uid)
    if c is None:
        raise OpError(404, f"Client '{uid}' not found")
    if not c.get("PUBLIC_KEY_SHA256"):
        raise OpError(409, f"Client '{uid}' must be secured first (pinned key), otherwise it could not recover a token "
                           f"rotated while it is offline")
    return _issue_token(state, uid, actor, dry_run, "ROTATE_CLIENT_TOKEN", f"Token of client '{uid}' rotated")


def _issue_token(state, uid, actor, dry_run, action, summary, pin=None):
    import secrets
    cfg = read_disk(state)
    c = _find_by(cfg.get("SERVER_CLIENT", []), "UID", uid)
    if c is None:
        raise OpError(404, f"Client '{uid}' not found")
    if pin:
        c["PUBLIC_KEY_SHA256"] = pin
    c["TOKEN"] = secrets.token_urlsafe(32)
    result = _commit(state, cfg, actor, action, summary, dry_run)
    if not dry_run:
        connected = state["dict_of_clients"].get(uid)
        if connected is not None and connected.status == "CONNECTED":
            state["dict_of_commands_for_network_clients"].setdefault(uid, []).append(
                {"ACTION": "SET_TOKEN", "TOKEN": c["TOKEN"]})
    return dict(result, uid=uid)


def _client_field_errors(values, cfg, with_uid=False):
    errors = {}
    if with_uid and not _ok(validate_uid, str(values.get("UID", "")).strip()):
        errors["UID"] = CLIENT_MESSAGES["UID"]
    if not _valid_host(str(values.get("IP_ADDRESS", "")).strip()):
        errors["IP_ADDRESS"] = CLIENT_MESSAGES["IP_ADDRESS"]
    known = {g["UID"] for g in cfg.get("MESH_GROUP", [])}
    if any(g not in known for g in _as_list(values.get("MESH_GROUP_UID_LIST"))):
        errors["MESH_GROUP_UID_LIST"] = CLIENT_MESSAGES["MESH_GROUP_UID_LIST"]
    max_bw = str(values.get("MAX_BANDWIDTH", "") or "").strip()
    if max_bw and not _ok(lambda x: validate_bandwidth(x) > 0, max_bw):
        errors["MAX_BANDWIDTH"] = CLIENT_MESSAGES["MAX_BANDWIDTH"]
    port_range = str(values.get("MESH_LISTENERS_PORT_RANGE", "") or "").strip()
    if port_range and not _valid_port_range(port_range):
        errors["MESH_LISTENERS_PORT_RANGE"] = CLIENT_MESSAGES["MESH_LISTENERS_PORT_RANGE"]
    return errors


def _apply_client_form(c, values):
    c["IP_ADDRESS"] = str(values.get("IP_ADDRESS", "")).strip()
    c["MESH_GROUP_UID_LIST"] = _as_list(values.get("MESH_GROUP_UID_LIST"))
    for key in ("MAX_BANDWIDTH", "MESH_LISTENERS_PORT_RANGE"):
        value = str(values.get(key, "") or "").strip()
        if value:
            c[key] = value
        else:
            c.pop(key, None)
    if "BEHIND_NAT" in values:  # absent d'un ancien appel : inchangé
        if _bool_text(values.get("BEHIND_NAT")):
            c["BEHIND_NAT"] = True
        else:
            c.pop("BEHIND_NAT", None)
    # Les autres clés (EXCLUDED_CLIENT_UID, OVERRIDE_DST_NODE_IP...) ne sont pas dans le formulaire : conservées.


def _validate_clients(cfg):
    clients = cfg.get("SERVER_CLIENT", [])
    uids = [c.get("UID") for c in clients]
    if len(uids) != len(set(uids)):
        raise OpError(409, "Client names must be unique")
    probe = copy.deepcopy(cfg)
    for c in probe.get("SERVER_CLIENT", []):
        if _client_field_errors(c, probe):
            raise OpError(422, f"Invalid declaration for client '{c.get('UID')}'")
        if "EXCLUDED_CLIENT_UID" in c and not validate_excluded_client(c, probe):
            raise OpError(422, f"EXCLUDED_CLIENT_UID of client '{c['UID']}' refers to an unknown client or group")
        if "OVERRIDE_DST_NODE_IP" in c and not validate_override_dst_node_ip(c, probe):
            raise OpError(422, f"OVERRIDE_DST_NODE_IP of client '{c['UID']}' is invalid")


def _live_clients(disk_clients, live, dynamic_uids):
    """Clients pour la config en mémoire : ceux du fichier, avec l'IP apprise des clients déjà dynamiques."""
    learned = {c["UID"]: c.get("IP_ADDRESS") for c in live.get("SERVER_CLIENT", [])}
    clients = copy.deepcopy(disk_clients)
    for c in clients:
        if (c.get("IP_ADDRESS") == DYNAMIC_IP and c["UID"] in dynamic_uids
                and learned.get(c["UID"]) not in (None, DYNAMIC_IP)):
            c["IP_ADDRESS"] = learned[c["UID"]]
    return clients


def _dynamic_uids(state):
    """Clients dynamiques du serveur (st_mesh.DYNAMIC_UIDS), ensemble partagé avec la boucle de contrôle."""
    if "dynamic_uids" not in state:
        try:
            from lib import st_mesh
            state["dynamic_uids"] = st_mesh.DYNAMIC_UIDS
        except Exception:  # noqa: BLE001 - hors serveur (outils, tests) : un ensemble local suffit
            state["dynamic_uids"] = set()
    return state["dynamic_uids"]


# ------------------------------------------------------------------------------------------------------- databases

DB_ENGINES = {"VICTORIAMETRICS": "VictoriaMetrics", "INFLUXDB2": "InfluxDB2"}
DB_OPTIONAL = ("DB_ORG", "DB_BUCKET", "DB_USE_WEB_PROXY", "DB_CONNECTION_POOL_MAXSIZE", "DB_RETENTION")
DB_NOT_CONNECTION = ("DB_RETENTION",)  # réglages qui ne demandent pas de recréer la connexion
DB_MESSAGES = {
    "DB_UID": FIELD_MESSAGES["UID"],
    "DB_ENGINE": "VictoriaMetrics or InfluxDB2",
    "DB_SERVER": "An IP address or a host name",
    "DB_PORT": "A port between 1 and 65534",
    "DB_TOKEN": "Required for InfluxDB2",
    "DB_ORG": "Required for InfluxDB2",
    "DB_BUCKET": "Required for InfluxDB2",
    "DB_USE_WEB_PROXY": "Empty, or a proxy URL such as http://proxy:3128",
    "DB_CONNECTION_POOL_MAXSIZE": "Empty, or a positive integer",
    "DB_RETENTION": "Empty, or a duration such as 30d, 12w or 1y",
}


def list_databases(state):
    """Bases déclarées, sans jamais renvoyer le jeton (DB_TOKEN_SET dit seulement s'il y en a un)."""
    rows = []
    for d in read_disk(state).get("DATABASE", []):
        row = {k: v for k, v in d.items() if k != "DB_TOKEN"}
        row["DB_TOKEN_SET"] = bool(d.get("DB_TOKEN"))
        rows.append(row)
    return rows


def create_database(state, values, actor, dry_run=False):
    cfg = read_disk(state)
    uid = str(values.get("DB_UID", "")).strip()
    _raise(_db_field_errors(values, None, with_uid=True))
    if _find_by(cfg.get("DATABASE", []), "DB_UID", uid) is not None:
        raise OpError(409, f"Database '{uid}' already exists", {"DB_UID": "This name is already used"})
    d = {"DB_UID": uid}
    _apply_db_form(d, values)
    cfg.setdefault("DATABASE", []).append(d)
    return dict(_commit(state, cfg, actor, "CREATE_DATABASE", f"Database '{uid}' created", dry_run), uid=uid)


def update_database(state, uid, values, actor, dry_run=False):
    cfg = read_disk(state)
    d = _find_by(cfg.get("DATABASE", []), "DB_UID", uid)
    if d is None:
        raise OpError(404, f"Database '{uid}' not found")
    _raise(_db_field_errors(values, d))
    _apply_db_form(d, values)
    return dict(_commit(state, cfg, actor, "UPDATE_DATABASE", f"Database '{uid}' updated", dry_run), uid=uid)


def delete_database(state, uid, actor, dry_run=False):
    cfg = read_disk(state)
    d = _find_by(cfg.get("DATABASE", []), "DB_UID", uid)
    if d is None:
        raise OpError(404, f"Database '{uid}' not found")
    cfg["DATABASE"].remove(d)
    return dict(_commit(state, cfg, actor, "DELETE_DATABASE", f"Database '{uid}' deleted", dry_run), uid=uid)


def test_database(state, values):
    """Ouvre une connexion d'essai avec ces paramètres, sans rien enregistrer : {"status": "ONLINE", ...}."""
    uid = str(values.get("DB_UID", "")).strip() or "CONNECTION_TEST"
    existing = _find_by(read_disk(state).get("DATABASE", []), "DB_UID", uid)
    _raise(_db_field_errors(values, existing))
    d = dict(copy.deepcopy(existing or {}), DB_UID=uid)
    _apply_db_form(d, values)
    probe = {"DATABASE": [d]}
    if not config_validation_database(probe):
        raise OpError(422, "Invalid database parameters (see the server log)")
    try:
        conn = _db_factory(state)(probe, uid)
    except Exception as exc:  # noqa: BLE001 - un pilote de base peut lever n'importe quoi
        return {"status": "ERROR", "message": f"{type(exc).__name__}: {exc}"}
    return {"status": getattr(conn, "status", "UNKNOWN")}


def _db_field_errors(values, existing, with_uid=False):
    keys = ("DB_UID", "DB_ENGINE", "DB_SERVER", "DB_PORT", "DB_TOKEN") + DB_OPTIONAL
    v = {k: str(values.get(k, "") or "").strip() for k in keys}
    errors = {}
    if with_uid and not _ok(validate_uid, v["DB_UID"]):
        errors["DB_UID"] = DB_MESSAGES["DB_UID"]
    engine = DB_ENGINES.get(v["DB_ENGINE"].upper())
    if engine is None:
        errors["DB_ENGINE"] = DB_MESSAGES["DB_ENGINE"]
    if not _valid_host(v["DB_SERVER"]):
        errors["DB_SERVER"] = DB_MESSAGES["DB_SERVER"]
    if not (v["DB_PORT"].isdigit() and 1 <= int(v["DB_PORT"]) <= 65534):
        errors["DB_PORT"] = DB_MESSAGES["DB_PORT"]
    if engine == "InfluxDB2":
        has_token = bool(v["DB_TOKEN"]) or (_token_may_follow(existing, values)
                                            and not _truthy(values.get("DB_TOKEN_CLEAR")))
        if not has_token:
            errors["DB_TOKEN"] = DB_MESSAGES["DB_TOKEN"]
        for key in ("DB_ORG", "DB_BUCKET"):
            if not v[key]:
                errors[key] = DB_MESSAGES[key]
    if v["DB_USE_WEB_PROXY"] and not re.match(r"^https?://[^\s:/]+(:\d+)?/?$", v["DB_USE_WEB_PROXY"]):
        errors["DB_USE_WEB_PROXY"] = DB_MESSAGES["DB_USE_WEB_PROXY"]
    pool = v["DB_CONNECTION_POOL_MAXSIZE"]
    if pool and not (pool.isdigit() and int(pool) > 0):
        errors["DB_CONNECTION_POOL_MAXSIZE"] = DB_MESSAGES["DB_CONNECTION_POOL_MAXSIZE"]
    if v["DB_RETENTION"] and parse_retention(v["DB_RETENTION"]) is None:
        errors["DB_RETENTION"] = DB_MESSAGES["DB_RETENTION"]
    return errors


def _db_endpoint(d):
    """Où part le jeton : adresse, port, TLS et mandataire."""
    return (str(d.get("DB_SERVER", "")).strip().lower(), str(d.get("DB_PORT", "")).strip(),
            bool(_truthy(d.get("DB_SERVER_USE_SSL"))), str(d.get("DB_USE_WEB_PROXY", "") or "").strip())


def _token_may_follow(existing, values):
    """Le jeton enregistré n'est gardé que vers la même adresse : sinon il partirait vers l'hôte choisi par
    l'appelant (test de connexion, modification)."""
    return bool((existing or {}).get("DB_TOKEN")) and _db_endpoint(existing) == _db_endpoint(values)


def _apply_db_form(d, values):
    keep_token = _token_may_follow(d, values)
    d["DB_ENGINE"] = DB_ENGINES[str(values.get("DB_ENGINE", "")).strip().upper()]
    d["DB_SERVER"] = str(values.get("DB_SERVER", "")).strip()
    d["DB_PORT"] = str(values.get("DB_PORT", "")).strip()
    d["DB_SERVER_USE_SSL"] = _truthy(values.get("DB_SERVER_USE_SSL"))
    token = str(values.get("DB_TOKEN", "") or "").strip()
    if token:
        d["DB_TOKEN"] = token  # laissé vide : le jeton enregistré est gardé, vers la même adresse seulement
    elif _truthy(values.get("DB_TOKEN_CLEAR")) or not keep_token:
        d.pop("DB_TOKEN", None)
    for key in DB_OPTIONAL:
        value = str(values.get(key, "") or "").strip()
        if value:
            d[key] = value
        else:
            d.pop(key, None)
    if d["DB_ENGINE"] == "InfluxDB2":
        d.setdefault("DB_CONNECTION_POOL_MAXSIZE", "100")


def _db_connection_params(d):
    return None if d is None else {k: v for k, v in d.items() if k not in DB_NOT_CONNECTION}


def _db_factory(state):
    factory = state.get("db_factory")
    if factory is None:
        from lib.st_db_factory import make_db_connection
        factory = make_db_connection
    return factory


def _rebuild_connections(state, live, recreated):
    """Met à jour la liste des connexions, partagée avec le thread serveur : garde celles qui n'ont pas changé."""
    conn_db = state.get("conn_db")
    if conn_db is None:
        return
    existing = {getattr(c, "DB_UID", None): c for c in conn_db}
    rebuilt = []
    for d in live.get("DATABASE", []):
        uid = d["DB_UID"]
        if uid in recreated or uid not in existing:
            try:
                rebuilt.append(_db_factory(state)(live, uid))
            except Exception as exc:  # noqa: BLE001
                log.error(f"DATABASE '{uid}': CONNECTION COULD NOT BE CREATED: {type(exc).__name__}:{exc}")
        else:
            rebuilt.append(existing[uid])
    conn_db[:] = rebuilt


_RETENTION_RE = re.compile(r"^(\d+)([hdwy])$", re.IGNORECASE)
_RETENTION_HOURS = {"h": 1, "d": 24, "w": 24 * 7, "y": 24 * 365}


def parse_retention(value):
    """Durée au format -retentionPeriod de VictoriaMetrics (48h, 30d, 12w, 1y ; un nombre seul compte en mois),
    convertie en heures. None si invalide."""
    value = str(value or "").strip()
    if value.isdigit():
        return int(value) * 24 * 31 if int(value) > 0 else None
    m = _RETENTION_RE.match(value)
    if not m or int(m.group(1)) == 0:
        return None
    return int(m.group(1)) * _RETENTION_HOURS[m.group(2).lower()]


# ---------------------------------------------------------------------------------------------------- utilitaires

def _raise(errors):
    if errors:
        raise OpError(400, "Some fields are invalid", errors)


def _ok(check, value):
    try:
        with _quiet():
            return bool(value) and bool(check(value))
    except Exception:  # noqa: BLE001 - les fonctions de validation lèvent parfois sur une entrée invalide
        return False


def _truthy(value):
    return value is True or str(value).strip().lower() in ("true", "1", "yes", "on")


def _as_list(value):
    if value is None or value == "":
        return []
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return [str(x).strip() for x in value if str(x).strip()]


def _valid_host(value):
    if not value:
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(re.match(r"^[A-Za-z0-9.-]+$", value)) and FQDN(value).is_valid


def _valid_port_range(value):
    m = re.match(r"^(\d+)-(\d+)$", value)
    return bool(m) and 1 <= int(m.group(1)) < int(m.group(2)) <= 65534


def _find_by(items, key, uid):
    return next((i for i in items if i.get(key) == uid), None)


# -------------------------------------------------------------------------------------------------------- versions

def restore(state, version, actor, dry_run=False):
    """Revient à une version gardée du fichier. Mesh groups, clients et bases de données sont appliqués à chaud ;
    les autres sections (SERVER, GLOBAL) sont écrites mais demandent un redémarrage du serveur."""
    try:
        text = store.read_version(state["config_file_path"], version)
    except KeyError:
        raise OpError(404, f"Version '{version}' not found")
    try:
        target = toml.loads(text)
    except toml.TomlDecodeError as exc:
        raise OpError(422, f"Version '{version}' is not valid TOML: {exc}")
    result = _commit(state, target, actor, "RESTORE_CONFIG", f"Configuration restored to version {version}", dry_run)
    return dict(result, version=version)


# --------------------------------------------------------------------------------------------------------- interne

def _commit(state, disk_cfg, actor, action, summary, dry_run):
    live = state["config"]
    old_disk = read_disk(state)
    groups = copy.deepcopy(disk_cfg.get("MESH_GROUP", []))
    profiles = copy.deepcopy(disk_cfg.get("IPERF3_PROFILE", []))
    if not validate_group(dict(live, MESH_GROUP=groups, IPERF3_PROFILE=profiles,
                               SERVER_CLIENT=copy.deepcopy(disk_cfg.get("SERVER_CLIENT", []))), "MESH_GROUP"):
        raise OpError(422, "Invalid mesh group parameters (see the server log)")

    # Clients : remplacés seulement si leur déclaration a changé ; l'IP apprise d'un client dynamique est gardée.
    old_clients = {c["UID"]: c for c in old_disk.get("SERVER_CLIENT", [])}
    new_clients = {c["UID"]: c for c in disk_cfg.get("SERVER_CLIENT", [])}
    changed_clients = {u for u in set(old_clients) | set(new_clients) if old_clients.get(u) != new_clients.get(u)}
    live_clients = live.get("SERVER_CLIENT", [])
    if changed_clients:
        _validate_clients(disk_cfg)
        live_clients = _live_clients(disk_cfg.get("SERVER_CLIENT", []), live, _dynamic_uids(state))

    # Bases de données : connexion recréée pour chaque base ajoutée ou dont les paramètres de connexion changent.
    old_dbs = {d["DB_UID"]: d for d in old_disk.get("DATABASE", [])}
    new_dbs = {d["DB_UID"]: d for d in disk_cfg.get("DATABASE", [])}
    recreated = [u for u in new_dbs if _db_connection_params(old_dbs.get(u)) != _db_connection_params(new_dbs[u])]
    live_dbs = None
    if old_dbs != new_dbs:
        live_dbs = copy.deepcopy(disk_cfg.get("DATABASE", []))
        if not config_validation_database({"DATABASE": live_dbs}):
            raise OpError(422, "Invalid database parameters (see the server log)")

    probe_live = dict(copy.deepcopy({k: v for k, v in live.items() if k != "SERVER"}),
                      SERVER=dict(live.get("SERVER", {})), MESH_GROUP=copy.deepcopy(groups),
                      SERVER_CLIENT=copy.deepcopy(live_clients))
    _apply_live_server(probe_live, old_disk, disk_cfg)
    scratch = {}
    try:
        _, tuples = generate_client_config_mesh(probe_live, scratch)
    except PortExhausted as exc:
        raise OpError(409, f"Not applied: {exc}")
    except (SystemExit, Exception) as exc:  # noqa: BLE001 - sys.exit() quand un client dépasse son MAX_BANDWIDTH
        log.error(f"{action} REFUSED, CLIENT CONFIG GENERATION FAILED: {type(exc).__name__}:{exc}")
        raise OpError(409, "Not applied: a client would exceed its MAX_BANDWIDTH, or the client configuration "
                           "could not be generated (see the server log)")

    current = state["_dict_by_node_generated_config"]
    sent_changed = any(old_disk.get("GLOBAL", {}).get(k, d) != disk_cfg.get("GLOBAL", {}).get(k, d)
                       for k, d in GLOBAL_SENT_TO_CLIENTS)
    everyone = set(new_clients) if sent_changed else set()  # ces réglages leur parviennent à la reconnexion
    affected = sorted({uid for uid in set(current) | set(scratch) if _edges(current.get(uid)) != _edges(scratch.get(uid))}
                      | changed_clients | everyone)
    assessment = st_capacity.assess(st_capacity.measure(current), st_capacity.measure(scratch),
                                    st_capacity.limits(disk_cfg.get("SERVER", {})))
    if assessment["violations"]:
        raise OpError(409, "Not applied: " + "; ".join(assessment["violations"]) + _hub_suggestion(disk_cfg))
    impact = _impact(assessment)
    if impact["alert"] and not dry_run and not CONFIRMED.get():
        raise OpError(428, f"Large change ({impact['alert_reason']}): review it and confirm explicitly")
    old_text = _read_text(state["config_file_path"])
    new_text = toml.dumps(disk_cfg)
    result = {"impact": impact, "message": summary, "diff": store.redacted_diff(old_text, new_text), "affected_clients": affected,
              "reconnected_clients": [], "recreated_databases": recreated,
              "restart_required": _restart_keys(old_disk, disk_cfg), "dry_run": dry_run}
    if dry_run:
        return result

    try:
        entry = store.save_text(state["config_file_path"], new_text, actor, action, summary)
    except OSError as exc:
        log.error(f"{action} NOT APPLIED, UNABLE TO WRITE THE CONFIGURATION FILE: {exc}")
        raise OpError(500, f"Not applied: unable to write the configuration file ({exc})")

    # Sur place : les autres threads gardent une référence à ces listes.
    _apply_live_server(live, old_disk, disk_cfg)
    _apply_live_global(live, old_disk, disk_cfg)
    live["MESH_GROUP"][:] = groups
    live.setdefault("IPERF3_PROFILE", [])[:] = profiles
    if changed_clients:
        live.setdefault("SERVER_CLIENT", [])[:] = live_clients
        dynamic = _dynamic_uids(state)
        dynamic.clear()
        dynamic.update(c["UID"] for c in disk_cfg.get("SERVER_CLIENT", []) if c.get("IP_ADDRESS") == DYNAMIC_IP)
        for uid in [u for u in current if u not in new_clients]:
            current.pop(uid, None)  # client retiré : plus de config générée pour lui
    _, state["_dict_by_group_of_generated_tuple_for_map"] = generate_client_config_mesh(live, current)
    if live_dbs is not None:
        live.setdefault("DATABASE", [])[:] = live_dbs
        _rebuild_connections(state, live, recreated)

    for uid in affected:
        client = state["dict_of_clients"].get(uid)
        if client is not None and client.status == "CONNECTED":
            state["dict_of_commands_for_network_clients"].setdefault(uid, []).append({"ACTION": "RECONNECT_CLIENT"})
            result["reconnected_clients"].append(uid)
    try:  # les tableaux de bord suivent tout de suite (flux retirés, rôles)
        st_flow_catalog.PUBLISHER.maybe(live, current, state.get("conn_db"), force=True)
    except Exception as exc:  # noqa: BLE001
        log.error(f"EXPECTED FLOWS NOT PUBLISHED: {type(exc).__name__}:{exc}")
    log.info(f"{action} BY {actor}: {summary}; RECONNECTING {result['reconnected_clients']}; "
             f"RECREATED DATABASE CONNECTIONS {recreated}")
    return dict(result, version=entry["version"])


def _apply_topology(cfg, g, values):
    """Topologie du formulaire (MESH par défaut) ; un hub qui n'est pas encore membre du groupe le rejoint."""
    topology = str(values.get("TOPOLOGY", "") or "MESH").strip().upper()
    hubs = _as_list(values.get("HUBS")) if topology != "MESH" else []
    probe = {"TOPOLOGY": topology, "HUBS": hubs}
    _raise(st_topology.errors(probe, [c["UID"] for c in cfg.get("SERVER_CLIENT", [])]))
    if topology == "MESH":
        g.pop("TOPOLOGY", None)
        g.pop("HUBS", None)
        return
    g["TOPOLOGY"], g["HUBS"] = topology, hubs
    for hub in hubs:
        client = _find_by(cfg.get("SERVER_CLIENT", []), "UID", hub)
        if g["UID"] not in client.setdefault("MESH_GROUP_UID_LIST", []):
            client["MESH_GROUP_UID_LIST"].append(g["UID"])


def _hub_groups_left(cfg, uid, new_groups):
    """Groupes dont le client est hub et qu'il quitterait."""
    return [g["UID"] for g in cfg.get("MESH_GROUP", []) if uid in (g.get("HUBS") or []) and g["UID"] not in new_groups]


def _impact(assessment):
    """Résumé de l'impact d'un changement, pour l'aperçu."""
    before, after = assessment["before"], assessment["after"]
    busiest = assessment["busiest"]
    entry = after["clients"].get(busiest) if busiest else None
    return {"flows_before": before["total_flows"], "flows_after": after["total_flows"],
            "added_flows": assessment["added_flows"],
            "points_per_s_before": before["points_per_s"], "points_per_s_after": after["points_per_s"],
            "busiest": dict(entry, uid=busiest) if entry else None,
            "alert": assessment["alert"], "alert_reason": assessment["alert_reason"], "limits": assessment["limits"]}


def _hub_suggestion(cfg):
    """Pour les grands groupes en maillage complet : ce que donnerait une topologie à deux hubs."""
    hints = []
    for g in cfg.get("MESH_GROUP", []):
        n = len(_members(cfg, g["UID"]))
        if st_topology.topology(g) == "MESH" and n >= 6 and not g.get("DISABLED"):
            hints.append(f"{g['UID']} ({n} members): {n * (n - 1)} flows as a full mesh, "
                         f"{st_topology.flow_count({'TOPOLOGY': 'DUAL_HUB'}, n)} with a dual hub")
    return (". Consider a hub topology: " + "; ".join(hints)) if hints else ""


def _edges(generated):
    """Flux d'un client dans la config générée. send_config y ajoute CLIENT et GLOBAL à chaque connexion : ces clés
    ne disent rien d'un changement de mesh group."""
    generated = generated or {}
    return {k: generated.get(k) or {} for k in ("LISTENERS", "CONNECTORS")}


def _apply_form(g, values):
    for k in EDITABLE_FIELDS:
        value = str(values.get(k, "") or "").strip()
        if value:
            g[k] = value
        else:
            g.pop(k, None)  # seulement possible avec un profil, qui fournit alors la valeur
    g.pop("PACKET_PER_SECOND", None)  # le formulaire fixe le débit et la taille : le 3e est recalculé
    for key in ("DESCRIPTION", "IPERF3_PROFILE"):
        value = str(values.get(key, "") or "").strip()
        if value:
            g[key] = value
        else:
            g.pop(key, None)


def _raise_on_field_errors(values, with_uid=False, optional=False):
    errors = field_errors(values, with_uid, optional)
    if errors:
        raise OpError(400, "Some fields are invalid", errors)


def _find(cfg, uid):
    return next((g for g in cfg.get("MESH_GROUP", []) if g["UID"] == uid), None)


def _require(cfg, uid):
    g = _find(cfg, uid)
    if g is None:
        raise OpError(404, f"Mesh group '{uid}' not found")
    return g


def _members(cfg, uid):
    return [c["UID"] for c in cfg.get("SERVER_CLIENT", []) if uid in c.get("MESH_GROUP_UID_LIST", [])]


def _read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""

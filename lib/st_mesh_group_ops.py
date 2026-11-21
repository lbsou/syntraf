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
import copy
import logging

import toml

from lib import st_config_store as store
from lib.st_conf_validation import (validate_bandwidth, validate_dscp, validate_packet_size, validate_interval,
                                    validate_uid, validate_group, generate_client_config_mesh)

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
    """Mesh groups tels qu'écrits dans le fichier, avec le nombre de membres et le débit sortant par membre."""
    cfg = read_disk(state)
    groups = copy.deepcopy(cfg.get("MESH_GROUP", []))
    for g in groups:
        g["MEMBERS"] = len(_members(cfg, g["UID"]))
        n = g["MEMBERS"]
        g["BW_PER_NODE_KBPS"] = (n * (n - 1) * validate_bandwidth(g["BANDWIDTH"]) / n / 1000) if n else 0
        g["DISABLED"] = g.get("DISABLED", False) is True
    return groups


def get_group(state, uid):
    for g in list_groups(state):
        if g["UID"] == uid:
            return g
    raise OpError(404, f"Mesh group '{uid}' not found")


def field_errors(values, with_uid=False):
    """Erreurs par champ du formulaire : {"BANDWIDTH": "message", ...} (vide si tout est valide)."""
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
        try:
            ok = bool(v[name]) and check(v[name])
        except Exception:  # noqa: BLE001 - les fonctions de validation lèvent parfois sur une entrée invalide
            ok = False
        if not ok:
            errors[name] = FIELD_MESSAGES[name]
    return errors


# ----------------------------------------------------------------------------------------------------- mesh groups

def create(state, values, actor, dry_run=False):
    uid = str(values.get("UID", "")).strip()
    _raise_on_field_errors(values, with_uid=True)
    cfg = read_disk(state)
    if _find(cfg, uid) is not None:
        raise OpError(409, f"Mesh group '{uid}' already exists", {"UID": "This name is already used"})
    new = {"UID": uid}
    _apply_form(new, values)
    cfg["MESH_GROUP"].append(new)
    return dict(_commit(state, cfg, actor, "CREATE_MESH_GROUP", f"Mesh group '{uid}' created", dry_run), uid=uid)


def update(state, uid, values, actor, dry_run=False):
    _raise_on_field_errors(values)
    cfg = read_disk(state)
    g = _require(cfg, uid)
    _apply_form(g, values)
    return dict(_commit(state, cfg, actor, "UPDATE_MESH_GROUP", f"Mesh group '{uid}' updated", dry_run), uid=uid)


def set_disabled(state, uid, disabled, actor, dry_run=False):
    cfg = read_disk(state)
    g = _require(cfg, uid)
    if disabled:
        g["DISABLED"] = True
    else:
        g.pop("DISABLED", None)
    verb = "disabled" if disabled else "enabled"
    action = "DISABLE_MESH_GROUP" if disabled else "ENABLE_MESH_GROUP"
    return dict(_commit(state, cfg, actor, action, f"Mesh group '{uid}' {verb}", dry_run), uid=uid)


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
    cfg["MESH_GROUP"].append(clone)
    result = _commit(state, cfg, actor, "DUPLICATE_MESH_GROUP", f"Mesh group '{uid}' duplicated as '{new_uid}'",
                     dry_run)
    return dict(result, uid=new_uid)


def save_map(state, uid, cyto_json, actor):
    cfg = read_disk(state)
    _require(cfg, uid)["WEBUI_JSON"] = cyto_json
    return _commit(state, cfg, actor, "SAVE_MAP", f"Map of mesh group '{uid}' saved", False)


# -------------------------------------------------------------------------------------------------------- versions

def restore(state, version, actor, dry_run=False):
    """Revient à une version gardée du fichier. Les mesh groups sont appliqués à chaud ; les autres sections
    (clients, bases de données, réglages globaux) sont écrites mais demandent un redémarrage du serveur."""
    try:
        text = store.read_version(state["config_file_path"], version)
    except KeyError:
        raise OpError(404, f"Version '{version}' not found")
    try:
        target = toml.loads(text)
    except toml.TomlDecodeError as exc:
        raise OpError(422, f"Version '{version}' is not valid TOML: {exc}")
    current = read_disk(state)
    restart_required = any(target.get(k) != current.get(k) for k in set(target) | set(current) if k != "MESH_GROUP")
    result = _commit(state, target, actor, "RESTORE_CONFIG", f"Configuration restored to version {version}", dry_run)
    return dict(result, restart_required=restart_required, version=version)


# --------------------------------------------------------------------------------------------------------- interne

def _commit(state, disk_cfg, actor, action, summary, dry_run):
    live = state["config"]
    groups = copy.deepcopy(disk_cfg.get("MESH_GROUP", []))
    if not validate_group(dict(live, MESH_GROUP=groups), "MESH_GROUP"):
        raise OpError(422, "Invalid mesh group parameters (see the server log)")

    scratch = {}
    try:
        _, tuples = generate_client_config_mesh(dict(copy.deepcopy(live), MESH_GROUP=copy.deepcopy(groups)), scratch)
    except (SystemExit, Exception) as exc:  # noqa: BLE001 - sys.exit() quand un client dépasse son MAX_BANDWIDTH
        log.error(f"{action} REFUSED, CLIENT CONFIG GENERATION FAILED: {type(exc).__name__}:{exc}")
        raise OpError(409, "Not applied: a client would exceed its MAX_BANDWIDTH, or the client configuration "
                           "could not be generated (see the server log)")

    current = state["_dict_by_node_generated_config"]
    affected = sorted(uid for uid in set(current) | set(scratch) if _edges(current.get(uid)) != _edges(scratch.get(uid)))
    old_text = _read_text(state["config_file_path"])
    new_text = toml.dumps(disk_cfg)
    result = {"message": summary, "diff": store.redacted_diff(old_text, new_text), "affected_clients": affected,
              "reconnected_clients": [], "dry_run": dry_run}
    if dry_run:
        return result

    try:
        entry = store.save_text(state["config_file_path"], new_text, actor, action, summary)
    except OSError as exc:
        log.error(f"{action} NOT APPLIED, UNABLE TO WRITE THE CONFIGURATION FILE: {exc}")
        raise OpError(500, f"Not applied: unable to write the configuration file ({exc})")

    live["MESH_GROUP"][:] = groups  # sur place : les autres threads gardent une référence à cette liste
    _, state["_dict_by_group_of_generated_tuple_for_map"] = generate_client_config_mesh(live, current)
    for uid in affected:
        client = state["dict_of_clients"].get(uid)
        if client is not None and client.status == "CONNECTED":
            state["dict_of_commands_for_network_clients"].setdefault(uid, []).append({"ACTION": "RECONNECT_CLIENT"})
            result["reconnected_clients"].append(uid)
    log.info(f"{action} BY {actor}: {summary}; RECONNECTING {result['reconnected_clients']}")
    return dict(result, version=entry["version"])


def _edges(generated):
    """Flux d'un client dans la config générée. send_config y ajoute CLIENT et GLOBAL à chaque connexion : ces clés
    ne disent rien d'un changement de mesh group."""
    generated = generated or {}
    return {k: generated.get(k) or {} for k in ("LISTENERS", "CONNECTORS")}


def _apply_form(g, values):
    for k in EDITABLE_FIELDS:
        g[k] = str(values.get(k, "")).strip()
    g.pop("PACKET_PER_SECOND", None)  # le formulaire fixe le débit et la taille : le 3e est recalculé
    description = str(values.get("DESCRIPTION", "") or "").strip()
    if description:
        g["DESCRIPTION"] = description
    else:
        g.pop("DESCRIPTION", None)


def _raise_on_field_errors(values, with_uid=False):
    errors = field_errors(values, with_uid)
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

"""Admission des clients : clé publique épinglée, jeton propre à chaque client, demandes en attente d'approbation.

Règles (authorize) :
  - client déclaré avec une clé épinglée (PUBLIC_KEY_SHA256) : la clé présentée doit être la même ;
  - client déclaré avec son propre jeton (TOKEN) : il doit présenter ce jeton. Exception : si sa clé épinglée
    correspond et qu'il présente un jeton partagé, il est accepté et son jeton lui est remis (remise initiale,
    ou rattrapage d'une rotation faite pendant son absence). La clé prouve l'identité ;
  - client déclaré sans jeton propre (ancien fonctionnement) : un jeton partagé suffit ;
  - nom inconnu présentant un jeton partagé : demande enregistrée « en attente », refus jusqu'à approbation ;
  - nom refusé par un administrateur : refusé jusqu'à ce qu'il soit pardonné.

Les demandes et les refus sont gardés dans un fichier JSON à côté du fichier de configuration.
"""
import collections
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
import threading

MAX_PENDING = 200
SAFE_UID = re.compile(r"^[A-Za-z0-9_-]{4,50}$")
Decision = collections.namedtuple("Decision", "accepted reason deliver_token")
_locks = collections.defaultdict(threading.Lock)


def fingerprint(public_key):
    return "sha256:" + hashlib.sha256(str(public_key or "").strip().encode()).hexdigest()


def authorize(config, payload, ip, enrollment):
    uid = str(payload.get("CLIENT_UID") or "")
    token = str(payload.get("TOKEN") or "")
    key = payload.get("PUBLIC_KEY") or ""
    shared = set((config.get("SERVER", {}).get("TOKEN") or {}).values())
    client = next((c for c in config.get("SERVER_CLIENT", []) if c.get("UID") == uid), None)

    if client is not None:
        pinned = client.get("PUBLIC_KEY_SHA256")
        if pinned and fingerprint(key) != pinned:
            # Nouvelle clé (réinstallation ?) avec un jeton valide : demande de changement de clé à approuver
            if enrollment is not None and (token == client.get("TOKEN") or token in shared):
                enrollment.record(uid, ip, key, payload.get("SYNTRAF_CLIENT_VERSION", ""), key_change=True)
            return Decision(False, "KEY MISMATCH", None)
        own = client.get("TOKEN")
        if own:
            if token == own:
                return Decision(True, "", None)
            if pinned and token in shared:
                return Decision(True, "", own)
            return Decision(False, "INVALID TOKEN", None)
        return Decision(True, "", None) if token in shared else Decision(False, "INVALID TOKEN", None)

    if enrollment is not None and enrollment.is_rejected(uid):
        return Decision(False, "REJECTED", None)
    if token in shared and SAFE_UID.match(uid) and enrollment is not None:
        enrollment.record(uid, ip, key, payload.get("SYNTRAF_CLIENT_VERSION", ""))
        return Decision(False, "PENDING APPROVAL", None)
    return Decision(False, "UNKNOWN CLIENT", None)


class Enrollment:
    """Demandes en attente et refus, dans un fichier JSON (source de vérité partagée par le serveur et la webui)."""

    def __init__(self, path):
        self.path = path

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, ValueError):
            data = {}
        return {"pending": data.get("pending", {}), "rejected": data.get("rejected", {})}

    def _save(self, data):
        directory = os.path.dirname(os.path.abspath(self.path))
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".pending-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, self.path)

    @staticmethod
    def _now():
        return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    def record(self, uid, ip, public_key, version, key_change=False):
        with _locks[self.path]:
            data = self._load()
            p = data["pending"].get(uid)
            fp = fingerprint(public_key)
            if p is None:
                if len(data["pending"]) >= MAX_PENDING:
                    return  # liste pleine : on n'en accepte pas davantage (protection contre l'inondation)
                p = {"UID": uid, "FIRST_SEEN": self._now(), "ATTEMPTS": 0, "KEY_CHANGED": False}
            elif p.get("PUBLIC_KEY_SHA256") != fp:
                p["KEY_CHANGED"] = True  # deux appareils (ou une réinstallation) pour le même nom : à vérifier
            p.update({"IP_ADDRESS": ip, "PUBLIC_KEY": public_key, "PUBLIC_KEY_SHA256": fp, "VERSION": version,
                      "LAST_SEEN": self._now(), "ATTEMPTS": p["ATTEMPTS"] + 1, "KEY_CHANGE": key_change})
            data["pending"][uid] = p
            self._save(data)

    def pending(self):
        return sorted(self._load()["pending"].values(), key=lambda p: p["FIRST_SEEN"])

    def rejected(self):
        return sorted(self._load()["rejected"].values(), key=lambda r: r["UID"])

    def is_rejected(self, uid):
        return uid in self._load()["rejected"]

    def take(self, uid):
        """Retire et renvoie une demande (approbation)."""
        with _locks[self.path]:
            data = self._load()
            p = data["pending"].pop(uid, None)
            if p is not None:
                self._save(data)
            return p

    def reject(self, uid, actor):
        with _locks[self.path]:
            data = self._load()
            p = data["pending"].pop(uid, {"UID": uid})
            data["rejected"][uid] = {"UID": uid, "REJECTED_AT": self._now(), "REJECTED_BY": actor,
                                     "IP_ADDRESS": p.get("IP_ADDRESS"), "PUBLIC_KEY_SHA256": p.get("PUBLIC_KEY_SHA256")}
            self._save(data)

    def forgive(self, uid):
        with _locks[self.path]:
            data = self._load()
            if data["rejected"].pop(uid, None) is not None:
                self._save(data)

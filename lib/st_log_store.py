"""Côté serveur : journaux reçus des clients, un dossier par client sous LOGDIR/clients/<UID>/, avec rotation par
taille et nombre de fichiers (comme les journaux du serveur) et purge des fichiers plus vieux que la rétention."""
import datetime as dt
import os
import re
import threading
import time

CLIENTS_DIR = "clients"
FILENAME = "syntraf.log"
SAFE_UID = re.compile(r"^[A-Za-z0-9_-]{1,50}$")
_lock = threading.Lock()


def client_dir(logdir, uid):
    return os.path.join(logdir, CLIENTS_DIR, uid)


def append(logdir, uid, lines, dropped, max_bytes, backups):
    """Ajoute les lignes reçues d'un client à son journal ; une ligne signale celles qu'il a dû abandonner."""
    if not SAFE_UID.match(uid or "") or not logdir:
        return
    if dropped:
        stamp = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S%z")
        lines = [f" {stamp} - WARNING - st_log_store (append,0) - {dropped} log line(s) dropped by the client "
                 f"(buffer full while the server was unreachable)"] + list(lines)
    if not lines:
        return
    directory = client_dir(logdir, uid)
    path = os.path.join(directory, FILENAME)
    text = "".join(contained(line) for line in lines)
    with _lock:
        os.makedirs(directory, exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) + len(text.encode()) > max_bytes:
            _rotate(path, backups)
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


def contained(line):
    """Une ligne reçue, sur une ou plusieurs lignes (trace d'exception) : seule la première peut commencer une
    entrée ; les suivantes sont décalées (deux espaces) pour rester des lignes de suite et ne jamais être lues
    comme une entrée forgée (autre niveau, autre module)."""
    first, *rest = str(line).rstrip("\n").split("\n")
    return "".join([first + "\n"] + ["  " + r.lstrip("\r") + "\n" for r in rest])


def _rotate(path, backups):
    for i in range(backups - 1, 0, -1):
        src, dst = f"{path}.{i}", f"{path}.{i + 1}"
        if os.path.exists(src):
            os.replace(src, dst)
    if backups >= 1:
        os.replace(path, f"{path}.1")
    else:
        os.remove(path)


def purge_older_than(logdir, days, now=None):
    """Supprime les fichiers de journal (du serveur et des clients) modifiés il y a plus de `days` jours.
    Un fichier courant (syntraf.log) n'est jamais supprimé. Renvoie les chemins supprimés."""
    if not days or not logdir or not os.path.isdir(logdir):
        return []
    limit = (now or time.time()) - float(days) * 86400
    removed = []
    for root, _, files in os.walk(logdir):
        for name in files:
            if name == FILENAME or not name.startswith(FILENAME):
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getmtime(path) < limit:
                    os.remove(path)
                    removed.append(path)
            except OSError:
                continue
    return removed

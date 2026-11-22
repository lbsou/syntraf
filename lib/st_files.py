"""Fichiers secrets (clés privées, configuration avec jetons, versions, identifiants iperf3) : lisibles par le seul
propriétaire (0600), y compris quand le fichier existait déjà avec des droits plus larges.
Bibliothèque standard uniquement."""
import os


def open_private(path, mode="w", encoding="utf-8"):
    """Comme open(path, mode) en écriture, avec les droits 0600 (sans effet de droits sous Windows)."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if "a" in mode else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        os.chmod(path, 0o600)  # O_CREAT ne change pas les droits d'un fichier existant
    except OSError:
        pass
    if "b" in mode:
        return os.fdopen(fd, mode)
    return os.fdopen(fd, mode, encoding=encoding)


def private_paths(config, config_file_path):
    """Fichiers secrets connus d'une installation : configuration, ses versions, clés privées, identifiants."""
    paths = [config_file_path, config_file_path + ".access.json", config_file_path + ".secret_key",
             config_file_path + ".pending.json"]
    history = config_file_path + ".history"
    if os.path.isdir(history):
        paths += [os.path.join(history, n) for n in os.listdir(history)]
    for section, key in (("SERVER", "SERVER_X509_PRIVATE_KEY"), ("CLIENT", "CLIENT_X509_PRIVATE_KEY")):
        value = (config.get(section) or {}).get(key)
        if isinstance(value, str):
            paths.append(value)
    rsa_dir = (config.get("GLOBAL") or {}).get("IPERF3_RSA_KEY_DIRECTORY")
    if isinstance(rsa_dir, str) and os.path.isdir(rsa_dir):
        paths += [os.path.join(rsa_dir, n) for n in os.listdir(rsa_dir) if n.startswith("private") or
                  n.endswith((".csv", ".json"))]
    return paths


def tighten(paths):
    """Ramène à 0600 les fichiers existants (installations antérieures) ; renvoie ceux qui ont changé."""
    changed = []
    for path in paths:
        try:
            if os.path.isfile(path) and os.stat(path).st_mode & 0o077:
                os.chmod(path, 0o600)
                changed.append(path)
        except OSError:
            pass
    return changed

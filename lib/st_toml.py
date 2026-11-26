"""Écriture TOML sûre pour les textes libres.

toml 0.10.2 échappe les chaînes avec repr() puis retouche le résultat : une barre oblique inverse suivie de « x »
(« C:\\Users\\xavier ») devient une séquence d'échappement réservée et le fichier ne se relit plus ; les
caractères de contrôle sont altérés sans erreur. Ce module garde l'encodeur de toml et remplace seulement
l'écriture des chaînes par l'échappement de la spécification TOML (chaîne de base entre guillemets).
"""
import toml

_SHORT = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def dump_str(value):
    """Chaîne de base TOML qui se relit à l'identique."""
    out = []
    for ch in value:
        if ch in _SHORT:
            out.append(_SHORT[ch])
        elif ch < " " or ch == "\x7f":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


class _Encoder(toml.TomlEncoder):
    def __init__(self):
        super().__init__()
        self.dump_funcs[str] = dump_str


def dumps(config):
    """Comme toml.dumps, avec des chaînes correctement échappées."""
    return toml.dumps(config, encoder=_Encoder())


def dump(config, file):
    """Comme toml.dump, avec des chaînes correctement échappées."""
    file.write(dumps(config))

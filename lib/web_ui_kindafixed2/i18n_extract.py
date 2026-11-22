"""Textes de l'interface à traduire : extraits des gabarits, du JavaScript et des messages de l'API.

    python -m lib.web_ui_kindafixed2.i18n_extract            # textes sans traduction française
    python -m lib.web_ui_kindafixed2.i18n_extract --all      # tous les textes

Le traducteur du navigateur (static/js/st_i18n.js) remplace chaque nœud de texte (et title, placeholder, aria-label)
dont le contenu est une clé du dictionnaire (static/i18n/fr.json) ; « {0} », « {1} »… y désignent des valeurs
variables (nom d'un client, nombre...). lab/tests/test_i18n.py vérifie que chaque texte extrait est traduit.
"""
import html.parser
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATES = HERE / "templates"
SCRIPTS = [HERE / "static" / "js" / "st_app.js", HERE / "static" / "js" / "st_crud.js"]
PYTHON = [HERE / "st_api_v1.py", HERE.parent / "st_mesh_group_ops.py", HERE.parent / "st_capacity.py",
          HERE.parent / "st_syslog.py", HERE / "st_auth.py"]
DICTIONARY = HERE / "static" / "i18n" / "fr.json"
# Pages de l'ancienne interface, non servies par la navigation actuelle
SKIP = {"login2.html", "map.html", "maps.html", "config.html", "global_config.html", "users_config.html"}
ATTRS = ("title", "placeholder", "aria-label", "data-bs-title", "alt")
WORD = re.compile(r"[A-Za-z]{2,}")
FRENCH = re.compile(r"[éèàùçêâîôûœ«»]|\b(les|des|une|est|pour|dans|avec|sans)\b")
SHORT_WORDS = {"live", "restart", "dynamic", "none", "default", "disabled", "secured"}


def _clean(text):
    return " ".join(text.split())


def _numbered(text):
    """${...} ou {...} → {0}, {1}..."""
    n = [0]

    def repl(_m):
        n[0] += 1
        return "{" + str(n[0] - 1) + "}"
    return repl


def _is_ui_text(text, code=True):
    """Texte destiné à l'utilisateur (et non un sélecteur, une URL, une clé de configuration, un journal...).
    code=False : texte d'un gabarit HTML, où un point-virgule est de la ponctuation et non du JavaScript."""
    if not text or not WORD.search(text) or len(text) > 400:
        return False
    if FRENCH.search(text):  # docstring ou commentaire en français
        return False
    letters = [c for c in text if c.isalpha()]
    if len(letters) > 8 and sum(c.isupper() for c in letters) / len(letters) > 0.6:  # message de journal
        return False
    if re.fullmatch(r"[a-z0-9 .:{}-]+", text) and re.search(r"[a-z]-[a-z0-9{]|\.bs\.|^use strict$", text):
        return False  # classes CSS, événements
    if re.fullmatch(r"[A-Z0-9_]+(\.[A-Z0-9_]+)?", text):  # clé de configuration (LOG_LEVEL, GLOBAL.LOG_TO)
        return False
    if re.fullmatch(r"[\w./-]+", text) and not re.fullmatch(r"[A-Z][a-z]+", text):  # identifiant, chemin
        return text in SHORT_WORDS
    if text.startswith(("/", "#", ".", "http", "fa-", "fas ", "btn", "col-", "bg-", "text-", "form-", "d-", "st-")):
        return False
    if re.search(r"[=<>]|=>|\(\)|' \+|\+ '", text) or (code and ";" in text):
        return False
    # Fragments d'expressions JS (ternaires imbriqués) : leurs textes complets sont ajoutés à la main au dictionnaire
    if re.search(r"\$\{|\)\.join|^['):]|'\s*:\s*'|'\}$", text):
        return False
    return True


class _Text(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.found, self._skip = set(), 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "code", "pre"):
            self._skip += 1
        for name, value in attrs:
            if name in ATTRS and value:
                self._add(value)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "code", "pre") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self._add(data)

    def _add(self, text):
        text = _clean(re.sub(r"\{\{.*?\}\}|\{%.*?%\}", " {0} ", text))
        text = _clean(re.sub(r"(\{0\}\s*){2,}", " {0} ", text))
        text = re.sub(r"^(\{0\}\s*)+|(\s*\{0\})+$", "", text).strip()
        if _is_ui_text(text.replace("{0}", ""), code=False):
            self.found.add(text)


def _template_literal_texts(literal):
    """Segments de texte d'un gabarit JS (`...${x}...`) : les ${...} deviennent {0}, {1}... ; balises retirées."""
    out = []
    for part in re.split(r"<[^>]+>", literal):
        text = _clean(re.sub(r"\$\{(?:[^{}]|\{[^{}]*\})*\}", _numbered(part), part))
        text = re.sub(r"^[\s·,;:()]+|[\s,;:(]+$", "", text) if text.startswith(("·", ",", "(")) else text
        if text and not re.fullmatch(r"[\s{}\d·]*", text) and _is_ui_text(re.sub(r"\{\d+\}", "", text)):
            out.append(text)
    return out


def _js_texts(source):
    found = set()
    source = re.sub(r"^\s*//.*$", "", source, flags=re.M)
    for m in re.finditer(r"`((?:[^`\\]|\\.)*)`", source, re.S):
        found.update(_template_literal_texts(m.group(1)))
    stripped = re.sub(r"`(?:[^`\\]|\\.)*`", "``", source, flags=re.S)
    for m in re.finditer(r'"((?:[^"\\\n]|\\.)*)"|\'((?:[^\'\\\n]|\\.)*)\'', stripped):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        if "<" in raw:
            found.update(_template_literal_texts(raw))
            continue
        text = _clean(raw.replace("\\'", "'").replace('\\"', '"'))
        if _is_ui_text(text) and (" " in text or re.fullmatch(r"[A-Z][a-z]+…?", text) or text in SHORT_WORDS):
            found.add(text)
    return found


def _python_texts(source):
    """Messages renvoyés par l'API et affichés dans l'interface (erreurs, champs, résumés)."""
    found = set()
    source = re.sub(r'"""(?:.|\n)*?"""', "", source)
    source = re.sub(r"_op\((?:[^()]|\([^()]*\))*\)", "", source)  # descriptions OpenAPI : pas dans l'interface
    source = re.sub(r"^\s*#.*$", "", source, flags=re.M)
    for m in re.finditer(r'(f?)"((?:[^"\\\n]|\\.)*)"', source):
        is_f, raw = m.group(1), m.group(2)
        if not re.match(r"[A-Z]", raw) or " " not in raw:
            continue
        if is_f:
            raw = re.sub(r"\{[^{}]*\}", _numbered(raw), raw)
        text = _clean(raw)
        if _is_ui_text(re.sub(r"\{\d+\}", "", text)) and not text.endswith(":"):
            found.add(text)
    return found


def extract():
    texts = set()
    for page in sorted(TEMPLATES.glob("*.html")):
        if page.name in SKIP:
            continue
        source = page.read_text(encoding="utf-8")
        parser = _Text()
        parser.feed(re.sub(r"<script\b.*?</script>", "", source, flags=re.S))
        texts |= parser.found
        # Arguments des expressions Jinja : menu ({% set nav = [...] %}), macros (page_header, field(help=...))
        for block in re.findall(r"\{\{(.*?)\}\}|\{%(.*?)%\}", source, flags=re.S):
            for text in re.findall(r'"([^"\n]+)"', "".join(block)):
                text = _clean(text)
                if _is_ui_text(text, code=False) and (" " in text or re.fullmatch(r"[A-Z][a-z]+", text)):
                    texts.add(text)
        for script in re.findall(r"<script\b[^>]*>(.*?)</script>", source, flags=re.S):
            texts |= _js_texts(script)
    for script in SCRIPTS:
        texts |= _js_texts(script.read_text(encoding="utf-8"))
    for module in PYTHON:
        texts |= _python_texts(module.read_text(encoding="utf-8"))
    return sorted(texts)


def dictionary():
    return json.loads(DICTIONARY.read_text(encoding="utf-8")) if DICTIONARY.exists() else {}


def missing():
    fr = dictionary()
    return [t for t in extract() if t not in fr]


if __name__ == "__main__":
    for text in (extract() if "--all" in sys.argv else missing()):
        print(text)

"""Langue de l'interface (lib/web_ui_kindafixed2/static/js/st_i18n.js, static/i18n/fr.json) : chaque texte de
l'interface a sa traduction française, et les traductions gardent leurs valeurs variables. Sans dépendance.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import importlib.util  # noqa: E402

# Chargé par son chemin : importer le paquet de la webui demanderait Flask
_spec = importlib.util.spec_from_file_location("i18n_extract", ROOT / "lib/web_ui_kindafixed2/i18n_extract.py")
i18n_extract = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(i18n_extract)

PLACEHOLDER = re.compile(r"\{\d+\}")


def test_every_interface_text_has_a_french_translation():
    missing = i18n_extract.missing()
    assert missing == [], "À traduire dans static/i18n/fr.json :\n" + "\n".join(missing)


def test_translations_keep_their_values():
    for en, fr in i18n_extract.dictionary().items():
        assert fr.strip(), en
        # une traduction peut omettre une valeur (accord), jamais en inventer une
        assert set(PLACEHOLDER.findall(fr)) <= set(PLACEHOLDER.findall(en)), en


def test_every_page_loads_the_translator_and_offers_the_choice():
    base = (ROOT / "lib/web_ui_kindafixed2/templates/base.html").read_text(encoding="utf-8")
    assert "js/st_i18n.js" in base and 'id="st-lang"' in base
    assert base.index("st_i18n.js") < base.index("st_app.js")  # avant les autres scripts : pas d'anglais furtif

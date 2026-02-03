"""
Internationalization (i18n) module for SYNTRAF WebUI
Supports English and French languages
"""

import json
import os
import logging

log = logging.getLogger("syntraf." + __name__)

# Default language
DEFAULT_LANGUAGE = 'en'
SUPPORTED_LANGUAGES = ['en', 'fr']

# Translation dictionaries
_translations = {}


def load_translations(app_root_dir):
    """Load all translation files from the translations directory."""
    global _translations

    translations_dir = os.path.join(app_root_dir, 'lib', 'web_ui_kindafixed2', 'translations')

    for lang in SUPPORTED_LANGUAGES:
        file_path = os.path.join(translations_dir, f'{lang}.json')
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    _translations[lang] = json.load(f)
                log.info(f"Loaded translations for language: {lang}")
            else:
                log.warning(f"Translation file not found: {file_path}")
                _translations[lang] = {}
        except Exception as e:
            log.error(f"Error loading translations for {lang}: {e}")
            _translations[lang] = {}


def get_locale():
    """Get the current locale from session or browser preferences."""
    from flask import session, request, has_request_context

    # Check if we're in a request context
    if not has_request_context():
        return DEFAULT_LANGUAGE

    try:
        # Check session first
        if 'language' in session:
            lang = session['language']
            if lang in SUPPORTED_LANGUAGES:
                return lang

        # Check browser Accept-Language header
        if request:
            best_match = request.accept_languages.best_match(SUPPORTED_LANGUAGES)
            if best_match:
                return best_match
    except Exception:
        pass

    return DEFAULT_LANGUAGE


def set_locale(language):
    """Set the current locale in session."""
    from flask import session
    if language in SUPPORTED_LANGUAGES:
        session['language'] = language
        return True
    return False


def translate(key, default=None, **kwargs):
    """
    Translate a key to the current locale.

    Args:
        key: The translation key (e.g., 'nav.home', 'buttons.save')
        default: Default value if key not found (defaults to key itself)
        **kwargs: Format arguments for string interpolation

    Returns:
        Translated string
    """
    lang = get_locale()
    translations = _translations.get(lang, {})

    # Support nested keys with dot notation
    keys = key.split('.')
    value = translations

    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        else:
            value = None
            break

    if value is None:
        # Fallback to English if not found in current language
        if lang != 'en':
            en_translations = _translations.get('en', {})
            value = en_translations
            for k in keys:
                if isinstance(value, dict):
                    value = value.get(k)
                else:
                    value = None
                    break

    if value is None:
        value = default if default is not None else key

    # String interpolation
    if kwargs and isinstance(value, str):
        try:
            value = value.format(**kwargs)
        except KeyError:
            pass

    return value


def get_translations_for_template():
    """Get all translations for the current locale (for JavaScript use)."""
    lang = get_locale()
    return _translations.get(lang, _translations.get('en', {}))


def get_current_language():
    """Get the current language code."""
    return get_locale()


def get_language_name(lang_code):
    """Get the display name for a language code."""
    names = {
        'en': 'English',
        'fr': 'Français'
    }
    return names.get(lang_code, lang_code)


def init_app(app, app_root_dir):
    """Initialize i18n for a Flask application."""
    load_translations(app_root_dir)

    log.info(f"i18n initialized with {len(_translations)} languages")

    # Make translation function available in templates using Jinja globals
    app.jinja_env.globals['_'] = translate
    app.jinja_env.globals['t'] = translate
    app.jinja_env.globals['get_locale'] = get_locale
    app.jinja_env.globals['get_language_name'] = get_language_name
    app.jinja_env.globals['supported_languages'] = SUPPORTED_LANGUAGES

    # Also register as context processor for dynamic values
    @app.context_processor
    def inject_i18n():
        return {
            'current_language': get_current_language(),
        }

    # Add language switching endpoint
    @app.route('/set_language/<lang>')
    def set_language(lang):
        from flask import redirect, request
        set_locale(lang)
        # Redirect back to the referring page or home
        return redirect(request.referrer or '/')

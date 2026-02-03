import os
import secrets
from dotenv import load_dotenv
from lib.st_global import DefaultValues

load_dotenv(os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, '.env'))

class Config(object):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    EXPLAIN_TEMPLATE_LOADING = False
    # Use environment variable or generate a secure random key
    # WARNING: If SECRET_KEY is generated, sessions will be invalidated on restart
    SECRET_KEY = os.getenv("SECRET_KEY") or secrets.token_hex(32)
    # CSRF protection settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour token validity

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True
    SESSION_PROTECTION = "basic"
    FLASK_ENV = "development"

class ProductionConfig(Config):
    DEBUG = False
    SESSION_PROTECTION = "strong"
    FLASK_ENV = "production"
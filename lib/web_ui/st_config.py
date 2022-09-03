import os
from dotenv import load_dotenv
from lib.st_global import DefaultValues

load_dotenv(os.path.join(DefaultValues.SYNTRAF_ROOT_DIR, '.env'))

class Config(object):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    EXPLAIN_TEMPLATE_LOADING = False
    SECRET_KEY = os.getenv("SECRET_KEY")

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = True
    SESSION_PROTECTION = "basic"
    FLASK_ENV = "development"

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_PROTECTION = "strong"
    FLASK_ENV = "production"
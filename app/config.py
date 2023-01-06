# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
from decouple import config


class Config(object):

    SECRET_KEY = config("SECRET_KEY")

    # Celery
    broker_url = config("CELERY_BROKER_URL", default="redis://localhost:6379/0")
    result_backend = config("RESULT_BACKEND", default="redis://localhost:6379/0")

    SQLALCHEMY_TRACK_MODIFICATIONS = False


class ProductionConfig(Config):
    DEBUG = False

    # Security
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_DURATION = 3600

    # PostgreSQL database for Production
    SQLALCHEMY_DATABASE_URI = "{}://{}:{}@{}:{}/{}".format(
        config("DB_ENGINE", default="postgresql"),
        config("DB_USERNAME", default="grepmarx"),
        config("DB_PASS", default="changeme"),
        config("DB_HOST", default="localhost"),
        config("DB_PORT", default=5432),
        config("DB_NAME", default="grepmarx"),
    )


class DebugConfig(Config):
    DEBUG = True
    # SQLITE database for Debug (this will create a file in <app> FOLDER)
    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "db.sqlite3")


# Load all possible configurations
config_dict = {"Production": ProductionConfig, "Debug": DebugConfig}

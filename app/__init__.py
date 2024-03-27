# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""

from importlib import import_module

from celery import Celery
from flask import Flask
from flask_ldap3_login import LDAP3LoginManager
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# load the extension

db = SQLAlchemy()
login_manager = LoginManager()
ldap_manager = LDAP3LoginManager()

# Instantiate Celery
celery = Celery(__name__)


def register_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)
    ldap_manager.app = app


def register_blueprints(app):
    for module_name in ("base", "administration", "analysis", "rules", "projects"):
        module = import_module("app.{}.routes".format(module_name))
        app.register_blueprint(module.blueprint)


def configure_database(app):
    with app.app_context():
        db.create_all()

    def initialize_database():
        db.create_all()

    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()
        

def create_app(config):

    # Init app and config
    app = Flask(__name__, static_folder="base/static")
    app.config.from_object(config)
    
    # Configure Celery
    celery.config_from_object(config)
    celery.conf.update(app.config)

    # Register modules
    register_extensions(app)
    register_blueprints(app)

    # Configure DB
    configure_database(app)
    Migrate(app=app, db=db, compare_type=True)

    return app


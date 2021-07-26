# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from celery import Celery
from importlib import import_module

db = SQLAlchemy()
login_manager = LoginManager()
# Instantiate Celery
celery = Celery(__name__, broker='redis://localhost:6379/0', result_backend='redis://localhost:6379/0')

def register_extensions(app):
    db.init_app(app)
    login_manager.init_app(app)

def register_blueprints(app):
    for module_name in ('base', 'administration', 'analysis', 'rules', 'projects'):
        module = import_module('grepmarx.{}.routes'.format(module_name))
        app.register_blueprint(module.blueprint)

def configure_database(app):

    @app.before_first_request
    def initialize_database():
        db.create_all()

    @app.teardown_request
    def shutdown_session(exception=None):
        db.session.remove()

def create_app(config):
    app = Flask(__name__, static_folder='base/static')
    app.config.from_object(config)
    # Configure celery
    celery.conf.update(app.config)
    register_extensions(app)
    register_blueprints(app)
    configure_database(app)
    return app

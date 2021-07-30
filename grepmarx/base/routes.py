# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""

from datetime import datetime

from grepmarx import db, login_manager
import grepmarx
from grepmarx.base import blueprint
from grepmarx.base.forms import LoginForm
from grepmarx.base.models import User
from grepmarx.base.util import verify_pass
from grepmarx.rules.model import SupportedLanguage
from flask import current_app, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from is_safe_url import is_safe_url


@blueprint.route('/')
def route_default():
    return redirect(url_for('base_blueprint.login'))

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:
        # read form data
        username = request.form['username']
        password = request.form['password']
        # Locate user
        user = User.query.filter_by(username=username).first()
        # Check the password
        if user and verify_pass(password, user.password):
            user.last_login_on = datetime.now()
            db.session.commit()
            login_user(user)
            current_app.logger.info("Authentication successful (user.id=%i)", user.id)
            return redirect(url_for('base_blueprint.route_default'))
        # Something (user or pass) is not ok
        current_app.logger.info("Authentication failure (username was '%s')", username)
        return render_template('login.html', msg='Wrong user or password', form=login_form)
    if not current_user.is_authenticated:
        return render_template('login.html',
                               form=login_form)
    return redirect(url_for('base_blueprint.index'))

@blueprint.route('/logout')
def logout():
    current_app.logger.info("User logged out (user.id=%i)", current_user.id)
    logout_user()
    return redirect(url_for('base_blueprint.login'))


@blueprint.route("/switch-theme")
def switch_theme():
    user = User.query.filter_by(id=session["_user_id"]).first()
    user.dark_theme = not user.dark_theme
    db.session.commit()
    if is_safe_url(request.referrer, {request.host}):
        ret = redirect(request.referrer)
    else:
        ret = redirect(url_for("base_blueprint.route_default"))
    return ret

@blueprint.route("/dashboard")
@login_required
def index():
    return render_template('dashboard.html', segment='dashboard')

@blueprint.route("/init")
def init():
    db.session.add(User(username="admin", email="admin@grepmarx",
                        password="admin"))
    db.session.add(SupportedLanguage(name="Python", extensions=".py"))
    db.session.add(
        SupportedLanguage(
            name="C", extensions=".cpp,.c++,.cxx,.hpp,.hh,.h++,.hxx,.c,.cc,.h"
        )
    )
    db.session.add(SupportedLanguage(
        name="JavaScript", extensions=".js,.htm,.html"))
    db.session.add(SupportedLanguage(
        name="TypeScript", extensions=".ts,.html"))
    db.session.add(SupportedLanguage(name="JSON", extensions=".json"))
    db.session.add(
        SupportedLanguage(
            name="PHP",
            extensions=".php,.php3,.php4,.php5,.php5.6,.phtm,.phtml,.tpl,.ctp,.twig",
        )
    )
    db.session.add(
        SupportedLanguage(
            name="Java",
            extensions=".javasln,.project,.java,.jsp,.jspf,.tag,.tld,.hbs,.properties",
        )
    )
    db.session.add(SupportedLanguage(name="Go", extensions=".go"))
    db.session.add(SupportedLanguage(name="OCaml", extensions=".ml,.mli"))
    db.session.add(
        SupportedLanguage(name="Ruby", extensions=".rb,.rhtml,.rxml,.rjs,.erb")
    )
    db.session.add(SupportedLanguage(name="Kotlin", extensions=".kt,.kts"))
    db.session.add(SupportedLanguage(name="Generic", extensions=""))
    db.session.commit()
    return "done", 200

# Errors


@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template('page-403.html'), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template('page-403.html'), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template('page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('page-500.html'), 500

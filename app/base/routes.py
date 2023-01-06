# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""


from datetime import datetime
from operator import concat
from os import path
from is_safe_url import is_safe_url
from ldap3 import Server, Connection, Tls,ALL
import ssl

from flask import (current_app, redirect, render_template, request, session,
                   url_for)
from flask_login import current_user, login_required, login_user, logout_user
from app import db, login_manager
from app.base import blueprint
from app.constants import AUTH_LDAP,AUTH_LOCAL, PROJECTS_SRC_PATH, RULES_PATH
from app.base.forms import LoginForm
from app.base.models import User
from app.administration.models import LdapConf
from app.base.util import (init_db, last_12_months_analysis_count, remove_dir_content,
                                verify_pass)
from app.projects.models import Project
from app.rules.models import Rule, RulePack, RuleRepository

@blueprint.route("/")
def route_default():
    # Init DB if first launch (eg. no user yet registered)
    if db.session.query(User).count() == 0:
        init_db()
        # Also remove projects and rules repo in data/ (if any)
        if(path.exists(PROJECTS_SRC_PATH)):
            remove_dir_content(PROJECTS_SRC_PATH)
        if(path.exists(RULES_PATH)):
            remove_dir_content(RULES_PATH)
    return redirect(url_for("base_blueprint.login"))


@blueprint.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm(request.form)
    if "login" in request.form:
        # read form data
        username = request.form["username"]
        password = request.form["password"]
        if request.form.get('ldap'):
            ldap_conf = LdapConf.query.first()
            ldap_server = ldap_conf.url
            ldap_search = ldap_conf.search_base
            user ="uid="+username+","
            all = concat(user, ldap_search)
            tls = Tls(ciphers='ALL', validate = ssl.CERT_REQUIRED,ca_certs_file = '/opt/grepmarx/ldap-cert/ca.crt')
            server = Server(ldap_search, port=636, use_ssl=True, get_info=ALL, tls=tls)
            c = Connection(server, user=all, password=password, auto_bind=True)
            test = c.bind()
            if test == True:
                
                user = User.query.filter_by(username=username,local=AUTH_LDAP).first()

                if user :
                    db.session.commit()
                    login_user(user)
                    current_app.logger.info("Authentication successful (user.id=%i)", user.id)
                    return redirect(url_for("base_blueprint.route_default"))
                else :
                    user = User(
                            username=username,
                            local = False,
                        )
                    db.session.add(user)
                    db.session.commit()
                    current_app.logger.info("New user configuration added (user.id=%i)", user.id)
                    login_user(user)
                    current_app.logger.info("Authentication successful (user.id=%i)", user.id)
                    return redirect(url_for("base_blueprint.route_default"))
            
            else:
                current_app.logger.info(
                "Authentication failure (username was '%s')", username)
                return render_template(
                    "login.html", msg="Wrong user or password", form=login_form
                    )
        # Locate user
        else :
            user = User.query.filter_by(username=username,local=AUTH_LOCAL).first()
            # Check the password
            if user and verify_pass(password, user.password):
                user.last_login_on = datetime.now()
                db.session.commit()
                login_user(user)
                current_app.logger.info("Authentication successful (user.id=%i)", user.id)
                return redirect(url_for("base_blueprint.route_default"))
            # Something (user or pass) is not ok
            current_app.logger.info("Authentication failure (username was '%s')", username)
            return render_template(
                "login.html", msg="Wrong user or password", form=login_form
            )
    if not current_user.is_authenticated:
        return render_template("login.html", form=login_form)
    return redirect(url_for("base_blueprint.index"))


@blueprint.route("/logout")
def logout():
    current_app.logger.info("User logged out (user.id=%i)", current_user.id)
    logout_user()
    return redirect(url_for("base_blueprint.login"))


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
    return render_template(
        "dashboard.html",
        nb_projects=Project.query.count(),
        nb_rules=Rule.query.count(),
        nb_rule_packs=RulePack.query.count(),
        nb_repos=RuleRepository.query.count(),
        analysis_per_month=last_12_months_analysis_count(),
        user=current_user,
        segment="dashboard",
    )


# Errors


@login_manager.unauthorized_handler
def unauthorized_handler():
    return render_template("page-403.html"), 403


@blueprint.errorhandler(403)
def access_forbidden(error):
    return render_template("page-403.html"), 403


@blueprint.errorhandler(404)
def not_found_error(error):
    return render_template("page-404.html"), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template("page-500.html"), 500

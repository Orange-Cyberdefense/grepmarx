# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""

import ssl
from datetime import datetime
from os import path

from app import db, ldap_manager, login_manager
from app.administration.models import LdapConfiguration
from app.administration.util import validate_user_form
from app.base import blueprint, util
from app.base.forms import LoginForm, CreateUserForm, CreateTeamForm
from app.base.models import User, Team
from app.base.util import (init_db, last_12_months_analysis_count,
                           ldap_config_dict, remove_dir_content, verify_pass)
from app.constants import (AUTH_LDAP, AUTH_LOCAL, PROJECTS_SRC_PATH, ROLE_ADMIN,
                           ROLE_GUEST, ROLE_USER, RULES_PATH)
from app.projects.models import Project
from app.rules.models import Rule, RulePack, RuleRepository
from flask import (current_app, redirect, render_template, request, session,
                   url_for, flash)
from flask_login import current_user, login_required, login_user, logout_user
from is_safe_url import is_safe_url
from ldap3 import Tls


@blueprint.route("/")
def route_default():
    # Init DB if first launch (eg. no user yet registered)
    if db.session.query(User).count() == 0:
        init_db()
        # Also remove projects and rules repo in data/ (if any)
        if path.exists(PROJECTS_SRC_PATH):
            remove_dir_content(PROJECTS_SRC_PATH)
        if path.exists(RULES_PATH):
            remove_dir_content(RULES_PATH)
        #return to welcome page to create an account
        return redirect(url_for("base_blueprint.welcome"))
    return redirect(url_for("base_blueprint.login"))


@blueprint.route("/welcome", methods=["GET", "POST"])
def welcome():
    user_form = CreateUserForm(request.form)
    if "username" in request.form:
        #Form is valid
        error = validate_user_form(user_form)
        #Check if data isn't already used
        if error is not None:
            flash(error, "error")
            return render_template("welcome.html", error=error, form=user_form)
        # We can create the user
        user = User(**request.form)
        user.role = ROLE_ADMIN
        db.session.add(user)
        db.session.commit()
        current_app.logger.info("New user added (user.id=%i)", user.id)
        flash("New user successfully added", "success")
        return redirect(url_for("base_blueprint.login"))
    else:
        #invalid form
        return render_template("welcome.html", form=user_form)

@blueprint.route("/login", methods=["GET", "POST"])
def login():
    login_form = LoginForm(request.form)
    # Flag if LDAP is configured
    ldap_config = LdapConfiguration.query.first()
    ldap_activated = (
        True if ldap_config is not None and ldap_config.ldap_activated else False
    )
    if "login" in request.form:
        # read form data
        username = request.form["username"]
        password = request.form["password"]
        # LDAP user
        if request.form.get("ldap"):
            if not ldap_activated:
                # No LDAP config in DB, return an error
                current_app.logger.info(
                    "LDAP authentication is not enabled (username was '%s')", username
                )
                return render_template(
                    "login.html",
                    msg="LDAP authentication is not enabled",
                    form=login_form,
                )
            # Define TLS context if encryption is enabled
            if ldap_config.use_tls:
                tls = Tls(
                    ciphers="ALL",
                    validate=ssl.CERT_REQUIRED,
                    ca_certs_file=ldap_config.cacert_path,
                )
            else:
                tls = None
            # LDAP server setup
            ldap_manager.add_server(
                ldap_config.server_host,
                ldap_config.server_port,
                ldap_config.use_tls,
                tls_ctx=tls,
            )
            # Init the LDAP manager with the config
            ldap_manager.init_config(ldap_config_dict())
            # Check if the credentials are correct
            response = ldap_manager.authenticate(username, password)
            # LDAP auth failed
            if response.status.value != 2:
                current_app.logger.info(
                    "LDAP Authentication failure (username was '%s')", username
                )
                return render_template(
                    "login.html",
                    msg="LDAP authentication failed",
                    form=login_form,
                    ldap_activated=ldap_activated,
                )
            user = User.query.filter_by(username=username, local=AUTH_LDAP).first()
            # LDAP user already exists in DB
            if user:
                # User is not approved (guest)
                if user.role == ROLE_GUEST:
                    current_app.logger.info(
                        "Guest user authenticated (user.id=%i)", user.id
                    )
                    return render_template(
                        "login.html",
                        msg="Your account is pending administrator approval",
                        form=login_form,
                        ldap_activated=ldap_activated,
                    )
                else:
                    login_user(user)
                    current_app.logger.info(
                        "LDAP authentication successful (user.id=%i)", user.id
                    )
                    return redirect(url_for("base_blueprint.route_default"))
            # Create a new LDAP user in DB
            else:
                user = User(
                    username=username,
                    first_name=response.user_info["givenName"][0],
                    last_name=response.user_info["sn"][0],
                    email=response.user_info["mail"][0],
                    # If user approval is enabled, set the guest role
                    role=ROLE_GUEST if ldap_config.users_approval else ROLE_USER,
                    local=AUTH_LDAP,
                )
                db.session.add(user)
                db.session.commit()
                current_app.logger.info(
                    "New user configuration added (user.id=%i)", user.id
                )
                # Login only if admin approval is not required
                if not ldap_config.users_approval:
                    login_user(user)
                    current_app.logger.info(
                        "Authentication successful (user.id=%i)", user.id
                    )
                    return redirect(url_for("base_blueprint.route_default"))
                else:
                    return render_template(
                        "login.html",
                        msg="Your account is pending administrator approval",
                        form=login_form,
                    )
        # Local user
        else:
            user = User.query.filter_by(username=username, local=AUTH_LOCAL).first()
            # Check the password
            if user and verify_pass(password, user.password):
                user.last_login_on = datetime.now()
                db.session.commit()
                login_user(user)
                current_app.logger.info(
                    "Authentication successful (user.id=%i)", user.id
                )
                return redirect(url_for("base_blueprint.route_default"))
            # Something (user or pass) is not ok
            current_app.logger.info(
                "Authentication failure (username was '%s')", username
            )
            return render_template(
                "login.html",
                msg="Wrong user or password",
                form=login_form,
                ldap_activated=ldap_activated,
            )
    if not current_user.is_authenticated:
        return render_template(
            "login.html", form=login_form, ldap_activated=ldap_activated
        )
    return redirect(url_for("base_blueprint.index"))


@blueprint.route("/logout")
def logout():
    current_app.logger.info("User logged out (user.id=%i)", current_user.id)
    logout_user()
    return redirect(url_for("base_blueprint.login"))

@blueprint.route("/teams_setting/remove/<team_id>")
@login_required
def team_remove(team_id):
    team = Team.query.filter_by(id=team_id).first_or_404()
    db.session.delete(team)
    db.session.commit()
    return redirect(url_for("base_blueprint.teams_setting"))

@blueprint.route("teams_setting/edit/<team_id>", methods=["GET", "POST"])
@login_required
def team_edit(team_id):
    edit_team = Team.query.filter_by(id=team_id).first_or_404()
    teamForm = CreateTeamForm()
    admin = util.is_admin(current_user.role)
    if admin:
        if len(request.form) > 0:
            if teamForm.validate_on_submit():
                # teamForm.populate_obj(edit_team)
                member_ids = teamForm.members.data
                edit_team.members = User.query.filter(User.id.in_(member_ids)).all()

                project_ids = teamForm.projects.data
                edit_team.projects = Project.query.filter(Project.id.in_(project_ids)).all()
                db.session.commit()
                current_app.logger.info("Team updated (team.id=%i)", team_id)
                flash("Team successfully updated", "success")
                return redirect(url_for("base_blueprint.teams_setting"))
            else:
                return render_template(
                "team_edit.html",
                edit=True,
                form=teamForm,
                user=current_user,
                team=edit_team,
            )
        else:
            teamForm.name.data = edit_team.name
            return render_template(
                "team_edit.html",
                edit=True,
                form=teamForm,
                user=current_user,
                team=edit_team,
            )
    else:
        return render_template("403.html"), 403

@blueprint.route("teams_setting/add", methods=["POST", "GET"])
@login_required
def team_add():
    teamForm = CreateTeamForm()
    admin = util.is_admin(current_user.role)
    if admin:
        if request.method == "POST" and teamForm.validate_on_submit():
            new_team = Team(
                name=teamForm.name.data,
                creator=current_user.username,
                user_id=current_user.id
            )
            member_ids = teamForm.members.data
            members = User.query.filter(User.id.in_(member_ids)).all()

            new_team.members = members
            project_ids = teamForm.projects.data
            projects = Project.query.filter(Project.id.in_(project_ids)).all()

            new_team.projects = projects
            db.session.add(new_team)
            db.session.commit()
            return redirect(url_for("base_blueprint.teams_setting"))
        return render_template("team_edit.html", user=current_user, form=teamForm, edit=False, team=None)
    else:
        return render_template("403.html"), 403

@blueprint.route("/teams_setting", methods=["GET", "POST"])
@login_required
def teams_setting():
    teamForm = CreateTeamForm()
    teamTable = Team.query.all()
    if request.method == "POST" and teamForm.validate_on_submit():
        new_team = Team(
            name=teamForm.name.data,
            creator=current_user.username,
            user_id=current_user.id
        )
        member_ids = teamForm.members.data
        members = User.query.filter(User.id.in_(member_ids)).all()

        new_team.members = members
        project_ids = teamForm.projects.data
        projects = Project.query.filter(Project.id.in_(project_ids)).all()

        new_team.projects = projects
        db.session.add(new_team)
        db.session.commit()
        return redirect(url_for("base_blueprint.teams_setting", edit=False))
    return render_template("teams_setting.html", user=current_user, segment="teams", form=teamForm, teamTable=teamTable, edit=False)



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

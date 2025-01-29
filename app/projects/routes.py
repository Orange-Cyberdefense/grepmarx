# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from datetime import datetime
import json
import os
import pathlib

from zipfile import BadZipFile, ZipFile

from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    send_file,
    url_for,
    request,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app import db
from app.constants import (
    EXTRACT_FOLDER_NAME,
    LANGUAGES_DEVICONS,
    PROJECTS_SRC_PATH,
    SCAN_LOGS_FOLDER,
)
from app.base import util
from app.projects import blueprint
from app.projects.forms import ProjectForm, XLSExportForm
from app.projects.models import Project
from app.projects.util import (
    check_zipfile,
    count_lines,
    generate_xls,
    has_access,
    remove_project,
    sha256sum,
    top_supported_language_lines_counts,
    duration_format,
    format_metric_prefix,
    get_user_projects_ids,
)
from app.base.models import Team


@blueprint.route("/projects")
@login_required
def projects_list():
    projects = Project.query.all()
    project_form = ProjectForm()
    admin = util.is_admin(current_user.role)
    user_projects_ids = get_user_projects_ids(current_user)
    return render_template(
        "projects_list.html",
        projects=projects,
        form=project_form,
        user=current_user,
        admin=admin,
        user_projects_ids=user_projects_ids,
        top_supported_language_lines_counts=top_supported_language_lines_counts,
        format_metric_prefix=format_metric_prefix,
        duration_format=duration_format,
        lang_icons=LANGUAGES_DEVICONS,
        segment="projects",
    )


@blueprint.route("/projects/<project_id>", methods=["POST", "GET"])
@login_required
def projects_dashboard(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    # XLS export button
    form = XLSExportForm()
    if form.validate_on_submit():
        selected_option = form.choice.data
        # Faire quelque chose avec l'option sélectionnée, comme rediriger vers une autre page
        return redirect(
            url_for(
                "projects_blueprint.xls_export",
                project_id=project_id,
                selected_option=selected_option,
            )
        )
    # Get the 5 first inspector matches
    features = project.appinspector.match[0:5]
    return render_template(
        "project_dashboard.html",
        project=project,
        user=current_user,
        top_supported_language_lines_counts=top_supported_language_lines_counts,
        lang_icons=LANGUAGES_DEVICONS,
        features=features,
        segment="projects",
        form=form,
    )


@blueprint.route("/projects/<project_id>/status")
@login_required
def projects_status(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    return str(project.status), 200

@blueprint.route("/projects/<project_id>/progress")
@login_required
def projects_progress(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    # Calculate current analysis progress in %
    progress = project.analysis.progress
    delta = datetime.now() - project.analysis.progress_updated_on
    if progress < 100 and progress > -1:
        progress = int(progress + delta.seconds / 60)
        if progress > 100:
            progress = 99
    return str(progress), 200

@blueprint.route("/projects/remove/<project_id>")
@login_required
def projects_remove(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    remove_project(project)
    current_app.logger.info("Project deleted (project.id=%i)", project.id)
    flash("Project successfully deleted", "success")
    return redirect(url_for("projects_blueprint.projects_list"))


@blueprint.route("/projects/create", methods=["POST"])
@login_required
def projects_create():
    project_form = ProjectForm()
    # Form is valid
    if project_form.validate_on_submit():
        # Create a new project
        project_name = project_form.name.data
        file = project_form.source_archive.data
        project = Project(
            name=project_name,
            creator=current_user,
            archive_filename=secure_filename(file.filename),
        )
        # Store the new project in db
        db.session.add(project)
        db.session.commit()
        # Store the archive on disk
        if not os.path.isdir(PROJECTS_SRC_PATH):
            pathlib.Path(PROJECTS_SRC_PATH).mkdir(parents=True, exist_ok=True)
        project_path = os.path.join(PROJECTS_SRC_PATH, str(project.id))
        os.mkdir(project_path)
        archive_path = os.path.join(project_path, secure_filename(file.filename))
        file.save(archive_path)
        # Check if the provided archive is valid
        error, msg = check_zipfile(archive_path)
        if error:
            current_app.logger.warning(
                "Invalid archive file uploaded (archive path was '%s')", archive_path
            )
            remove_project(project)
            return msg, 403
        # Extract archive on disk
        project.archive_sha256sum = sha256sum(archive_path)
        source_path = os.path.join(project_path, EXTRACT_FOLDER_NAME)
        with ZipFile(archive_path, "r") as zip_ref:
            try:
                zip_ref.extractall(source_path)
            except BadZipFile as e:
                current_app.logger.error("Bad zip file: %s", str(e))
                remove_project(project)
                return "Bad zip file", 403
        # Count lines of code and save project
        count_lines(project)
        db.session.commit()
        current_app.logger.info("New project created (project.id=%i)", project.id)
        # Add the project to the global team
        Global_team = Team.query.filter_by(name="Global").first()
        Global_team_project_ids = [project.id for project in Global_team.projects]
        Global_team_project_ids.append(project.id)
        Global_team.projects = Project.query.filter(
            Project.id.in_(Global_team_project_ids)
        ).all()
        print(Global_team)
        db.session.commit()
        return str(project.id), 200
    # Form is invalid
    else:
        current_app.logger.warning(
            "Project add form invalid entries: %s", json.dumps(project_form.errors)
        )
        return json.dumps(project_form.errors), 403


@blueprint.route("/projects/xls_export/<project_id>")
@login_required
def xls_export(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    # Generate XLS file
    selected_option = request.args.get("selected_option")
    xls_path = generate_xls(project, selected_option)
    # Return generated file to the browser
    return send_file(xls_path, as_attachment=True)

@blueprint.route("/projects/<project_id>/download_sources")
@login_required
def download_sources(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    # Path to the source archive file
    source_archive = os.path.join(os.getcwd(), PROJECTS_SRC_PATH, str(project.id), project.archive_filename)
    if not os.path.isfile(source_archive):
        flash("Source code archive not found for this project.", "error")
        return redirect(url_for("projects_blueprint.projects_list"))
    # Return generated file to the browser
    return send_file(source_archive, as_attachment=True)

@blueprint.route("/projects/<project_id>/download_analysis_logs")
@login_required
def download_analysis_logs(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    # Path to the log file
    log_file = os.path.join(os.getcwd(), PROJECTS_SRC_PATH, str(project.id), SCAN_LOGS_FOLDER, str(project.analysis.id) + ".log")
    if not os.path.isfile(log_file):
        flash("No log file found for this project.", "error")
        return redirect(url_for("projects_blueprint.projects_list"))
    # Return generated file to the browser
    return send_file(log_file, as_attachment=True)
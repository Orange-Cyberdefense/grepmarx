# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import json
import os
import pathlib
from glob import glob
from zipfile import BadZipFile, ZipFile

from flask import current_app, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from grepmarx import db
from grepmarx.constants import (
    EXTRACT_FOLDER_NAME,
    LANGUAGES_DEVICONS,
    PROJECTS_SRC_PATH,
)
from grepmarx.projects import blueprint
from grepmarx.projects.forms import ProjectForm
from grepmarx.projects.model import Project
from grepmarx.projects.util import check_zipfile, sha256sum
from werkzeug.utils import secure_filename


@blueprint.route("/projects")
@login_required
def projects_list():
    projects = Project.query.all()
    project_form = ProjectForm()
    return render_template(
        "projects_list.html",
        projects=projects,
        form=project_form,
        user=current_user,
        lang_icons=LANGUAGES_DEVICONS,
        segment="projects",
    )


@blueprint.route("/projects/<project_id>/status")
@login_required
def projects_status(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    return str(project.status), 200


@blueprint.route("/projects/remove/<project_id>")
@login_required
def projects_remove(project_id):
    project = Project.query.filter_by(id=project_id).first_or_404()
    project.remove()
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
            project.remove()
            return msg, 403
        # Extract archive on disk
        project.archive_sha256sum = sha256sum(archive_path)
        source_path = os.path.join(project_path, EXTRACT_FOLDER_NAME)
        with ZipFile(archive_path, "r") as zip_ref:
            try:
                zip_ref.extractall(source_path)
            except BadZipFile as e:
                current_app.logger.error("Bad zip file: %s", str(e))
                project.remove()
                return "Bad zip file", 403
        # Count lines of code and save project
        project.count_lines()
        db.session.commit()
        current_app.logger.info("New project created (project.id=%i)", project.id)
        return str(project.id), 200
    # Form is invalid
    else:
        current_app.logger.warning(
            "Project add form invalid entries: %s", json.dumps(project_form.errors)
        )
        return json.dumps(project_form.errors), 403

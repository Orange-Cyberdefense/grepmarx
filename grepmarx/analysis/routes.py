# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import json
import os

from flask import current_app, flash, redirect, render_template, url_for
from flask_login import current_user, login_required
from grepmarx import db
from grepmarx.analysis import blueprint
from grepmarx.analysis.forms import ScanForm
from grepmarx.analysis.model import Analysis, Occurence, Vulnerability
from grepmarx.analysis.util import async_scan
from grepmarx.projects.model import Project
from grepmarx.rules.model import Rule, RulePack
from pygments.lexers import guess_lexer_for_filename


@blueprint.route("/analysis/workbench/<analysis_id>")
@login_required
def analysis_workbench(analysis_id):
    # TODO LFI via vulnerability location !
    analysis = Analysis.query.filter_by(id=analysis_id).first_or_404()
    vulnerabilities = analysis.vulnerabilities_sorted_by_severity()
    return render_template(
        "analysis_workbench.html",
        user=current_user,
        vulnerabilities=vulnerabilities,
        segment="",
    )


@blueprint.route("/analysis/codeview/<occurence_id>")
@login_required
def analysis_codeview(occurence_id):
    occurence = Occurence.query.filter_by(id=occurence_id).first_or_404()
    project_id = occurence.vulnerability.analysis.project.id
    file = os.path.join(
        Project.PROJECTS_SRC_PATH,
        str(project_id),
        Project.EXTRACT_FOLDER_NAME,
        occurence.file_path,
    )
    with open(file, "r") as f:
        code = f.read()
    language = guess_lexer_for_filename(file, code).name
    hl_lines = (
        str(occurence.position.line_start) + "-" + str(occurence.position.line_end)
        if occurence.position.line_end > occurence.position.line_start
        else str(occurence.position.line_start)
    )
    # code = Markup(code)
    return render_template(
        "analysis_occurence_codeview.html",
        code=code,
        language=language,
        hl_lines=hl_lines,
        user=current_user,
        path=occurence.file_path,
    )


@blueprint.route("/analysis/occurence_details/<occurence_id>")
@login_required
def analysis_occurence_details(occurence_id):
    occurence = Occurence.query.filter_by(id=occurence_id).first_or_404()
    return render_template(
        "analysis_occurence_details.html",
        occurence=occurence,
        owasp_links=Rule.OWASP_TOP10_LINKS,
    )


@blueprint.route("/analysis/occurences_table/<vulnerability_id>")
@login_required
def analysis_occurences_table(vulnerability_id):
    vulnerability = Vulnerability.query.filter_by(id=vulnerability_id).first_or_404()
    return render_template(
        "analysis_occurences_table.html", vulnerability=vulnerability
    )


@blueprint.route("/analysis/scans/new/<project_id>")
@login_required
def scans_new(project_id, scan_form=None):
    # Asscociate corresponding project
    project = Project.query.filter_by(id=project_id).first_or_404()
    if scan_form is None:
        scan_form = ScanForm(project_id=project.id)
    # Dynamically adds choices for multiple selection fields
    scan_form.rule_packs.choices = ((rp.id, rp.name) for rp in RulePack.query.all())
    return render_template(
        "analysis_scans_new.html",
        project=project,
        form=scan_form,
        user=current_user,
        segment="projects",
    )


@blueprint.route("/analysis/scans/launch", methods=["POST"])
@login_required
def scans_launch():
    scan_form = ScanForm()
    project = Project.query.filter_by(id=scan_form.project_id.data).first_or_404()
    # Dynamically adds choices for multiple selection fields
    scan_form.rule_packs.choices = ((rp.id, rp.name) for rp in RulePack.query.all())
    # Form is valid
    if scan_form.validate_on_submit():
        # Need at least one rule pack
        if len(scan_form.rule_packs.data) <= 0:
            flash("At least one rule pack should be selected", "error")
            return scans_new(project_id=project.id, scan_form=scan_form)
        # Get applicable rule packs
        selected_rule_packs = RulePack.query.filter(
            RulePack.id.in_(scan_form.rule_packs.data)
        ).all()
        # Create a new analysis
        project.analysis = Analysis(
            rule_packs=selected_rule_packs,
            ignore_paths=scan_form.ignore_paths.data,
            ignore_filenames=scan_form.ignore_filenames.data,
        )
        db.session.commit()
        # Set rule folder for the project
        project_rules_path = os.path.join(
            Project.PROJECTS_SRC_PATH, str(project.id), "rules"
        )
        # Copy all applicable rules in a folder under the project's directory
        project.analysis.import_rules(project_rules_path)
        # Start celery asynchronous scan
        current_app.logger.info("New analysis started (project.id=%i)", project.id)
        async_scan.delay(project.analysis.id)
        # Done
        current_app.logger.info("Analysis completed (project.id=%i)", project.id)
        flash("Analysis successfully launched", "success")
        return redirect(url_for("projects_blueprint.projects_list"))
    # Form is not valid, form.error is populated
    else:
        current_app.logger.warning(
            "Analysis launch form invalid entries: %s", json.dumps(scan_form.errors)
        )
        flash(str(scan_form.errors), "error")
        return scans_new(project_id=project.id, scan_form=scan_form)

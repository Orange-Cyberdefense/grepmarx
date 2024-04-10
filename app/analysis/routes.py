# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import json
import os
import time

import chardet
from flask import (
    current_app,
    flash,
    redirect,
    render_template,
    url_for,
    request,
    jsonify,
)
from flask_login import current_user, login_required
from pygments.lexers import guess_lexer_for_filename
from pygments.util import ClassNotFound

import io
import csv
from flask import make_response

from app import db
from app.analysis import blueprint
from app.analysis.forms import ScanForm
from app.analysis.models import (
    Analysis,
    AppInspector,
    InspectorTag,
    Match,
    Occurence,
    Vulnerability,
    VulnerableDependency,
)
from app.analysis.util import (
    async_scan,
    import_rules,
    stop_analysis,
    vulnerabilities_sorted_by_severity,
)
from app.constants import (
    EXTRACT_FOLDER_NAME,
    OWASP_TOP10_LINKS,
    PROJECTS_SRC_PATH,
    STATUS_PENDING,
    STATUS,
)
from app.projects.models import Project
from app.projects.util import has_access, top_language_lines_counts
from app.rules.models import RulePack

#
# Scans
#


@blueprint.route("/analysis/scans/new/<project_id>")
@login_required
def scans_new(project_id, scan_form=None):
    project = Project.query.filter_by(id=project_id).first_or_404()
    if scan_form is None:
        scan_form = ScanForm(project_id=project.id)
    # Dynamically adds choices for multiple selection fields
    scan_form.rule_packs.choices = ((rp.id, rp.name) for rp in RulePack.query.all())
    # Rule packs preselection depending on the project's detected languages
    project_languages = [
        llc.language for llc in project.project_lines_count.language_lines_counts
    ]
    all_rules_packs = RulePack.query.all()
    selected_rule_packs = list()
    for rule_pack in all_rules_packs:
        for supported_language in rule_pack.languages:
            if supported_language.name in project_languages:
                selected_rule_packs.append(rule_pack.id)
    return render_template(
        "analysis_scans_new.html",
        project=project,
        form=scan_form,
        user=current_user,
        top_language_lines_counts=top_language_lines_counts,
        selected_rule_packs=selected_rule_packs,
        segment="projects",
    )


@blueprint.route("/analysis/scans/launch", methods=["POST"])
@login_required
def scans_launch():
    scan_form = ScanForm()
    project = Project.query.filter_by(id=scan_form.project_id.data).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, project):
        return render_template("403.html"), 403
    # Dynamically adds choices for multiple selection fields
    scan_form.rule_packs.choices = list((rp.id, rp.name) for rp in RulePack.query.all())
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
        # create a new app inspector
        project.appinspector = AppInspector()
        # Set rule folder for the project
        project_rules_path = os.path.join(PROJECTS_SRC_PATH, str(project.id), "rules")
        # Copy all applicable rules in a folder under the project's directory
        try:
            import_rules(project.analysis, project_rules_path)
        except FileNotFoundError:
            flash(
                "There was an issue while getting the rules for this analysis. Please synchronize the rules from the 'Analysis rules' page.",
                "error",
            )
            return scans_new(project_id=project.id, scan_form=scan_form)
        # Start celery asynchronous scan
        project.status = STATUS_PENDING
        db.session.commit()
        current_app.logger.info("New analysis queued (project.id=%i)", project.id)
        async_scan.delay(project.analysis.id, project.appinspector.id)
        # async_scan.apply_async(args=(project.analysis.id, project.appinspector.id))
        # Wait to make sure the status changed to STATUS_ANALYZING before rendering the projects list
        time.sleep(1.0)
        flash("Analysis successfully launched", "success")
        return redirect(url_for("projects_blueprint.projects_list"))
    # Form is not valid, form.error is populated
    else:
        current_app.logger.warning(
            "Analysis launch form invalid entries: %s", json.dumps(scan_form.errors)
        )
        flash(str(scan_form.errors), "error")
        return scans_new(project_id=project.id, scan_form=scan_form)


@blueprint.route("/analysis/scans/stop/<analysis_id>")
@login_required
def scans_stop(analysis_id):
    analysis = Analysis.query.filter_by(id=analysis_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, analysis.project):
        return render_template("403.html"), 403
    stop_analysis(analysis)
    flash("Analysis has successfully been stopped.", "success")
    return redirect(url_for("projects_blueprint.projects_list"))


#
# Workbench
#


@blueprint.route("/analysis/workbench/<analysis_id>")
@login_required
def analysis_workbench(analysis_id):
    analysis = Analysis.query.filter_by(id=analysis_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, analysis.project):
        return render_template("403.html"), 403
    if len(analysis.vulnerabilities) <= 0:
        flash(
            "No findings were found for this project during the last analysis", "error"
        )
        return redirect(
            url_for(
                "projects_blueprint.projects_dashboard", project_id=analysis.project.id
            )
        )
    vulnerabilities = vulnerabilities_sorted_by_severity(analysis)
    return render_template(
        "analysis_workbench.html",
        user=current_user,
        vulnerabilities=vulnerabilities,
        segment="",
    )


@blueprint.route("/analysis/codeview/<occurence_id>")
@login_required
def analysis_codeview(occurence_id):
    # Get occurence infos
    occurence = Occurence.query.filter_by(id=occurence_id).first_or_404()
    project_id = occurence.vulnerability.analysis.project.id
    # Check if the user has access to the project
    if not has_access(current_user, occurence.vulnerability.analysis.project):
        return render_template("403.html"), 403
    # Get the source code file
    source_path = os.path.join(PROJECTS_SRC_PATH, str(project_id), EXTRACT_FOLDER_NAME)
    file = os.path.join(source_path, occurence.file_path)
    # Mitigate path traversal risk
    common_prefix = os.path.commonprefix(
        (os.path.realpath(file), os.path.realpath(source_path))
    )
    if common_prefix != os.path.realpath(source_path):
        return "", 403
    # Detect file encoding
    with open(file, "rb") as f:
        raw_data = f.read()
        encoding = chardet.detect(raw_data)["encoding"]
    # Open the file with detected encoding
    with open(file, "r", encoding=encoding, errors="replace") as f:
        code = f.read()
    # Try to guess file language for syntax highlighting
    try:
        language = guess_lexer_for_filename(file, code).name
    except ClassNotFound as e:
        language = "generic"
    # Define lines to be highlighted
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
        project_id=project_id,
    )


@blueprint.route("/analysis/occurence_details/<occurence_id>")
@login_required
def analysis_occurence_details(occurence_id):
    occurence = Occurence.query.filter_by(id=occurence_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, occurence.vulnerability.analysis.project):
        return render_template("403.html"), 403
    return render_template(
        "analysis_occurence_details.html",
        occurence=occurence,
        owasp_links=OWASP_TOP10_LINKS,
    )


@blueprint.route(
    "/analysis/occurences_table/<occurence_id>/save_status", methods=["GET"]
)
@login_required
def save_status(occurence_id):
    vulnerability_id = request.args.get("vulnerabilityId")
    vulnerability = Vulnerability.query.filter_by(id=vulnerability_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, vulnerability.analysis.project):
        return render_template("403.html"), 403
    for occurence in vulnerability.occurences:
        if occurence.id == int(occurence_id):
            occurence.status = request.args.get("status")
            try:
                db.session.commit()
                flash(
                    f"Occurence {occurence_id} status updated successfully.", "success"
                )
                return (
                    jsonify(
                        {
                            "message": f"Occurence {occurence_id} status updated successfully."
                        }
                    ),
                    200,
                )
            except Exception as e:
                db.session.rollback()
                flash("Error : Add occurence status wto db faild.")
                return jsonify({"error": str(e)}), 500
    flash("Error: Occurence not found.")
    return "Error", 404


@blueprint.route(
    "/analysis/occurences_table/<vulnerability_id>", methods=["POST", "GET"]
)
@login_required
def analysis_occurences_table(vulnerability_id):
    vulnerability = Vulnerability.query.filter_by(id=vulnerability_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, vulnerability.analysis.project):
        return render_template("403.html"), 403
    return render_template(
        "analysis_occurences_table.html", vulnerability=vulnerability, status=STATUS
    )


#
# Dependency scan
#


@blueprint.route("/analysis/dependencies/<analysis_id>")
@login_required
def analysis_dependencies(analysis_id):
    analysis = Analysis.query.filter_by(id=analysis_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, analysis.project):
        return render_template("403.html"), 403
    return render_template("dependencies.html", user=current_user, analysis=analysis)


@blueprint.route("/analysis/dependencies/details/<vuln_dep_id>")
@login_required
def analysis_dependencies_details(vuln_dep_id):
    vulnerableDependency = VulnerableDependency.query.filter_by(
        id=vuln_dep_id
    ).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, vulnerableDependency.analysis.project):
        return render_template("403.html"), 403
    return render_template(
        "dependencies_details.html",
        vulnerableDependency=vulnerableDependency,
    )


@blueprint.route("/analysis/<analysis_id>/dependencies/export/csv")
@login_required
def analysis_dependencies_export_csv(analysis_id):
    analysis = Analysis.query.filter_by(id=analysis_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, analysis.project):
        return render_template("403.html"), 403
    data = [
        [
            "Id",
            "Package",
            "Type",
            "Version",
            "Fix version",
            "Severity",
            "CVSS",
            "Vendor confirmed",
            "Has PoC",
            "Know exploit",
            "Direct usage",
            "Indirect dependency",
            "Prioritized",
            "Reference",
        ]
    ]
    for vuln_dep in analysis.vulnerable_dependencies:
        data.append(
            [
                vuln_dep.common_id,
                vuln_dep.pkg_ref,
                vuln_dep.pkg_type,
                vuln_dep.version,
                vuln_dep.fix_version,
                vuln_dep.severity,
                vuln_dep.cvss_score,
                vuln_dep.vendor_confirmed,
                vuln_dep.has_poc,
                vuln_dep.has_exploit,
                vuln_dep.direct,
                vuln_dep.indirect,
                vuln_dep.prioritized,
                vuln_dep.source,
            ]
        )
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerows(data)
    output = make_response(si.getvalue())
    filename = "%i-Vulnerable Dependencies-%s.csv" % (
        analysis.id,
        analysis.project.name,
    )
    output.headers["Content-Disposition"] = "attachment; filename=" + filename
    output.headers["Content-type"] = "text/csv"
    return output


#
# Inspector
#


@blueprint.route("/analysis/inspector/<inspector_id>")
@login_required
def analysis_inspector(inspector_id):
    appinspector = AppInspector.query.filter_by(id=inspector_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, appinspector.project):
        return render_template("403.html"), 403
    return render_template(
        "app_inspector.html", user=current_user, appinspector=appinspector
    )


@blueprint.route("/analysis/inspector/excerpt/<tag_id>")
@login_required
def analysis_inspector_excerpt(tag_id):
    """Retrieve the content of an inspectorTag object thanks to an id"""
    inspectortag = InspectorTag.query.filter_by(id=tag_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, inspectortag.match.appinspector.project):
        return render_template("403.html"), 403
    print(inspectortag.excerpt)
    return render_template("app_inspector_excerpt.html", inspectortag=inspectortag)


@blueprint.route("/analysis/inspector/occurence/<match_id>")
@login_required
def analysis_inspector_occurence(match_id):
    """Retrieve all the filenames associated with a match"""
    match = Match.query.filter_by(id=match_id).first_or_404()
    # Check if the user has access to the project
    if not has_access(current_user, match.appinspector.project):
        return render_template("403.html"), 403
    inspectortag = InspectorTag.query.filter_by(match_id=match_id).all()
    return render_template(
        "app_inspector_ocuurence_view.html", inspectortag=inspectortag, match=match
    )

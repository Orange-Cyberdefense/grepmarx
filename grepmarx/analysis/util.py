# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
from datetime import datetime

from flask import current_app
from grepmarx import celery, db
from grepmarx.analysis import model
from grepmarx.projects.model import Project
from libsast import Scanner
from semgrep.error import SemgrepError


@celery.task(name="grepmarx-scan")
def async_scan(analysis_id):

    current_app.logger.debug("Entering async scan for analysis with id=%i", analysis_id)
    analysis = model.Analysis.query.filter_by(id=analysis_id).first()

    # Status in now Analysing
    analysis.started_on = datetime.now()
    analysis.project.status = Project.STATUS_ANALYZING
    db.session.commit()

    # Define the scan path
    scan_path = os.path.join(
        Project.PROJECTS_SRC_PATH, str(analysis.project.id), Project.EXTRACT_FOLDER_NAME
    )

    # Set scanner options
    project_rules_path = os.path.join(
        Project.PROJECTS_SRC_PATH, str(analysis.project.id), "rules"
    )
    options = analysis.generate_options(project_rules_path)
    current_app.logger.debug(
        "Scanner options for project with id=%i: %s", analysis.project.id, str(options)
    )

    scanner = Scanner(options, [scan_path])
    try:
        result = scanner.scan()
        analysis.load_scan_results(result)
        analysis.project.status = Project.STATUS_FINISHED

    except SemgrepError as e:
        analysis.project.error_message = repr(e)
        analysis.project.status = Project.STATUS_ERROR
        current_app.logger.error(
            "Error while scanning project with id=%i: %s", analysis.project.id, str(e)
        )

    analysis.finished_on = datetime.now()
    db.session.commit()

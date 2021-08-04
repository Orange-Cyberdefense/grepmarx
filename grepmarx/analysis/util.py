# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
from datetime import datetime
from shutil import copyfile, rmtree

from flask import current_app
from grepmarx import celery, db
from grepmarx.rules.util import generate_severity
from grepmarx.analysis.models import Analysis, AnalysisError, Occurence, Vulnerability
from grepmarx.constants import (
    EXTRACT_FOLDER_NAME,
    PROJECTS_SRC_PATH,
    RULE_EXTENSIONS,
    RULES_PATH,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    STATUS_ANALYZING,
    STATUS_ERROR,
    STATUS_FINISHED,
)
from libsast import Scanner
from semgrep.error import SemgrepError

##
## Analysis utils
##


@celery.task(name="grepmarx-scan")
def async_scan(analysis_id):
    """Launch the actual libsast/semgrep scan, asynchronously through celery.

    Args:
        analysis_id (int): ID of the analysis to populate with the results
    """
    current_app.logger.debug("Entering async scan for analysis with id=%i", analysis_id)
    analysis = Analysis.query.filter_by(id=analysis_id).first()
    # Status in now Analysing
    analysis.started_on = datetime.now()
    analysis.project.status = STATUS_ANALYZING
    db.session.commit()
    # Define the scan path
    scan_path = os.path.join(
        PROJECTS_SRC_PATH, str(analysis.project.id), EXTRACT_FOLDER_NAME
    )
    # Set scanner options
    project_rules_path = os.path.join(
        PROJECTS_SRC_PATH, str(analysis.project.id), "rules"
    )
    options = generate_options(analysis, project_rules_path)
    current_app.logger.debug(
        "Scanner options for project with id=%i: %s", analysis.project.id, str(options)
    )
    # Start scan
    scanner = Scanner(options, [scan_path])
    try:
        result = scanner.scan()
        load_scan_results(analysis, result)
        analysis.project.status = STATUS_FINISHED
    except SemgrepError as e:
        analysis.project.error_message = repr(e)
        analysis.project.status = STATUS_ERROR
        current_app.logger.error(
            "Error while scanning project with id=%i: %s", analysis.project.id, str(e)
        )
    # Done
    analysis.finished_on = datetime.now()
    db.session.commit()


def load_scan_results(analysis, libsast_result):
    """Populate an Analysis object with the result of libsast/semgrep scan.

    Args:
        libsast_result (dict): return value of libsast.Scanner.scan()
    """
    if libsast_result is not None:
        if "semantic_grep" in libsast_result:
            matches = libsast_result["semantic_grep"]["matches"]
            for c_match in matches:
                analysis.vulnerabilities.append(
                    load_vulnerability(c_match, matches[c_match])
                )
            errors = libsast_result["semantic_grep"]["errors"]
            for c_error in errors:
                analysis.errors.append(AnalysisError.load_error(c_error))


def generate_options(analysis, rule_folder):
    """Generate libsast/semgrep options depending on the attributes of an analysis.

    Args:
        rule_folder (string): path to be used as the rule folder for the scanner
    Returns:
        dict: options ready to be passed to a libsast.Scanner object
    """
    options = dict()
    # Rule path
    options["sgrep_rules"] = rule_folder
    # Ignore filenames
    options["ignore_filenames"] = set(
        # Remove empty elements
        filter(None, analysis.ignore_filenames.split(","))
    )
    # Ignore paths
    options["ignore_paths"] = set(
        # Remove empty elements
        filter(None, analysis.ignore_paths.split(","))
    )
    # Extensions
    ext_str = ""
    for c_rule_pack in analysis.rule_packs:
        print(c_rule_pack.name)
        for c_language in c_rule_pack.languages:
            print(c_language.name)
            ext_str += c_language.extensions + ","
    options["sgrep_extensions"] = set(
        # Remove duplicates
        dict.fromkeys(
            # Remove empty elements
            filter(None, ext_str.split(","))
        )
    )
    return options


def import_rules(analysis, rule_folder):
    """Copy all YML files corresponding to rules of an analysis' rule packs into a (project) folder.

    Args:
        analysis (Analysis): analysis object of the project in whose folder rules should be imported
        rule_folder ([type]): destination folder (usually data/projects/<project_id>/rules/)
    """
    if os.path.isdir(rule_folder):
        rmtree(rule_folder)
    os.mkdir(rule_folder)
    for c_rule_pack in analysis.rule_packs:
        for c_rule in c_rule_pack.rules:
            src = os.path.join(RULES_PATH, c_rule.file_path)
            dst = os.path.join(
                rule_folder,
                c_rule.repository.name
                + "_"
                + c_rule.category
                + "."
                + c_rule.title
                + next(iter(RULE_EXTENSIONS)),
            )
            copyfile(src, dst)
            current_app.logger.debug(
                "Imported rule for project with id=%i: %s",
                analysis.project.id,
                dst,
            )


def vulnerabilities_sorted_by_severity(analysis):
    """Get vulnerabilities of an analysis sorted by their severity level (most critical first).

    Args:
        analysis (Analysis): analysis object populated with vulnerabilities

    Returns:
        list: vulnerability objects sorted by severity
    """
    r_vulns = list()
    low_vulns = list()
    for c_vulns in analysis.vulnerabilities:
        if c_vulns.severity == SEVERITY_HIGH:
            r_vulns.insert(0, c_vulns)
        elif c_vulns.severity == SEVERITY_MEDIUM:
            r_vulns.append(c_vulns)
        else:
            low_vulns.append(c_vulns)
    r_vulns.extend(low_vulns)
    return r_vulns

##
## Vulnerability utils
##

def load_vulnerability(match_title, match_dict):
    """Create a vulnerability object from a 'match' element of libsast/semgrep results.

    Args:
        match_title (string): match title
        match_dict (dict): match element with its properties

    Returns:
        Vulnerability: fully populated vulnerability
    """
    vuln = Vulnerability(title=match_title)
    for c_occurence in match_dict["files"]:
        vuln.occurences.append(Occurence.load_occurence(c_occurence))
    metadata = match_dict["metadata"]
    if "description" in metadata:
        vuln.description = metadata["description"]
    if "cwe" in metadata:
        vuln.cwe = metadata["cwe"]
    if "owasp" in metadata:
        vuln.owasp = metadata["owasp"]
    if "references" in metadata:
        vuln.references = " ".join(metadata["references"])
    vuln.severity = generate_severity(vuln.cwe)
    return vuln
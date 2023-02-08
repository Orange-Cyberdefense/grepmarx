# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import json
import multiprocessing
import os
import re
from datetime import datetime
from difflib import Match
from glob import glob
from shutil import copyfile, rmtree
import subprocess

from flask import current_app
from semgrep import semgrep_main
from semgrep.constants import OutputFormat
from semgrep.error import SemgrepError
from semgrep.output import OutputHandler, OutputSettings

from app import celery, db
from app.analysis.models import (
    Analysis,
    AppInspector,
    InspectorTag,
    Match,
    Occurence,
    Position,
    Vulnerability,
    VulnerableDependency,
)
from app.constants import (
    APPLICATION_INSPECTOR,
    DEPSCAN,
    DEPSCAN_RESULT_FILE,
    DEPSCAN_RESULT_FOLDER,
    EXTRACT_FOLDER_NAME,
    PROJECTS_SRC_PATH,
    RULE_EXTENSIONS,
    RULES_PATH,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    STATUS_ABORTED,
    STATUS_ANALYZING,
    STATUS_ERROR,
    STATUS_FINISHED,
)
from app.projects.util import (
    calculate_risk_level,
    count_occurences,
)
from app.rules.util import generate_severity

##
## Analysis utils
##


@celery.task(name="grepmarx-scan", bind=True)
def async_scan(self, analysis_id, app_inspector_id):
    """Launch a new code scan on the project corresponding to the given analysis ID, asynchronously through celery.

    Args:
        analysis_id (int): ID of the analysis to populate with the results
    """
    current_app.logger.debug("Entering async scan for analysis with id=%i", analysis_id)
    analysis = Analysis.query.filter_by(id=analysis_id).first()
    app_inspector = AppInspector.query.filter_by(id=app_inspector_id).first()
    # Status in now Analysing
    analysis.started_on = datetime.now()
    analysis.project.status = STATUS_ANALYZING
    analysis.task_id = self.request.id
    db.session.commit()
    # Prepare semgrep options
    files_to_scan, project_rules_path, ignore = generate_semgrep_options(analysis)
    try:
        # SAST scan: invoke semgrep
        sast_result = sast_scan(files_to_scan, project_rules_path, ignore)
        # SCA scan: invoke depscan
        sca_result = sca_scan(analysis.project)
        # Inspector scan: invoke ApplicationInspector
        inspector_result = inspector_scan(app_inspector.project.id)
        # Everything went fine: load results into the analysis object
        load_sast_scan_results(analysis, sast_result)
        load_sca_scan_results(analysis, sca_result)
        load_inspector_results(app_inspector, inspector_result)
        # Also save SAST results into a file
        save_sast_result(analysis, sast_result)
        analysis.project.status = STATUS_FINISHED
    except Exception as e:
        analysis.project.error_message = repr(e)
        analysis.project.status = STATUS_ERROR
        current_app.logger.error(
            "Error while scanning project with id=%i: %s", analysis.project.id, str(e)
        )
    # Done
    analysis.finished_on = datetime.now()
    analysis.task_id = ""
    # Update project properties
    analysis.project.occurences_count = count_occurences(analysis.project)
    analysis.project.risk_level = calculate_risk_level(analysis.project)
    db.session.commit()


def stop_analysis(analysis):
    task_id = analysis.task_id
    celery.control.revoke(task_id, terminate=True, signal="SIGKILL")
    analysis.project.status = STATUS_ABORTED
    analysis.task_id = ""
    db.session.commit()


##
## SAST scan utils
##


def sast_scan(files_to_scan, project_rules_path, ignore):
    """Launch the actual semgrep scan. Credits to libsast:
    https://github.com/ajinabraham/libsast/blob/master/libsast/core_sgrep/helpers.py

    Args:
        files_to_scan (list): files' paths to be scanned
        project_rules_path (str): path to the folder with semgrep YML rules
        ignore (list): patterns of paths / filenames to skip

    Returns:
        [str]: Semgrep JSON output
    """
    cpu_count = multiprocessing.cpu_count()
    # util.set_flags(verbose=False, debug=False, quiet=True, force_color=False)
    output_settings = OutputSettings(
        output_format=OutputFormat.JSON,
        output_destination=None,
        error_on_findings=False,
        verbose_errors=False,
        strict=False,
        timeout_threshold=3,
        # json_stats=False,
        output_per_finding_max_lines_limit=None,
    )
    try:
        output_handler = OutputHandler(output_settings)
        (
            filtered_matches_by_rule,
            semgrep_errors,
            all_targets,
            renamed_targets,
            ignore_log,
            filtered_rules,
            profiler,
            profiling_data,
            parsing_data,
            explanations,
            shown_severities,
            lockfile_scan_info,
        ) = semgrep_main.main(
            output_handler=output_handler,
            target=files_to_scan,
            jobs=cpu_count,
            pattern=None,
            lang=None,
            configs=[project_rules_path],
            timeout=0,
            timeout_threshold=3,
            exclude=ignore,
            # I don't give a f*** about your .semgrepignore
            disable_nosem=True,
        )
        output_handler.rule_matches = [
            m for ms in filtered_matches_by_rule.values() for m in ms
        ]
        return output_handler._build_output()
    except SemgrepError as e:
        raise Exception(
            "SemgrepError", output_handler.semgrep_structured_errors[0].long_msg
        )


def save_sast_result(analysis, sast_result):
    """Save Semgrep JSON results as a file in the project's directory.

    Args:
        analysis (Analysis): corresponding analysis
        sast_result (str): Semgrep JSON results as string
    """
    filename = os.path.join(
        PROJECTS_SRC_PATH,
        str(analysis.project.id),
        "sast_analysis_" + str(analysis.id) + ".json",
    )
    f = open(filename, "a")
    f.write(sast_result)
    f.close()


def load_sast_scan_results(analysis, semgrep_output):
    """Populate an Analysis object with the result of a Semgrep scan.

    Args:
        analysis (Analysis): corresponding analysis
        semgrep_output (str): Semgrep JSON output as string
    """
    vulns = list()
    if semgrep_output != "":
        json_result = json.loads(semgrep_output)
        if json_result is not None:
            # Ignore errors, focus on results
            if "results" in json_result:
                results = json_result["results"]
                for c_result in results:
                    title = c_result["check_id"].split(".")[-1]
                    # Is it a new vulnerability or another occurence of a known one?
                    e_vulns = [v for v in vulns if v.title == title]
                    if len(e_vulns) == 0:
                        # Create a new vulnerability
                        n_vuln = load_vulnerability(title, c_result)
                        n_vuln.occurences.append(load_occurence(c_result))
                        vulns.append(n_vuln)
                    else:
                        # Add an occurence to an existing vulnerability
                        e_vuln = e_vulns[0]
                        e_vuln.occurences.append(load_occurence(c_result))
                        analysis.vulnerabilities = vulns


def load_vulnerability(title, sast_result):
    """Create a vulnerability object from a 'result' element of semgrep JSON results.

    Args:
        title (string): finding's title
        sast_result (dict): 'result' elements with its properties

    Returns:
        Vulnerability: fully populated vulnerability
    """
    vuln = Vulnerability(title=title)
    extra = sast_result["extra"]
    if "message" in extra:
        vuln.description = extra["message"]
    if "metadata" in extra:
        metadata = extra["metadata"]
        if "cwe" in metadata:
            # There may be multiple CWE ids
            if type(metadata["cwe"]) is list:
                vuln.cwe = metadata["cwe"][0]
            else:
                vuln.cwe = metadata["cwe"]
        if "owasp" in metadata:
            # There may be multiple OWASP ids (eg. 2017, 2021...)
            if type(metadata["owasp"]) is list:
                vuln.owasp = metadata["owasp"][0]
            else:
                vuln.owasp = metadata["owasp"]
        if "references" in metadata:
            vuln.references = " ".join(metadata["references"])
        vuln.severity = generate_severity(vuln.cwe)
    return vuln


def load_occurence(sast_result):
    """Create an occurence object from a 'result' element of semgrep JSON results.

    Args:
        sast_result (dict): 'result' elements with its properties

    Returns:
        Occurence: fully populated occurence
    """
    pattern = PROJECTS_SRC_PATH + "[\\/]?\d+[\\/]" + EXTRACT_FOLDER_NAME + "[\\/]?"
    clean_path = re.sub(pattern, "", sast_result["path"])
    occurence = Occurence(
        file_path=clean_path, match_string=sast_result["extra"]["lines"]
    )
    occurence.position = Position(
        line_start=sast_result["start"]["line"],
        line_end=sast_result["end"]["line"],
        column_start=sast_result["start"]["col"],
        column_end=sast_result["end"]["col"],
    )
    return occurence


def generate_semgrep_options(analysis):
    """Generate semgrep options depending on the attributes of an analysis.

    Args:
        analysis (Analysis): generate options for this analysis and parent project

    Returns:
        files_to_scan (list): files' paths to be scanned
        project_rules_path (str): path to the folder with semgrep YML rules
        ignore (list): patterns of paths / filenames to skip
    """
    # Define the scan path
    scan_path = os.path.join(
        PROJECTS_SRC_PATH, str(analysis.project.id), EXTRACT_FOLDER_NAME
    )
    # Define rules path
    project_rules_path = os.path.join(
        PROJECTS_SRC_PATH, str(analysis.project.id), "rules"
    )
    # Consolidate ignore list
    ignore = set(
        # Remove empty elements
        filter(None, analysis.ignore_filenames.split(","))
    )
    # Get all files corresponding to target extensions in project's source
    files_to_scan = list()
    for c_rule_pack in analysis.rule_packs:
        for c_language in c_rule_pack.languages:
            # Remove empty elements
            extensions = filter(None, c_language.extensions.split(","))
            for c_ext in extensions:
                files_to_scan += glob(
                    pathname=os.path.join(scan_path, "**", "*" + c_ext), recursive=True
                )
    return (files_to_scan, project_rules_path, ignore)


def import_rules(analysis, rule_folder):
    """Copy all YML files corresponding to rules of an analysis' rule packs into a (project) folder.

    Args:
        analysis (Analysis): analysis object of the project in whose folder rules should be imported
        rule_folder (str): destination folder (usually data/projects/<project_id>/rules/)
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
## SCA scan utils
##


def sca_scan(project):
    """Launch a depscan analysis. SBOM (Software Bill Of Material) will firstly be generated
    using `cdxgen'. The resulting BOM file will then be analyzed with depscan.

    Args:
        project (Project): corresponding target projet

    Returns:
        [dict]: depscan results (CycloneDX BOM+VEX)
    """
    source_path = os.path.join(PROJECTS_SRC_PATH, str(project.id), EXTRACT_FOLDER_NAME)
    output_folder = os.path.join(PROJECTS_SRC_PATH, str(project.id), DEPSCAN_RESULT_FOLDER)
    # Generate SBOM with cdxgen
    #bom_file = os.path.join(output_folder, BOM_FILE)
    #subprocess.run([CDXGEN, "-r", source_path, "-o", bom_file])
    # Launch depscan analysis
    subprocess.run(
        [
            DEPSCAN,
            "--no-banner",
            "--no-error",
            "--src",
            source_path,
            #"--bom",
            #bom_file,
            "--reports-dir",
            output_folder,
        ]
    )
    # Return depscan JSON result as list of dicts
    result = list()
    vex_files = glob(pathname=os.path.join(output_folder, "*.vex.json"))
    for file in vex_files:
        with open(file) as f:
            result.append(json.load(f))

    #f = open(os.path.join(output_folder, DEPSCAN_RESULT_FILE))
    #c = json.load(f)
    #f.close()
    return result


def load_sca_scan_results(analysis, dict_sca_results):
    """Populate an Analysis object with the result of an SCA (depscan) scan.

    Args:
        analysis (Analysis): corresponding analysis
        dict_sca_results (dict): depscan results (CycloneDX BOM+VEX)
    """
    vuln_deps = list()
    for sca_results in dict_sca_results:
        for c_vuln in sca_results["vulnerabilities"]:
            # Identify affected dependency
            bom_ref = c_vuln["bom-ref"]
            pkg_type = bom_ref.split("/")[1].split(":")[1]
            pkg_ref = bom_ref.split(":")[1].split("@")[0].replace(pkg_type + "/", "")
            pkg_name = bom_ref.split(":")[1].split("@")[0].split("/")[-1]
            # Get the source URL
            source ="N/A"
            if "source" in c_vuln and "url" in c_vuln["source"]:
                source = c_vuln["source"]["url"]
            elif "url" in c_vuln:
                source = c_vuln["url"] 
            # Retrieve ratings information
            severity = cvss_score = cvss_version = "N/A"
            if "ratings" in c_vuln and len(c_vuln["ratings"]) > 0:
                if "severity" in c_vuln["ratings"][0]:
                    severity =  c_vuln["ratings"][0]["severity"]
                if "score" in c_vuln["ratings"][0]:
                    cvss_score =  c_vuln["ratings"][0]["score"]
                if "method" in c_vuln["ratings"][0]:
                    cvss_version =  c_vuln["ratings"][0]["method"]
            # Search for affected and fixed versions    
            for v in c_vuln["affects"][0]["versions"]:
                if v["status"] == "affected":
                    version = v["version"]
                elif v["status"] == "unaffected":
                    fix_version = v["version"]
            # Search for insights
            for v in c_vuln["properties"]:
                prioritized = False
                if v["name"] == "depscan:prioritized" and v["value"] == "true":
                    prioritized = True
                elif v["name"] == "depscan:insights":
                    vendor_confirmed = True if "Vendor Confirmed" in v["value"] else False
                    has_poc = True if "Has PoC" in v["value"] else False
                    has_exploit = True if "Known Exploits" in v["value"] else False
                    direct = True if "Direct usage" in v["value"] else False
                    indirect = True if "Indirect dependency" in v["value"] else False
            # Register CWEs if any
            cwes = ""
            if "cwes" in c_vuln["ratings"]:
                cwes = c_vuln["ratings"]["cwes"].join(",")
            # Populate VulnerableDependency object
            vuln_deps.append(   
                VulnerableDependency(
                    common_id=c_vuln["id"],
                    bom_ref=bom_ref,
                    pkg_type=pkg_type,
                    pkg_ref=pkg_ref,
                    pkg_name=pkg_name,
                    source=source,
                    severity=severity,
                    cvss_score=cvss_score,
                    cvss_version=cvss_version,
                    cwes=cwes,
                    description=c_vuln["description"],
                    recommendation=c_vuln["recommendation"],
                    version=version,
                    fix_version=fix_version,
                    prioritized=prioritized,
                    vendor_confirmed=vendor_confirmed,
                    has_poc=has_poc,
                    has_exploit=has_exploit,
                    direct=direct,
                    indirect=indirect
                )
            )
            # Add VulnerableDependency into the analysis
            analysis.vulnerable_dependencies = vuln_deps
            current_app.logger.debug(
            "New vulnerable dependency %s added to the analysis with id=%i", c_vuln["id"], analysis.id
        )

##
## Inspector scan utils
##


def inspector_scan(project_id):
    """Microsoft Application Inspector is a software source code characterization tool
    that helps identify coding features of first or third party software components based
    on well-known library/API calls and is helpful in security and non-security use cases.

    Args:
        project_id (Project): project.id
    """
    source_path = os.path.join(PROJECTS_SRC_PATH, str(project_id), EXTRACT_FOLDER_NAME)
    # Call to external binary: ApplicationInspector.CLI
    cwd = os.getcwd()
    subprocess.run(
        [
            APPLICATION_INSPECTOR,
            "analyze",
            "-s",
            f"{source_path}/",
            "-f",
            "json",
            "-o",
            f"{cwd}/data/projects/{project_id}/{EXTRACT_FOLDER_NAME}.json",
        ],
        capture_output=True,
    ).stdout
    f = open(f"{cwd}/data/projects/{project_id}/{EXTRACT_FOLDER_NAME}.json")
    json_result = json.load(f)
    f.close()
    return json_result


def load_inspector_results(app_inspector, inspector_result):
    """Populate an AppInspector object with the result of a Application Inspector scan.

    Args:
        inspector_result (str): Application Inspector JSON output.
        app_inspector(AppInspector): Application Inspector object filter by ID.
    """
    match = list()

    if inspector_result != "":
        if "metaData" in inspector_result:
            data = inspector_result["metaData"]
            if "detailedMatchList" in data:
                detailed = data["detailedMatchList"]
                # we go through the dictionary again and again
                for data_in_detailed in detailed:
                    title = data_in_detailed["ruleName"]
                    e_match = [m for m in match if m.title == title]
                    if len(e_match) == 0:
                        # Creation of a match and an associated tag
                        n_match = load_match(title, data_in_detailed)
                        n_match.tag.append(load_tags(data_in_detailed))
                        match.append(n_match)
                    else:
                        e_matchs = e_match[0]
                        e_matchs.tag.append(load_tags(data_in_detailed))
                        app_inspector.match = match


def load_match(title, detailed):
    """Create a match object from a 'result' element of app_inspector JSON results.

    Args:
        title (string): finding's title
        inspector_result (dict): 'result' elements with its properties

    Returns:
        Match: fully populated match
    """

    match = Match(title=title)
    if detailed != "":
        if "ruleDescription" in detailed:
            match.description = detailed["ruleDescription"]
        if "pattern" in detailed:
            match.pattern = detailed["pattern"]
        if "fileName" in detailed:
            match.filename = detailed["fileName"]
        if "tags" in detailed and len(detailed["tags"]):
            match.tags = detailed["tags"][0]

    return match


def load_tags(data_in_detailed):
    """Create an tags and occurencde object from a 'data' element of application inspector JSON results.

    Args:
        data_in_detailed (dict): 'data' elements with its properties

    Returns:
        Occurence: fully populated occurence
    """
    tags = InspectorTag(
        start_line=data_in_detailed["startLocationLine"],
        start_column=data_in_detailed["startLocationColumn"],
        end_column=data_in_detailed["endLocationColumn"],
        end_line=data_in_detailed["endLocationLine"],
        excerpt=data_in_detailed["excerpt"],
        filename=data_in_detailed["fileName"],
    )
    if "severity" in data_in_detailed:
        tags.severity = data_in_detailed["severity"]
    return tags

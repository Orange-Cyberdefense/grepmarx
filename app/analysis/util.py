# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import html
import json
import logging
import re
import os
import re
from datetime import datetime
from difflib import Match
from glob import glob
from shutil import copyfile, rmtree
import subprocess
import traceback

from flask import current_app


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
    VulnerableDependencyReference,
)
from app.constants import (
    APPLICATION_INSPECTOR,
    APPLICATION_INSPECTOR_TIMEOUT,
    DEPSCAN,
    DEPSCAN_TIMEOUT,
    RESULT_FOLDER,
    EXTRACT_FOLDER_NAME,
    PROJECTS_SRC_PATH,
    RULE_EXTENSIONS,
    RULES_PATH,
    SCAN_LOGS_FOLDER,
    SEMGREP,
    SEMGREP_MAX_FILES,
    SEMGREP_TIMEOUT,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STATUS_ABORTED,
    STATUS_ANALYZING,
    STATUS_ERROR,
    STATUS_FINISHED,
    INSIGHTS_MAPPING,
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
def async_scan(self, analysis_id):
    """Launch a new code scan on the project corresponding to the given analysis ID, asynchronously through celery.

    Args:
        analysis_id (int): ID of the analysis to populate with the results
    """
    current_app.logger.info("Entering async scan for analysis with id=%i", analysis_id)
    analysis = Analysis.query.filter_by(id=analysis_id).first()
    # Create a dedicated logging handler for this scan
    analysis_log_to_file(analysis)
    # Status in now Analysing
    analysis.started_on = datetime.now()
    analysis.project.status = STATUS_ANALYZING
    analysis.task_id = self.request.id
    db.session.commit()
    current_app.logger.info(
        "[Analysis %i] New analysis started for project '%s' (project id=%i)",
        analysis.id,
        analysis.project.name,
        analysis.project.id,
    )
    # Prepare semgrep options
    files_to_scan, project_rules_path, ignore = generate_semgrep_options(analysis)
    try:
        # SAST scan: invoke semgrep
        sast_scan(analysis, files_to_scan, project_rules_path, ignore)

        # SCA scan: invoke depscan
        sca_result = sca_scan(analysis)
        load_sca_scan_results(analysis, sca_result)

        # Inspector scan: invoke ApplicationInspector
        inspector_result = inspector_scan(analysis)
        load_inspector_results(analysis, inspector_result)

        analysis.project.status = STATUS_FINISHED
    except Exception as e:
        current_app.logger.exception(
            "[Analysis %i] Error while scanning project '%s' (project id=%i)",
            analysis.id,
            analysis.project.name,
            analysis.project.id,
        )
        analysis.project.error_message = (
            repr(e) + "\nCheck scan logs for more details"
        )
        analysis.project.status = STATUS_ERROR

    # Done
    analysis.finished_on = datetime.now()
    analysis.task_id = ""
    # Update project properties
    analysis.project.occurences_count = count_occurences(analysis.project)
    analysis.project.risk_level = calculate_risk_level(analysis.project)
    db.session.commit()
    current_app.logger.info(
        "[Analysis %i] Analysis ended for project '%s' (project id=%i)",
        analysis.id,
        analysis.project.name,
        analysis.project.id,
    )


def stop_analysis(analysis):
    task_id = analysis.task_id
    celery.control.revoke(task_id, terminate=True, signal="SIGKILL")
    analysis.project.status = STATUS_ABORTED
    analysis.task_id = ""
    db.session.commit()
    current_app.logger.info(
        "Analysis stopped for project with id=%i", analysis.project.id
    )


##
## SAST scan utils
##


def remove_ignored_files(files_paths, ignore):
    result = []
    if not ignore:
        return files_paths
    for path in files_paths:
        should_include = True
        for data in ignore:
            if data in path:
                should_include = False
                break
        if should_include:
            result.append(path)
    return result


def sast_scan(analysis, files_to_scan, project_rules_path, ignore):
    """Run Semgrep, possibly multiple times if there is a lot of files,
    in order to avoid issues with shell limits. The maximum number of files
    for a specific scan is defined in utils.SEMGREP_MAX_FILES.

    Args:
        analysis (Analysis): analysis to populate with semgrep results
        files_to_scan (list): files' paths to be scanned
        project_rules_path (str): path to the folder with semgrep YML rules
        ignore (list): patterns of paths / filenames to skip
    """
    current_app.logger.info("[Analysis %i] Starting SAST scan (semgrep)", analysis.id)
    total_scans = int(len(files_to_scan) / SEMGREP_MAX_FILES) + 1
    # Run semgrep multiple times if there is a lot of files to avoid issues with shell limits
    for i in range(0, len(files_to_scan), SEMGREP_MAX_FILES):
        current_app.logger.info(
            "[Analysis %i] Semgrep execution %i / %i",
            analysis.id,
            int(i / SEMGREP_MAX_FILES) + 1,
            total_scans,
        )
        files_chunk = files_to_scan[i : i + SEMGREP_MAX_FILES]
        sast_result = semgrep_invoke(files_chunk, project_rules_path, ignore)
        # Save results on disk to allow download
        save_sast_result(analysis, sast_result, i)
        # Load results into the analysis object
        load_sast_scan_results(analysis, sast_result)
        current_app.logger.info(
            "[Analysis %i] SAST scan (semgrep) finished", analysis.id
        )


def semgrep_invoke(files_to_scan, project_rules_path, ignore):
    """Launch a semgrep scan.

    Args:
        files_to_scan (list): files' paths to be scanned
        project_rules_path (str): path to the folder with semgrep YML rules
        ignore (list): patterns of paths / filenames to skip

    Returns:
        [str]: Semgrep JSON output
    """
    files_to_scan = remove_ignored_files(files_to_scan, ignore)
    if len(files_to_scan) <= 0:
        return ""
    result = ""
    cmd = [
        SEMGREP,
        "scan",
        "--config",
        project_rules_path,
        "--disable-nosem",
        "--json",
    ] + files_to_scan

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SEMGREP_TIMEOUT
        ).stdout
    # Other exceptions will be catched in async_scan()
    except subprocess.TimeoutExpired:
        current_app.logger.warning(
            "Semgrep scan was cancelled because exceeding defined timeout (%i seconds)",
            SEMGREP_TIMEOUT,
        )

    return result


def save_sast_result(analysis, sast_result, step):
    """Save Semgrep JSON results as a file in the project's directory.

    Args:
        analysis (Analysis): corresponding analysis
        sast_result (str): Semgrep JSON results as string
    """
    filename = os.path.join(
        PROJECTS_SRC_PATH,
        str(analysis.project.id),
        RESULT_FOLDER,
        f"sast_report_{step}.json",
    )
    current_app.logger.info(
        "[Analysis %i] Saving semgrep results on disk: %s", analysis.id, filename
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
    # vulns = list()
    current_app.logger.info(
        "[Analysis %i] Loading semgrep results in database", analysis.id
    )
    if semgrep_output != "":
        json_result = json.loads(semgrep_output)
        if json_result is not None:
            # Ignore errors, focus on results
            if "results" in json_result:
                results = json_result["results"]
                current_app.logger.info(
                    "[Analysis %i] Found %i semgrep results", analysis.id, len(results)
                )
                for c_result in results:
                    title = c_result["check_id"].split(".")[-1]
                    # Is it a new vulnerability or another occurence of a known one?
                    e_vulns = [v for v in analysis.vulnerabilities if v.title == title]
                    if len(e_vulns) == 0:
                        # Create a new vulnerability
                        n_vuln = load_vulnerability(title, c_result)
                        n_vuln.occurences.append(load_occurence(c_result))
                        analysis.vulnerabilities.append(n_vuln)
                    else:
                        # Add an occurence to an existing vulnerability
                        e_vuln = e_vulns[0]
                        e_vuln.occurences.append(load_occurence(c_result))


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
        # Add impact, likelihood and confidence if present
        if "impact" in metadata:
            vuln.impact = metadata["impact"]
        if "likelihood" in metadata:
            vuln.likelihood = metadata["likelihood"]
        if "confidence" in metadata:
            vuln.confidence = metadata["confidence"]
        if "references" in metadata:
            vuln.references = " ".join(metadata["references"])
        # Replace rule level/severity by a calculated one
        vuln.severity = extra["severity"]
        generate_severity(vuln)
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
    current_app.logger.info("[Analysis %i] Setting up semgrep options", analysis.id)
    # Define the scan path
    scan_path = os.path.join(
        PROJECTS_SRC_PATH, str(analysis.project.id), EXTRACT_FOLDER_NAME
    )
    current_app.logger.info("[Analysis %i] Scan path: %s", analysis.id, scan_path)
    # Define rules path
    project_rules_path = os.path.join(
        PROJECTS_SRC_PATH, str(analysis.project.id), "rules"
    )
    current_app.logger.info(
        "[Analysis %i] Rules path: %s", analysis.id, project_rules_path
    )
    # Consolidate ignore list
    ignore = set(
        # Remove empty elements
        filter(None, analysis.ignore_filenames.split(","))
    )
    current_app.logger.info("[Analysis %i] Ignore list: %s", analysis.id, str(ignore))
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
    current_app.logger.info(
        "[Analysis %i] Found %i files to scan", analysis.id, len(files_to_scan)
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
            # Local custom rule
            if c_rule.repository is None or c_rule.category is None:
                dst = os.path.join(
                    rule_folder,
                    c_rule.title + next(iter(RULE_EXTENSIONS)),
                )
            # Repository rule
            else:
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
    for severity in (
        SEVERITY_CRITICAL,
        SEVERITY_HIGH,
        SEVERITY_MEDIUM,
        SEVERITY_LOW,
        SEVERITY_INFO,
    ):
        r_vulns += [
            vuln for vuln in analysis.vulnerabilities if vuln.severity == severity
        ]
    return r_vulns


##
## SCA scan utils
##


def sca_scan(analysis):
    """Launch a depscan scan. SBOM (Software Bill Of Material) will firstly be generated
    using `cdxgen'. The resulting BOM file will then be analyzed with depscan.

    Args:
        analysis (Analysis): corresponding analysis

    Returns:
        [dict]: depscan results (CycloneDX BOM+VEX)
    """
    current_app.logger.info("[Analysis %i] Starting SCA scan (depscan)", analysis.id)
    source_path = os.path.join(
        os.getcwd(), PROJECTS_SRC_PATH, str(analysis.project.id), EXTRACT_FOLDER_NAME
    )
    current_app.logger.info(
        "[Analysis %i] Depscan source path: %s", analysis.id, source_path
    )
    output_folder = os.path.join(
        os.getcwd(), PROJECTS_SRC_PATH, str(analysis.project.id), RESULT_FOLDER
    )
    current_app.logger.info(
        "[Analysis %i] Depscan output folder: %s", analysis.id, output_folder
    )
    # Clean previous depscan results
    delete_sca_files(output_folder)
    # Launch depscan analysis
    current_app.logger.info("[Analysis %i] Depscan execution", analysis.id)
    try:
        subprocess.run(
            cwd=source_path,
            timeout=DEPSCAN_TIMEOUT,
            args=[
                DEPSCAN,
                "--no-banner",
                "--no-error",
                "--no-vuln-table",
                "--sync",
                "--src",
                source_path,
                "--reports-dir",
                output_folder,
            ],
        )
    # Other exceptions will be catched in async_scan()
    except subprocess.TimeoutExpired:
        current_app.logger.warning(
            "Depscan scan was cancelled because exceeding defined timeout (%i seconds)",
            DEPSCAN_TIMEOUT,
        )
    # Return depscan JSON result as list of dicts
    result = list()
    vex_files = glob(pathname=os.path.join(output_folder, "*.vdr.json"))
    for file in vex_files:
        with open(file) as f:
            result.append(json.load(f))
    current_app.logger.info("[Analysis %i] SCA scan (depscan) finished", analysis.id)
    return result


def delete_sca_files(folder):
    for filename in os.listdir(folder):
        if "depscan" in filename or "sbom" in filename:
            file_path = os.path.join(folder, filename)
            if os.path.isfile(file_path) or os.path.islink(file_path):
                try:
                    os.unlink(file_path)
                except Exception as e:
                    current_app.logger.error("Failed to delete %s: %s" % (file_path, e))


def load_sca_scan_results(analysis, dict_sca_results):
    """Populate an Analysis object with the result of an SCA (depscan) scan.

    Args:
        analysis (Analysis): corresponding analysis
        dict_sca_results (dict): depscan results (CycloneDX BOM+VEX)
    """
    vuln_deps = list()
    current_app.logger.info(
        "[Analysis %i] Loading depscan results in database", analysis.id
    )
    # Prepare regex pattern to remove absolute path from filenames
    pattern = f".*/{PROJECTS_SRC_PATH}{analysis.project.id}/{EXTRACT_FOLDER_NAME}/"
    for sca_results in dict_sca_results:
        current_app.logger.info(
            "[Analysis %i] Found %i depscan results",
            analysis.id,
            len(sca_results["vulnerabilities"]),
        )
        for c_vuln in sca_results["vulnerabilities"]:
            # Identify affected dependency
            bom_ref = c_vuln["bom-ref"]
            pkg_type = bom_ref.split("/")[1].split(":")[1]
            pkg_ref = bom_ref.split(":")[1].split("@")[0].replace(pkg_type + "/", "")
            pkg_name = bom_ref.split(":")[1].split("@")[0].split("/")[-1]
            # Get the source URL
            source = "N/A"
            if "source" in c_vuln and "url" in c_vuln["source"]:
                source = c_vuln["source"]["url"]
            elif "url" in c_vuln:
                source = c_vuln["url"]
            # Retrieve ratings information
            severity = cvss_score = cvss_version = "N/A"
            if "ratings" in c_vuln and len(c_vuln["ratings"]) > 0:
                if "severity" in c_vuln["ratings"][0]:
                    severity = c_vuln["ratings"][0]["severity"]
                if "score" in c_vuln["ratings"][0]:
                    cvss_score = c_vuln["ratings"][0]["score"]
                if "method" in c_vuln["ratings"][0]:
                    cvss_version = c_vuln["ratings"][0]["method"]
            # Search for affected and fixed versions
            version = ""
            fix_version = ""
            for v in c_vuln["affects"][0]["versions"]:
                if v["status"] == "affected" and v["version"] is not None:
                    version = v["version"]
                elif v["status"] == "unaffected":
                    fix_version = v["version"]
            # Search for insights
            insights = {}
            for v in c_vuln["properties"]:
                prioritized = False
                if v["name"] == "depscan:prioritized" and v["value"] == "true":
                    prioritized = True
                elif v["name"] == "depscan:insights":
                    for key, value in INSIGHTS_MAPPING.items():
                        insights[key] = True if value in v["value"] else False
            # Register CWEs if any
            cwes = ""
            if "cwes" in c_vuln and len(c_vuln["cwes"]) > 0:
                cwes = ",".join(str(c) for c in c_vuln["cwes"])
            # Get advisories
            advisories = list()
            if "advisories" in c_vuln:
                for adv in c_vuln["advisories"]:
                    advisories.append(
                        VulnerableDependencyReference(
                            title=adv["title"], url=adv["url"]
                        )
                    )
            # Gets dependency tree
            dep_str = None
            if (
                "analysis" in c_vuln
                and "detail" in c_vuln["analysis"]
                and "Dependency Tree: " in c_vuln["analysis"]["detail"]
            ):
                dep_lst = json.loads(
                    c_vuln["analysis"]["detail"].replace("Dependency Tree: ", "")
                )
                dep_str = ",".join([dep.split("/")[-1] for dep in dep_lst])
            # Gets the dependency's sources from the components dict
            comp_src = ""
            for c_comp in sca_results["components"]:
                if c_comp["bom-ref"] == c_vuln["affects"][0]["ref"]:
                    if "properties" in c_comp:
                        for c_comp_property in c_comp["properties"]:
                            if c_comp_property["name"] == "SrcFile":
                                new_src = re.sub(pattern, "", c_comp_property["value"])
                                comp_src = f"{comp_src}{new_src},"
                    break
            # Populate VulnerableDependency object
            vuln_dep = VulnerableDependency(
                common_id=c_vuln["id"],
                bom_ref=bom_ref,
                pkg_type=pkg_type,
                pkg_ref=pkg_ref,
                pkg_name=pkg_name,
                dependency_tree=dep_str,
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
                source_files=comp_src,
            )
            # Add insights
            for key, value in insights.items():
                setattr(vuln_dep, key, value)
            vuln_deps.append(vuln_dep)
            # Add VulnerableDependency into the analysis
            analysis.vulnerable_dependencies = vuln_deps


def md2html(string):
    """A very quick and dirty way to make markdown descriptions a bit more presentable
    in HTML. The goal is not to have full markdown support, but only to handle
    most commonly used syntax in CVE descriptions: titles, code, line breaks...

    Args:
        string (String): markdown string to convert to HTML
    """
    # Encode any HTML present in the original description to avoid XSS
    string = html.escape(string)
    # Place titles in <strong>
    string = re.sub(r"^#+\s*(.*)", r"<strong>\1</strong>", string, flags=re.MULTILINE)
    # Place code samples in <pre>
    string = re.sub(
        r"```(.*?)```",
        r'<pre class="modal-code text-monospace">\1</pre>',
        string,
        flags=re.DOTALL,
    )
    # Place backticks terms in <code>
    string = re.sub(r"`(.*?)`", r"<code>\1</code>", string)
    # Replace line breaks with <br />
    string = re.sub(r"\n", "<br />", string)
    # Allow maximum 2 consecutive <br />
    string = re.sub(r"(<br\s*/?>\s*){3,}", "<br /><br />", string)
    return string


##
## Inspector scan utils
##


def inspector_scan(analysis):
    """Microsoft Application Inspector is a software source code characterization tool
    that helps identify coding features of first or third party software components based
    on well-known library/API calls and is helpful in security and non-security use cases.

    Args:
        project_id (Project): project.id
    """
    current_app.logger.info(
        "[Analysis %i] Starting Inspector scan (ApplicationInspector)", analysis.id
    )
    source_path = os.path.join(
        PROJECTS_SRC_PATH, str(analysis.project.id), EXTRACT_FOLDER_NAME
    )
    cwd = os.getcwd()
    output_file = f"{cwd}/data/projects/{analysis.project.id}/{RESULT_FOLDER}/inspector_report.json"

    try:
        # Call to external binary: ApplicationInspector.CLI
        subprocess.run(
            [
                APPLICATION_INSPECTOR,
                "analyze",
                "-s",
                f"{source_path}/",
                "-f",
                "json",
                "-o",
                output_file,
            ],
            capture_output=True,
            timeout=APPLICATION_INSPECTOR_TIMEOUT,
        ).stdout
    # Other exceptions will be catched in async_scan()
    except subprocess.TimeoutExpired:
        current_app.logger.warning(
            "ApplicationInspector scan was cancelled because exceeding defined timeout (%i seconds)",
            APPLICATION_INSPECTOR_TIMEOUT,
        )

    if os.path.exists(output_file):
        f = open(output_file)
    try:
        json_result = json.load(f)
    except json.JSONDecodeError as e:
        current_app.logger.error(
            "[Analysis %i] Error when gathering results file for Application Inspector scan (file is probably empty)",
            analysis.id,
        )
        return ""
    f.close()
    current_app.logger.info(
        "[Analysis %i] Inspector scan (ApplicationInspector) finished", analysis.id
    )
    return json_result


def load_inspector_results(analysis, inspector_result):
    """Populate an AppInspector object with the result of a Application Inspector scan.

    Args:
        inspector_result (str): Application Inspector JSON output
        Analysis (Analysis): Corresponding analysis
    """
    current_app.logger.info(
        "[Analysis %i] Loading AppInspector results in database", analysis.id
    )
    match = list()
    # create a new app inspector
    analysis.project.appinspector = AppInspector()
    if inspector_result != "":
        if "metaData" in inspector_result:
            data = inspector_result["metaData"]
            if "detailedMatchList" in data:
                detailed = data["detailedMatchList"]
                current_app.logger.info(
                    "[Analysis %i] Found %i AppInspector results",
                    analysis.id,
                    len(detailed),
                )
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
                        analysis.project.appinspector.match = match


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


def analysis_log_to_file(analysis):
    """Add to the current logger a handler in order to log analysis events into a local file.

    Args:
        analysis (Analysis): corresponding analysis
    """
    # Remove remaining handlers from other scans
    current_app.logger.handlers.clear()
    # Create folder for logs if not already there
    logs_path = os.path.join(
        os.getcwd(), PROJECTS_SRC_PATH, str(analysis.project.id), SCAN_LOGS_FOLDER
    )
    if not os.path.isdir(logs_path):
        os.mkdir(logs_path)
    # Add a new handler to write in the current analysis local logs
    log_file = os.path.join(logs_path, str(analysis.id) + ".log")
    handler = logging.FileHandler(log_file)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    current_app.logger.addHandler(handler)

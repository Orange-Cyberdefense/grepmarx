# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import json
import os
import re
import subprocess
from hashlib import sha256
from shutil import rmtree
from zipfile import ZipFile, is_zipfile

from pyparsing import Regex

from app import db
from app.constants import APP_INSP_PATH, EXTRACT_FOLDER_NAME, PROJECTS_SRC_PATH, SCC_PATH
from app.projects.models import LanguageLinesCount, ProjectLinesCount
from app.rules.models import SupportedLanguage

##
## Project utils
##


def remove_project(project):
    """Delete the project from the database (along with all its analysis), and
    remove the project folder from disk.

    Args:
        project (Project): project to remove
    """
    project_path = os.path.join(PROJECTS_SRC_PATH, str(project.id))
    if os.path.isdir(project_path):
        rmtree(project_path)
    db.session.delete(project)
    db.session.commit()




def application_inspector_scan(project_id):

    """Microsoft Application Inspector is a software source code characterization tool 
    that helps identify coding features of first or third party software components based 
    on well-known library/API calls and is helpful in security and non-security use cases.

    Args:
        project_id (Project): project.id 
    """

    source_path = os.path.join(PROJECTS_SRC_PATH, str(project_id), EXTRACT_FOLDER_NAME)
    # Call to external binary: ApplicationInspector.CLI
    cwd = os.getcwd()


    
    cmdline=subprocess.run(
            [APP_INSP_PATH,"analyze", "-s",f"{source_path}/", "-f","json","-o",f"{cwd}/data/projects/{project_id}/{EXTRACT_FOLDER_NAME}.json"], capture_output=True
        ).stdout
    print(cmdline)
    # #Excute App inspector binary and format json 
    # json_split = json_cmdline.replace(b'\n',b'')
    # #Replace \n by ""
    # json_convert = json_split.decode('utf-8')
    # #Convert bytes to String
    # json_regex= re.match(r"(\{[^}]+\}\}{1-9})", json_convert, re.MULTILINE)
    # #Use regular expression to exact match json part to use json.loads function 
    # json_match=json_regex.group(1)
    f= open(f"{cwd}/data/projects/{project_id}/{EXTRACT_FOLDER_NAME}.json")
    json_result= json.load(f)
    f.close()
    return json_result



def count_lines(project):
    """Count line of code of the project's code archive using third-party tool
    scc, and populate the ProjectLinesCount class member.

    Args:
        project (project): project with an already extracted source archive
    """
    source_path = os.path.join(PROJECTS_SRC_PATH, str(project.id), EXTRACT_FOLDER_NAME)
    # Call to external binary: scc
    json_result = json.loads(
        subprocess.run(
            [SCC_PATH, source_path, "-f", "json"], capture_output=True
        ).stdout
    )
    project.project_lines_count = load_project_lines_count(json_result)


def sha256sum(file_path):
    """Calculate the SHA256 sum of a file.

    Args:
        file_path (str): file for which to calculate the sum

    Returns:
        str: digest of the SHA256 sum
    """
    sha256_hash = sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()


def check_zipfile(zip_path):
    """Check if a zip file is valid and unencrypted.

    Args:
        zip_path (str): path to the zip file

    Returns:
        [bool]: true if the file is valid and unencrypted
        [str]: short error message if the file is invalid or encrypted
    """
    error = False
    msg = ""
    if not is_zipfile(zip_path):
        error = True
        msg = "invalid zip file"
    else:
        for zinfo in ZipFile(zip_path, "r").infolist():
            if zinfo.flag_bits & 0x1:
                error = True
                msg = "encrypted zip file"
                break
    return error, msg


def count_occurences(project):
    """Count the total number of vulnerability occurences for a project.
    An analysis must be associated to this project.

    Args:
        project (Project): Project for which occurences must be counted

    Returns:
        int: Total vulnerability occurences for the project
    """
    occurences_count = 0
    # We need an analysis to count occurences
    if project.analysis is not None:
        # Count the total number of vulnerability occurences
        for c_vulnerability in project.analysis.vulnerabilities:
            occurences_count = occurences_count + len(c_vulnerability.occurences)
    return occurences_count


def calculate_risk_level(project):
    """Calculate the risk level for a project. An analysis must be associated
    to this project. The risk level is calculated from a ratio between the
    number of findings and the number of lines of code.

    Args:
        project (Project): Project for which the risk level has to be calculated

    Returns:
        int: Calculated risk level (0 - 100)
    """
    risk_level = 0
    # We need an analysis to calculate a risk level
    if project.analysis is not None:
        # Make sure LOC count is > 0
        if (
            project.project_lines_count is not None
            and project.project_lines_count.total_code_count > 0
        ):
            # Calculate the actual risk level (to be improved)
            risk_level = (
                project.occurences_count / project.project_lines_count.total_code_count
            ) * 50000
            risk_level = int(round(risk_level))
            if risk_level > 100:
                risk_level = 100
    return risk_level


##
## ProjectLinesCount util
##


def top_language_lines_counts(project_lc, top_number):
    """Return the `top_number` most present languages in the project source archive,
    sorted by their lines counts.

    Args:
        project_lc (ProjectLinesCount): project lines count object populated with
        LanguageLinesCount
        top_number (int): number defining how many LanguageLinesCount to return

    Returns:
        list: LanguageLinesCount objects corresponding to the `top_number` most
        present languages
    """
    return sorted(
        project_lc.language_lines_counts, key=lambda x: x.code_count, reverse=True
    )[:top_number]


def top_supported_language_lines_counts(project_lc):
    """Return a list of SupportedLanguage objects corresponding to the supported
    languages detected in the project source archive, sorted by their lines counts.

    Args:
        project_lc (ProjectLinesCount): project lines count object populated with
        LanguageLinesCount

    Returns:
        list: LanguageLinesCount objects corresponding to supported languages
        detected in the project source archive, sorted by their lines counts
    """
    ret = list()
    languages = sorted(
        project_lc.language_lines_counts, key=lambda x: x.code_count, reverse=True
    )
    supported_languages = SupportedLanguage.query.all()
    for c_lang in languages:
        for c_sl in supported_languages:
            if c_sl.name.lower() == c_lang.language.lower():
                ret.append(c_sl)
    return ret


def load_project_lines_count(scc_result):
    """Create a new ProjectLinesCount object and populate it with the given scc
    results.

    Args:
        scc_result (list): deserialized (json.dumps) scc results

    Returns:
        ProjectLinesCount: fully populated project lines count object
    """
    # Empty ProjectLinesCount
    project_lc = ProjectLinesCount(
        total_file_count=0,
        total_line_count=0,
        total_blank_count=0,
        total_comment_count=0,
        total_code_count=0,
        total_complexity_count=0,
    )
    for c in scc_result:
        # Create a LanguageLineCount
        language_lines_count = LanguageLinesCount(
            language=c["Name"],
            file_count=c["Count"],
            line_count=c["Lines"],
            blank_count=c["Blank"],
            comment_count=c["Comment"],
            code_count=c["Code"],
            complexity_count=c["Complexity"],
        )
        project_lc.language_lines_counts.append(language_lines_count)
        # Update ProjectLineCount counters
        project_lc.total_file_count += c["Count"]
        project_lc.total_line_count += c["Lines"]
        project_lc.total_blank_count += c["Blank"]
        project_lc.total_comment_count += c["Comment"]
        project_lc.total_code_count += c["Code"]
        project_lc.total_complexity_count += c["Complexity"]
    return project_lc

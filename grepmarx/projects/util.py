# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import json
import os
import subprocess
from hashlib import sha256
from shutil import rmtree
from zipfile import ZipFile, is_zipfile

from grepmarx import db
from grepmarx.constants import EXTRACT_FOLDER_NAME, PROJECTS_SRC_PATH, SCC_PATH
from grepmarx.projects.models import ProjectLinesCount

##
## Project utils
##


def remove_project(project):
    """Delete the project from the database (along with all its analysis), and remove the project folder from disk.

    Args:
        project (Project): project to remove
    """
    project_path = os.path.join(PROJECTS_SRC_PATH, str(project.id))
    if os.path.isdir(project_path):
        rmtree(project_path)
    db.session.delete(project)
    db.session.commit()


def count_lines(project):
    """Count line of code of the project's code archive using third-party tool scc, and populate the ProjectLinesCount class member.

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
    project.project_lines_count = ProjectLinesCount.load_project_lines_count(
        json_result
    )


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

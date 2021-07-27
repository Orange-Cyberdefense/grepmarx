# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
import subprocess
import json
from shutil import rmtree

from sqlalchemy.sql.schema import ForeignKey

from grepmarx import db
from sqlalchemy import Column, Integer, String


class Project(db.Model):

    STATUS_NEW = 0
    STATUS_FINISHED = 1
    STATUS_ANALYZING = 2
    STATUS_ERROR = 3
    PROJECTS_SRC_PATH = "data/projects/"
    EXTRACT_FOLDER_NAME = "extract"

    __tablename__ = "Project"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    archive_filename = Column(String)
    archive_sha256sum = Column(String)
    status = Column(Integer, nullable=False, default=STATUS_NEW)
    error_message = Column(String)
    creator_id = db.Column(db.Integer, db.ForeignKey("User.id"), nullable=False)
    creator = db.relationship("User", backref=db.backref("projects", lazy=True))
    analysis = db.relationship(
        "Analysis",
        uselist=False,
        back_populates="project",
        cascade="all, delete-orphan",
    )
    project_lines_count = db.relationship(
        "ProjectLinesCount",
        uselist=False,
        back_populates="project",
        cascade="all, delete-orphan",
    )

    def remove(self):
        project_path = os.path.join(Project.PROJECTS_SRC_PATH, str(self.id))
        if os.path.isdir(project_path):
            rmtree(project_path)
        db.session.delete(self)
        db.session.commit()

    def count_lines(self):
        source_path = os.path.join(
            Project.PROJECTS_SRC_PATH, str(self.id), Project.EXTRACT_FOLDER_NAME
        )
        # Call to external binary: scc
        json_result = json.loads(
            subprocess.run(
                ["third-party/scc/scc", source_path, "-f", "json"], capture_output=True
            ).stdout
        )
        self.project_lines_count = ProjectLinesCount.load_project_lines_count(
            json_result
        )


class ProjectLinesCount(db.Model):

    __tablename__ = "ProjectLinesCount"

    id = Column("id", Integer, primary_key=True)
    total_file_count = Column(Integer)
    total_line_count = Column(Integer)
    total_blank_count = Column(Integer)
    total_comment_count = Column(Integer)
    total_code_count = Column(Integer)
    total_complexity_count = Column(Integer)
    project_id = Column(Integer, ForeignKey("Project.id"), nullable=False)
    project = db.relationship("Project", back_populates="project_lines_count")

    def top_language_lines_counts(self, top_number):
        return sorted(
            self.language_lines_counts, key=lambda x: x.code_count, reverse=True
        )[:top_number]

    @staticmethod
    def load_project_lines_count(scc_result):
        # Empty ProjectLinesCount
        project_lines_count = ProjectLinesCount(
            total_file_count=0,
            total_line_count=0,
            total_blank_count=0,
            total_comment_count=0,
            total_code_count=0,
            total_complexity_count=0
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
            project_lines_count.language_lines_counts.append(language_lines_count)
            # Update ProjectLineCount counters
            project_lines_count.total_file_count += c["Count"]
            project_lines_count.total_line_count += c["Lines"]
            project_lines_count.total_blank_count += c["Blank"]
            project_lines_count.total_comment_count += c["Comment"]
            project_lines_count.total_code_count += c["Code"]
            project_lines_count.total_complexity_count += c["Complexity"]
        return project_lines_count


class LanguageLinesCount(db.Model):

    __tablename__ = "LanguageLinesCount"

    id = Column("id", Integer, primary_key=True)
    language = Column(String)
    file_count = Column(Integer)
    line_count = Column(Integer)
    blank_count = Column(Integer)
    comment_count = Column(Integer)
    code_count = Column(Integer)
    complexity_count = Column(Integer)
    project_lines_count_id = Column(
        Integer, ForeignKey("ProjectLinesCount.id"), nullable=False
    )
    project_lines_count = db.relationship(
        "ProjectLinesCount",
        backref=db.backref(
            "language_lines_counts", lazy=True, cascade="all, delete-orphan"
        ),
    )

# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
from shutil import rmtree

from grepmarx import db
from grepmarx.base import util
from sqlalchemy import Column, Integer, String


class Project(db.Model):

    STATUS_NEW = 0
    STATUS_FINISHED = 1
    STATUS_ANALYZING = 2
    STATUS_ERROR = 3
    PROJECTS_SRC_PATH = "grepmarx/data/projects/"
    EXTRACT_FOLDER_NAME = "extract"

    __tablename__ = "Project"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    archive_filename = Column(String)
    archive_sha256sum = Column(String)
    status = Column(Integer, nullable=False, default=STATUS_NEW)
    error_message = Column(String)
    creator_id = db.Column(db.Integer, db.ForeignKey(
        "User.id"), nullable=False)
    creator = db.relationship(
        "User", backref=db.backref("projects", lazy=True)
    )
    analysis = db.relationship(
        "Analysis", uselist=False, back_populates="project", cascade="all, delete-orphan")
    project_lines_count = db.relationship(
        "ProjectLinesCount", uselist=False, back_populates="project", cascade="all, delete-orphan"
    )

    def remove(self):
        project_path = os.path.join(Project.PROJECTS_SRC_PATH, str(self.id))
        if os.path.isdir(project_path):
            rmtree(project_path)
        db.session.delete(self)
        db.session.commit()

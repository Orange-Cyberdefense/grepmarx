# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from app import db
from app.constants import STATUS_NEW
from sqlalchemy import Column, Integer, String
from sqlalchemy.sql.schema import ForeignKey


class Project(db.Model):

    __tablename__ = "Project"

    id = Column(Integer, primary_key=True)
    name = Column(String)
    archive_filename = Column(String)
    archive_sha256sum = Column(String)
    status = Column(Integer, nullable=False, default=STATUS_NEW)
    occurences_count = Column(Integer, default=0)
    risk_level = Column(Integer, default=0)
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

# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from app import db
from app.rules.models import analysis_to_rule_pack_association_table
from sqlalchemy import Column, Integer, String


class Analysis(db.Model):

    __tablename__ = "Analysis"

    id = Column(Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("Project.id"))
    project = db.relationship("Project", back_populates="analysis")
    started_on = db.Column(db.DateTime())
    finished_on = db.Column(db.DateTime())
    rule_packs = db.relationship(
        "RulePack",
        secondary=analysis_to_rule_pack_association_table,
        back_populates="analyzes",
    )
    ignore_paths = Column(String)
    ignore_filenames = Column(String)


class Vulnerability(db.Model):

    __tablename__ = "Vulnerability"

    id = Column(Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("Analysis.id"), nullable=False)
    analysis = db.relationship(
        "Analysis",
        backref=db.backref("vulnerabilities", lazy=True, cascade="all, delete-orphan"),
    )
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(String)
    cwe = Column(String)
    owasp = Column(String)
    references = Column(String)


class Occurence(db.Model):

    __tablename__ = "Occurence"

    id = Column(Integer, primary_key=True)
    vulnerability_id = db.Column(
        db.Integer, db.ForeignKey("Vulnerability.id"), nullable=False
    )
    vulnerability = db.relationship(
        "Vulnerability",
        backref=db.backref("occurences", lazy=True, cascade="all, delete-orphan"),
    )
    match_string = Column(String)
    file_path = Column(String, nullable=False)
    position = db.relationship("Position", uselist=False, back_populates="occurence")


class Position(db.Model):

    __tablename__ = "Position"

    id = Column(Integer, primary_key=True)
    occurence_id = db.Column(db.Integer, db.ForeignKey("Occurence.id"), nullable=True)
    occurence = db.relationship("Occurence", back_populates="position")
    line_start = Column(Integer)
    line_end = Column(Integer)
    column_start = Column(Integer)
    column_end = Column(Integer)


class AppInspector(db.Model):

    __tablename__ = "AppInspector"

    id = Column(Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("Project.id"))
    name = Column(String)
    filenames = Column(String)



class Matches(db.Model):

    __tablename__ = "Matches"

    id = Column(Integer, primary_key=True)
    app_inspector_id = db.Column(db.Integer, db.ForeignKey("AppInspector.id"), nullable=False)
    analysis = db.relationship(
        "AppInspector",
        backref=db.backref("matches", lazy=True, cascade="all, delete-orphan"),
    )
    title_rule = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    description = Column(String)
    pattern = Column(String)
    language = Column(String)
    filename = Column(String)

class Tag(db.Model):

    __tablename__ = "Tag"

    id = Column(Integer, primary_key=True)
    matches_id = db.Column(
        db.Integer, db.ForeignKey("Matches.id"), nullable=False
    )
    matches = db.relationship(
        "Matches",
        backref=db.backref("tag", lazy=True, cascade="all, delete-orphan"),
    )
    unique_tag = Column(String)
    start_column = Column(String)
    start_line = Column(String)
    end_column = Column(String)
    end_line = Column(String)
    
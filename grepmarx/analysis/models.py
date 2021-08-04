# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from grepmarx import db
from grepmarx.rules.models import analysis_to_rule_pack_association_table
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
    span_id = db.Column(
        db.Integer, db.ForeignKey("AnalysisErrorSpan.id"), nullable=True
    )
    span = db.relationship("AnalysisErrorSpan", back_populates="position")
    line_start = Column(Integer)
    line_end = Column(Integer)
    column_start = Column(Integer)
    column_end = Column(Integer)


class AnalysisError(db.Model):

    __tablename__ = "AnalysisError"

    id = Column(Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("Analysis.id"), nullable=False)
    analysis = db.relationship(
        "Analysis",
        backref=db.backref("errors", lazy=True, cascade="all, delete-orphan"),
    )
    code = Column(Integer, nullable=False)
    path = Column(String)
    rule_id = Column(String)
    error_type = Column(String)
    help_msg = Column(String)
    long_msg = Column(String)
    short_msg = Column(String)


class AnalysisErrorSpan(db.Model):

    __tablename__ = "AnalysisErrorSpan"

    id = Column(Integer, primary_key=True)
    analysis_error_id = db.Column(
        db.Integer, db.ForeignKey("AnalysisError.id"), nullable=False
    )
    analysis_error = db.relationship(
        "AnalysisError",
        backref=db.backref("spans", lazy=True, cascade="all, delete-orphan"),
    )
    file = Column(String, nullable=False)
    source_hash = Column(String)
    context_start = Column(String)
    context_end = Column(String)
    position = db.relationship("Position", uselist=False, back_populates="span")

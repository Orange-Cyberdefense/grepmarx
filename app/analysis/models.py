# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from sqlalchemy import Boolean, Column, Integer, String

from app import db
from app.rules.models import analysis_to_rule_pack_association_table
from app.constants import (TO_REVIEW)



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
    task_id = Column(String)


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
    impact = Column(String)
    likelihood = Column(String)
    confidence = Column(String)
    description = Column(String)
    cwe = Column(String)
    owasp = Column(String)
    references = Column(String)


class Occurence(db.Model):

    __tablename__ = "Occurence"

    id = Column(Integer, primary_key=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("Vulnerability.id"), nullable=False)
    vulnerability = db.relationship(
        "Vulnerability",
        backref=db.backref("occurences", lazy=True, cascade="all, delete-orphan"),
    )
    match_string = Column(String)
    file_path = Column(String, nullable=False)
    position = db.relationship("Position", uselist=False, back_populates="occurence")
    status = Column(db.Integer, nullable=True, default=TO_REVIEW["id"])


class Position(db.Model):

    __tablename__ = "Position"

    id = Column(Integer, primary_key=True)
    occurence_id = db.Column(db.Integer, db.ForeignKey("Occurence.id"), nullable=True)
    occurence = db.relationship("Occurence", back_populates="position")
    line_start = Column(Integer)
    line_end = Column(Integer)
    column_start = Column(Integer)
    column_end = Column(Integer)


class VulnerableDependency(db.Model):
    __tablename__ = "VulnerableDependency"

    id = Column(Integer, primary_key=True)
    analysis_id = db.Column(db.Integer, db.ForeignKey("Analysis.id"), nullable=False)
    analysis = db.relationship(
        "Analysis",
        backref=db.backref(
            "vulnerable_dependencies", lazy=True, cascade="all, delete-orphan"
        ),
    )
    common_id = Column(String, nullable=False)
    bom_ref = Column(String, nullable=False)
    pkg_type = Column(String, nullable=False)
    pkg_ref = Column(String, nullable=False)
    pkg_name = Column(String, nullable=False)
    source = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    cvss_score = Column(String)
    cvss_version = Column(String)
    cwes = Column(String)
    description = Column(String)
    recommendation = Column(String)
    version = Column(String, nullable=False)
    fix_version = Column(String)
    prioritized = Column(Boolean)
    vendor_confirmed = Column(Boolean)
    has_exploit = Column(Boolean)
    direct  = Column(Boolean)
    indirect = Column(Boolean)
    distro_specific = Column(Boolean)
    direct_dep = Column(Boolean)
    known_exploit = Column(Boolean)
    exploitable = Column(Boolean)
    flagged_weakness = Column(Boolean)
    suppress_for_containers = Column(Boolean)
    uninstall_candidate = Column(Boolean)
    indirect_dependency = Column(Boolean)
    local_install = Column(Boolean)
    reachable_Bounty_target = Column(Boolean)
    bug_Bounty_target = Column(Boolean)
    has_PoC = Column(Boolean)
    reachable = Column(Boolean)
    reachable_and_Exploitable = Column(Boolean)
    source_files = Column(String)

class VulnerableDependencyReference(db.Model):
    __tablename__ = "VulnerableDependencyReference"

    id = Column(Integer, primary_key=True)
    title = Column(String)
    url = Column(String)
    vulnerable_dependency_id = db.Column(
        db.Integer, db.ForeignKey("VulnerableDependency.id"), nullable=True
    )
    vulnerable_dependency = db.relationship(
        "VulnerableDependency",
        backref=db.backref("advisories", lazy=True, cascade="all, delete-orphan"),
    )


class AppInspector(db.Model):

    __tablename__ = "AppInspector"

    id = Column(Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("Project.id"))
    project = db.relationship("Project", back_populates="appinspector")


class Match(db.Model):

    __tablename__ = "Match"
    id = Column(Integer, primary_key=True)
    app_inspector_id = db.Column(
        db.Integer, db.ForeignKey("AppInspector.id"), nullable=False
    )
    appinspector = db.relationship(
        "AppInspector",
        backref=db.backref("match", lazy=True, cascade="all, delete-orphan"),
    )
    title = Column(String, nullable=False)
    description = Column(String)
    pattern = Column(String)
    language = Column(String)
    filename = Column(String)
    tags = Column(String)


class InspectorTag(db.Model):

    __tablename__ = "InspectorTag"

    id = Column(Integer, primary_key=True)
    match_id = db.Column(db.Integer, db.ForeignKey("Match.id"), nullable=False)
    match = db.relationship(
        "Match",
        backref=db.backref("tag", lazy=True, cascade="all, delete-orphan"),
    )
    excerpt = Column(String)
    filename = Column(String)
    severity = Column(String, nullable=False)
    start_column = Column(Integer)
    start_line = Column(Integer)
    end_column = Column(Integer)
    end_line = Column(Integer)

# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
import re
from shutil import copyfile, rmtree

from flask import current_app
from grepmarx import db
from grepmarx.projects.model import Project
from grepmarx.rules.model import Rule, analysis_to_rule_pack_association_table
from grepmarx.rules.util import generate_severity
from sqlalchemy import Column, ForeignKey, Integer, String


class Analysis(db.Model):

    IGNORE_EXTENSIONS = {".min.js"}
    IGNORE_FOLDERS = {"vendor", "test", "Test"}

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

    def import_rules(self, rule_folder):
        if os.path.isdir(rule_folder):
            rmtree(rule_folder)
        os.mkdir(rule_folder)
        for c_rule_pack in self.rule_packs:
            for c_rule in c_rule_pack.rules:
                src = os.path.join(Rule.RULES_PATH, c_rule.file_path)
                dst = os.path.join(
                    rule_folder,
                    c_rule.repository
                    + "_"
                    + c_rule.category
                    + "."
                    + c_rule.title
                    + Rule.RULE_EXTENSION,
                )
                copyfile(src, dst)
                current_app.logger.debug(
                    "Imported rule for project with id=%i: %s",
                    self.project.id,
                    dst,
                )

    def generate_options(self, rule_folder):
        options = dict()
        # Rule path
        options["sgrep_rules"] = rule_folder
        # Ignore filenames
        options["ignore_filenames"] = set(
            # Remove empty elements
            filter(None, self.ignore_filenames.split(","))
        )
        # Ignore paths
        options["ignore_paths"] = set(
            # Remove empty elements
            filter(None, self.ignore_paths.split(","))
        )
        # Extensions
        ext_str = ""
        for c_rule_pack in self.rule_packs:
            ext_str = ext_str.join(
                c_language.extensions + "," for c_language in c_rule_pack.languages
            )
        options["sgrep_extensions"] = set(
            # Remove duplicates
            dict.fromkeys(
                # Remove empty elements
                filter(None, ext_str.split(","))
            )
        )
        return options

    def load_scan_results(self, libsast_result):
        if libsast_result is not None:
            if "semantic_grep" in libsast_result:
                matches = libsast_result["semantic_grep"]["matches"]
                for c_match in matches:
                    self.vulnerabilities.append(
                        Vulnerability.load_vulnerability(c_match, matches[c_match])
                    )
                errors = libsast_result["semantic_grep"]["errors"]
                for c_error in errors:
                    self.errors.append(AnalysisError.load_error(c_error))

    def vulnerabilities_sorted_by_severity(self):
        r_vulnerabilities = list()
        low_vulnerabilities = list()
        for c_vulnerability in self.vulnerabilities:
            if c_vulnerability.severity == Rule.SEVERITY_HIGH:
                r_vulnerabilities.insert(0, c_vulnerability)
            elif c_vulnerability.severity == Rule.SEVERITY_MEDIUM:
                r_vulnerabilities.append(c_vulnerability)
            else:
                low_vulnerabilities.append(c_vulnerability)
        r_vulnerabilities.extend(low_vulnerabilities)
        return r_vulnerabilities


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

    @staticmethod
    def load_vulnerability(match_title, match_dict):
        vulnerability = Vulnerability(title=match_title)
        for c_occurence in match_dict["files"]:
            vulnerability.occurences.append(Occurence.load_occurence(c_occurence))
        metadata = match_dict["metadata"]
        if "description" in metadata:
            vulnerability.description = metadata["description"]
        if "cwe" in metadata:
            vulnerability.cwe = metadata["cwe"]
        if "owasp" in metadata:
            vulnerability.owasp = metadata["owasp"]
        if "references" in metadata:
            vulnerability.references = " ".join(metadata["references"])
        vulnerability.severity = generate_severity(vulnerability.cwe)
        return vulnerability


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

    @staticmethod
    def load_occurence(file_dict):
        pattern = (
            Project.PROJECTS_SRC_PATH
            + "[\\/]?\d+[\\/]"
            + Project.EXTRACT_FOLDER_NAME
            + "[\\/]?"
        )
        clean_path = re.sub(pattern, "", file_dict["file_path"])
        occurence = Occurence(
            file_path=clean_path, match_string=file_dict["match_string"]
        )
        occurence.position = Position(
            line_start=file_dict["match_lines"][0],
            line_end=file_dict["match_lines"][1],
            column_start=file_dict["match_position"][0],
            column_end=file_dict["match_position"][1],
        )
        return occurence


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

    @staticmethod
    def load_error(error_dict):
        error = AnalysisError(code=error_dict["code"], error_type=error_dict["type"])
        if "path" in error_dict:
            error.path = error_dict["path"]
        if "rule_id" in error_dict:
            error.rule_id = error_dict["rule_id"]
        if "spans" in error_dict:
            for c_span in error_dict["spans"]:
                error.spans.append(AnalysisErrorSpan.load_span(c_span))
        return error


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

    @staticmethod
    def load_span(span_dict):
        span = AnalysisErrorSpan(
            file=span_dict["file"],
            source_hash=span_dict["source_hash"],
            context_start=span_dict["context_start"],
            context_end=span_dict["context_end"],
        )
        span.position = Position(
            line_start=span_dict["start"]["line"],
            line_end=span_dict["end"]["line"],
            column_start=span_dict["start"]["col"],
            column_end=span_dict["end"]["col"],
        )
        return span


class ProjectLinesCount(db.Model):

    __tablename__ = "ProjectLinesCount"

    id = Column("id", Integer, primary_key=True)
    total_code_count = Column(Integer)
    total_documentation_count = Column(Integer)
    total_empty_count = Column(Integer)
    total_file_count = Column(Integer)
    total_line_count = Column(Integer)
    total_string_count = Column(Integer)
    project_id = Column(Integer, ForeignKey("Project.id"), nullable=False)
    project = db.relationship("Project", back_populates="project_lines_count")

    def top_language_lines_counts(self, top_number):
        return sorted(
            self.language_lines_counts, key=lambda x: x.code_count, reverse=True
        )[:top_number]

    @staticmethod
    def load_project_lines_count(pygount_summary):
        project_lines_count = ProjectLinesCount(
            total_code_count=pygount_summary.total_code_count,
            total_documentation_count=pygount_summary.total_documentation_count,
            total_empty_count=pygount_summary.total_empty_count,
            total_file_count=pygount_summary.total_file_count,
            total_line_count=pygount_summary.total_line_count,
            total_string_count=pygount_summary.total_string_count,
        )
        for key in pygount_summary.language_to_language_summary_map:
            c_ls = pygount_summary.language_to_language_summary_map[key]
            if not c_ls.is_pseudo_language:
                language_lines_count = LanguageLinesCount(
                    code_count=c_ls.code_count,
                    documentation_count=c_ls.documentation_count,
                    empty_count=c_ls.empty_count,
                    file_count=c_ls.file_count,
                    language=c_ls.language,
                    string_count=c_ls.string_count,
                )
                project_lines_count.language_lines_counts.append(language_lines_count)
        return project_lines_count


class LanguageLinesCount(db.Model):

    __tablename__ = "LanguageLinesCount"

    id = Column("id", Integer, primary_key=True)
    code_count = Column(Integer)
    documentation_count = Column(Integer)
    empty_count = Column(Integer)
    file_count = Column(Integer)
    language = Column(String)
    string_count = Column(Integer)
    project_lines_count_id = Column(
        Integer, ForeignKey("ProjectLinesCount.id"), nullable=False
    )
    project_lines_count = db.relationship(
        "ProjectLinesCount",
        backref=db.backref(
            "language_lines_counts", lazy=True, cascade="all, delete-orphan"
        ),
    )

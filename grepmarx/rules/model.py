# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
from glob import glob

from flask import current_app
from grepmarx import db
from grepmarx.administration.model import RuleRepository
from grepmarx.constants import RULE_EXTENSIONS, RULES_PATH
from grepmarx.rules.util import generate_severity
from sqlalchemy import Column, ForeignKey, Integer, String, Table
from yaml import YAMLError, safe_load

rule_to_supported_language_association_table = Table(
    "RuleToSupportedLanguageAssociation",
    db.metadata,
    Column("rule_id", Integer, ForeignKey("Rule.id")),
    Column("supported_language_id", Integer, ForeignKey("SupportedLanguage.id")),
)

rule_to_rule_pack_association_table = Table(
    "RuleToRulePackAssociation",
    db.metadata,
    Column("rule_id", Integer, ForeignKey("Rule.id")),
    Column("rule_pack_id", Integer, ForeignKey("RulePack.id")),
)

analysis_to_rule_pack_association_table = Table(
    "AnalysisToRulePackAssociation",
    db.metadata,
    Column("analysis_id", Integer, ForeignKey("Analysis.id")),
    Column("rule_pack_id", Integer, ForeignKey("RulePack.id")),
)

rule_pack_to_supported_language_association_table = Table(
    "RulePackToSupportedLanguageAssociation",
    db.metadata,
    Column("rule_pack_id", Integer, ForeignKey("RulePack.id")),
    Column("supported_language_id", Integer, ForeignKey("SupportedLanguage.id")),
)


class Rule(db.Model):

    __tablename__ = "Rule"

    id = Column("id", Integer, primary_key=True)
    title = Column(String)
    category = Column(String)
    severity = Column(String)
    file_path = Column(String)
    cwe = Column(String)
    owasp = Column(String)
    repository_id = db.Column(
        db.Integer, db.ForeignKey("RuleRepository.id"), nullable=False
    )
    repository = db.relationship(
        "RuleRepository",
        backref=db.backref("rules", lazy=True, cascade="all, delete-orphan"),
    )
    languages = db.relationship(
        "SupportedLanguage",
        secondary=rule_to_supported_language_association_table,
        back_populates="rules",
    )
    rule_packs = db.relationship(
        "RulePack",
        secondary=rule_to_rule_pack_association_table,
        back_populates="rules",
    )

    @staticmethod
    def sync_db(rules_folder):
        # Get all YML files in the folder
        rules_filenames = list()
        for c_ext in RULE_EXTENSIONS:
            rules_filenames += glob(
                pathname=os.path.join(rules_folder, "**", "*" + c_ext), recursive=True
            )
        supported_languages = SupportedLanguage.query.all()
        # Parse rules in these files
        for c_filename in rules_filenames:
            with open(c_filename, "r") as yml_stream:
                try:
                    yml_rules = safe_load(yml_stream)
                    file_path = c_filename.replace(RULES_PATH, "")
                    repository = file_path.split(os.path.sep)[0]
                    category = ".".join(file_path.split(os.path.sep)[1:][:-1])
                    if "rules" in yml_rules:
                        for c_rule in yml_rules["rules"]:
                            rule = Rule.query.filter_by(file_path=file_path).first()
                            # Create a new rule only if the file doesn't corresponds to an existing
                            # rule, in order to keep ids and not break RulePacks
                            if rule is None:
                                rule = Rule(
                                    title=c_rule["id"],
                                    file_path=file_path,
                                    repository=RuleRepository.query.filter_by(
                                        name=repository
                                    ).first(),
                                    category=category,
                                )
                                db.session.add(rule)
                            if "languages" in c_rule:
                                for c_language in c_rule["languages"]:
                                    for c_sl in supported_languages:
                                        if c_sl.name.lower() == c_language.lower():
                                            rule.languages.append(c_sl)
                            if "metadata" in c_rule:
                                if "cwe" in c_rule["metadata"]:
                                    rule.cwe = c_rule["metadata"]["cwe"]
                                if "owasp" in c_rule["metadata"]:
                                    rule.owasp = c_rule["metadata"]["owasp"]
                            rule.severity = generate_severity(rule.cwe)
                            current_app.logger.debug(
                                "Rule imported in DB: %s",
                                rule.repository.name
                                + "/"
                                + rule.category
                                + "/"
                                + rule.title,
                            )
                except YAMLError as e:
                    db.session.rollback()
                    raise (e)
                else:
                    db.session.commit()


class RulePack(db.Model):

    __tablename__ = "RulePack"

    id = Column("id", Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)
    analyzes = db.relationship(
        "Analysis",
        secondary=analysis_to_rule_pack_association_table,
        back_populates="rule_packs",
    )
    languages = db.relationship(
        "SupportedLanguage",
        secondary=rule_pack_to_supported_language_association_table,
        back_populates="rule_packs",
    )
    rules = db.relationship(
        "Rule",
        secondary=rule_to_rule_pack_association_table,
        back_populates="rule_packs",
    )


class SupportedLanguage(db.Model):

    __tablename__ = "SupportedLanguage"

    id = Column("id", Integer, primary_key=True)
    name = Column(String, unique=True)
    extensions = Column(String)
    rule_packs = db.relationship(
        "RulePack",
        secondary=rule_pack_to_supported_language_association_table,
        back_populates="languages",
    )
    rules = db.relationship(
        "Rule",
        secondary=rule_to_supported_language_association_table,
        back_populates="languages",
    )

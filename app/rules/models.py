# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from app import db
from sqlalchemy import Column, ForeignKey, Integer, String, Table
from sqlalchemy.sql.sqltypes import DateTime


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
        db.Integer, db.ForeignKey("RuleRepository.id"), nullable=True
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


class RuleRepository(db.Model):

    __tablename__ = "RuleRepository"

    id = Column("id", Integer, primary_key=True)
    name = Column(String, unique=True)
    description = Column(String)
    uri = Column(String)
    last_update_on = Column(DateTime())


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

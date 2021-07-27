# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
from glob import glob

from flask import current_app
from grepmarx import db
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

    SEVERITY_HIGH = "high"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_LOW = "low"
    RULES_PATH = "data/rules/"
    RULE_EXTENSION = ".yaml"
    OWASP_TOP10_LINKS = {
        "A1": "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection.html",
        "A2": "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication.html",
        "A3": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html",
        "A4": "https://owasp.org/www-project-top-ten/2017/A4_2017-XML_External_Entities_(XXE).html",
        "A5": "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html",
        "A6": "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration.html",
        "A7": "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS).html",
        "A8": "https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization.html",
        "A9": "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities.html",
        "A10": "https://owasp.org/www-project-top-ten/2017/A10_2017-Insufficient_Logging%2526Monitoring.html",
    }
    # https://cwe.mitre.org/top25/archive/2020/2020_cwe_top25.html#methodology
    TOP40_CWE_SEVERITIES = {
        "CWE-79": SEVERITY_MEDIUM,
        "CWE-787": SEVERITY_HIGH,
        "CWE-20": SEVERITY_HIGH,
        "CWE-125": SEVERITY_HIGH,
        "CWE-119": SEVERITY_HIGH,
        "CWE-89": SEVERITY_HIGH,
        "CWE-200": SEVERITY_HIGH,
        "CWE-416": SEVERITY_HIGH,
        "CWE-352": SEVERITY_HIGH,
        "CWE-78": SEVERITY_HIGH,
        "CWE-190": SEVERITY_HIGH,
        "CWE-22": SEVERITY_HIGH,
        "CWE-476": SEVERITY_MEDIUM,
        "CWE-287": SEVERITY_HIGH,
        "CWE-434": SEVERITY_HIGH,
        "CWE-732": SEVERITY_MEDIUM,
        "CWE-94": SEVERITY_HIGH,
        "CWE-522": SEVERITY_HIGH,
        "CWE-611": SEVERITY_HIGH,
        "CWE-798": SEVERITY_HIGH,
        "CWE-502": SEVERITY_HIGH,
        "CWE-269": SEVERITY_HIGH,
        "CWE-400": SEVERITY_HIGH,
        "CWE-306": SEVERITY_HIGH,
        "CWE-862": SEVERITY_MEDIUM,
        "CWE-426": SEVERITY_HIGH,
        "CWE-918": SEVERITY_HIGH,
        "CWE-295": SEVERITY_HIGH,
        "CWE-863": SEVERITY_MEDIUM,
        "CWE-284": SEVERITY_HIGH,
        "CWE-77": SEVERITY_HIGH,
        "CWE-401": SEVERITY_MEDIUM,
        "CWE-532": SEVERITY_MEDIUM,
        "CWE-362": SEVERITY_MEDIUM,
        "CWE-601": SEVERITY_MEDIUM,
        "CWE-835": SEVERITY_MEDIUM,
        "CWE-704": SEVERITY_HIGH,
        "CWE-415": SEVERITY_HIGH,
        "CWE-770": SEVERITY_HIGH,
        "CWE-59": SEVERITY_HIGH,
    }

    __tablename__ = "Rule"

    id = Column("id", Integer, primary_key=True)
    title = Column(String)
    repository = Column(String)
    category = Column(String)
    severity = Column(String)
    file_path = Column(String)
    cwe = Column(String)
    owasp = Column(String)
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
        rules_filenames = glob(
            pathname=os.path.join(rules_folder, "**", "*.yaml"), recursive=True
        )
        supported_languages = SupportedLanguage.query.all()
        for c_filename in rules_filenames:
            with open(c_filename, "r") as yml_stream:
                try:
                    yml_rules = safe_load(yml_stream)
                    file_path = c_filename.replace(Rule.RULES_PATH, "")
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
                                    repository=repository,
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
                                rule.repository + "/" + rule.category + "/" + rule.title,
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

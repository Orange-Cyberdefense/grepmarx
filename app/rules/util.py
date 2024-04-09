# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import os
import re
from glob import glob
from datetime import datetime
from shutil import rmtree

import git
from flask import current_app
from app import db
from app.constants import (
    LOCAL_RULES,
    RULE_EXTENSIONS,
    RULES_PATH,
    LOCAL_RULES_PATH,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
)
from app.rules.models import Rule, RuleRepository, SupportedLanguage
from yaml import YAMLError, safe_load

##
## Rule utils
##


def get_languages_names():
    supported_languages = SupportedLanguage.query.all()
    language_names = []

    for language in supported_languages:
        language_names.append(language.name)

    return language_names


def sync_db(rules_folder):
    """Parse all semgrep YAML rule files in the given folder, and for each
    rule create new a Rule object and persist it in the database. Existing rules ID
    are kept to preserve rule packs consistency.

    Args:
        rules_folder (str): path of the folder containing semgrep YAML rule files
    """
    # Get all YML files in the folder
    rules_filenames = list()
    for c_ext in RULE_EXTENSIONS:
        rules_filenames += glob(
            pathname=os.path.join(rules_folder, "**", "*" + c_ext), recursive=True
        )
    # Parse rules in these files
    for c_filename in rules_filenames:
        save_rule_in_db(c_filename)
    db.session.commit()
    # Research & destroy rules in DB which doesn't exist on the FS
    all_rules = Rule.query.all()
    for rule in all_rules:
        if not os.path.isfile(os.path.join(rules_folder, rule.file_path)):
            current_app.logger.debug(
                "Delete from DB rule which isn't in repos anymore: %s",
                rule.repository.name + "/" + rule.category + "/" + rule.title,
            )
            db.session.delete(rule)
    db.session.commit()


def save_rule_in_db(filename):
    with open(filename, "r") as yml_stream:
        # Repository name is the folder name of the rule file
        file_path = filename.replace(RULES_PATH, "")
        repository = file_path.split(os.path.sep)[0]
        # Check if the folder matches an existing repository
        if (
            RuleRepository.query.filter_by(name=repository).first()
            and repository != LOCAL_RULES is None
        ):
            current_app.logger.debug(
                "Folder does not match a registered rule repository. You should manually remove the unused `%s' folder.",
                repository,
            )
        else:
            # Parse yaml content
            yml_ok = True
            try:
                yml_rules = safe_load(yml_stream)
            # Skip file if not parseable
            except YAMLError as e:
                current_app.logger.debug(e)
                yml_ok = False
            if yml_ok:
                category = ".".join(file_path.split(os.path.sep)[1:][:-1])
                # Extract rules from the file, if any
                if "rules" in yml_rules and file_path[-10:] != ".test.yaml":
                    for c_rule in yml_rules["rules"]:
                        # Skip deprecated rules
                        if "metadata" in c_rule and "deprecated" in c_rule["metadata"]:
                            if c_rule["metadata"]["deprecated"]:
                                continue
                        rule = Rule.query.filter_by(file_path=file_path).first()
                        # Create a new rule only if the file doesn't corresponds to an existing
                        # rule, in order to keep ids and not break RulePacks
                        if rule is None:
                            rule = Rule()
                            db.session.add(rule)
                        # Basic rule information
                        rule.title = c_rule["id"]
                        rule.file_path = file_path
                        rule.repository = RuleRepository.query.filter_by(
                            name=repository
                        ).first()
                        rule.category = category
                        # Associate the rule with a known, supported language
                        if "languages" in c_rule:
                            rule.languages = (
                                list()
                            )  # reset to avoid duplicates in RuleToSupportedLanguageAssociation!
                            supported_languages = SupportedLanguage.query.all()
                            for c_language in c_rule["languages"]:
                                for c_sl in supported_languages:
                                    if c_sl.name.lower() == c_language.lower():
                                        rule.languages.append(c_sl)
                        # Add metadata: OWASP and CWE ids
                        if "metadata" in c_rule:
                            metadata = c_rule["metadata"]
                            if "cwe" in metadata:
                                # There may be multiple CWE ids
                                if type(metadata["cwe"]) is list:
                                    rule.cwe = metadata["cwe"][0]
                                else:
                                    rule.cwe = metadata["cwe"]
                            if "owasp" in metadata:
                                # There may be multiple OWASP ids (eg. 2017, 2021...)
                                if type(metadata["owasp"]) is list:
                                    rule.owasp = metadata["owasp"][0]
                                else:
                                    rule.owasp = metadata["owasp"]
                            # Add impact, likelihood and confidence if present
                            if "impact" in metadata:
                                rule.impact = metadata["impact"]
                            if "likelihood" in metadata:
                                rule.likelihood = metadata["likelihood"]
                            if "confidence" in metadata:
                                rule.confidence = metadata["confidence"]
                        # Replace rule level/severity by a calculated one
                        rule.severity = c_rule["severity"]
                        generate_severity(rule)
                        current_app.logger.debug(
                            "Rule imported in DB: %s",
                            repository + "/" + rule.category + "/" + rule.title,
                        )
                        # db.session.commit()


def add_new_rule(name, code):
    # Make sure the local rule directory exists
    if not os.path.exists(LOCAL_RULES_PATH):
        os.mkdir(LOCAL_RULES_PATH)
    # Normalize rule name for the file name
    name = name.replace(" ", "_").lower()
    rule_path = os.path.join(LOCAL_RULES_PATH, name + ".yml")
    # Save the rule file
    new_rule = open(rule_path, "w")
    new_rule.write(code)
    new_rule.close()
    return rule_path


def generate_severity(roc):
    """Generates a severity level (critical, high, medium, low, info) calculated from a
    rule's/vulnerability's impact, likelihood and confidence levels.

    If these levels are not present, original severity level will be transformed such as:
    - INFO => SEVERITY_INFO
    - WARNING => SEVERITY_LOW
    - ERROR => SEVERITY_MEDIUM

    Args:
        roc (Rule/Vulnerability): rule/vulnerability object already populated with at least the original severity level
    """
    if (
        roc.impact is not None
        and roc.likelihood is not None
        and roc.confidence is not None
    ):
        total = 0
        for level in (roc.impact, roc.likelihood, roc.confidence):
            if level == "HIGH":
                total += 3
            elif level == "MEDIUM":
                total += 2
            else:
                total += 1
        if total > 7:
            roc.severity = SEVERITY_CRITICAL
        elif total > 5:
            roc.severity = SEVERITY_HIGH
        elif total > 3:
            roc.severity = SEVERITY_MEDIUM
        else:
            roc.severity = SEVERITY_LOW
    else:
        if roc.severity == "ERROR":
            roc.severity = SEVERITY_MEDIUM
        elif roc.severity == "WARNING":
            roc.severity = SEVERITY_LOW
        else:
            roc.severity = SEVERITY_INFO


##
## RulePack utils
##


def validate_languages_rules(form):
    """Check that the 'languages' and 'rules' fields of a rule pack form are valid.

    Args:
        form (dict): form to validate (request.form)

    Returns:
        str: None if the fields are valid, a short error message otherwise
    """
    err = None
    # Need at least one language
    if len(form.languages.data) <= 0:
        err = "Please define at least one associated language for the rule pack"
    # Check the given rule list (comma separated integers)
    if not re.search("(\d+,)*\d+", form.rules.data, re.IGNORECASE):
        err = "Please define at least one rule for the rule pack"
    return err


def comma_separated_to_list(comma_separated):
    """Convert a string of comma separated IDs to a list of integers.
    Empty and duplicated elements are omitted.

    Args:
        comma_separated (str): string of comma separated IDs

    Returns:
        list: a list of integers
    """
    # Split the string into a list, then remove empty and duplicate elements
    r_list = list(dict.fromkeys(filter(None, comma_separated.split(","))))
    # Convert elements to integers
    for i in range(0, len(r_list)):
        r_list[i] = int(r_list[i])
    return r_list


##
## RuleRepository utils
##


def clone_rule_repo(repo, username="", token=""):
    """Perform a 'clone' operation on the rule repository.
    The rule repository's 'last_update_on' attribute will be updated.

    Args:
        repo (RuleRepository): rule repository to clone
        username (String): optional username for private repos
        token (String): optional token for private repos
    """
    repo_path = os.path.join(RULES_PATH, repo.name)
    if username == "" or token == "":
        clone_uri = repo.uri
    else:
        clone_uri = re.sub(
            r"(https?://)([a-zA-Z0-9].*)",
            r"\1" + username + ":" + token + "@\2",
            repo.uri,
        )

    git.Repo.clone_from(clone_uri, repo_path)

    repo.last_update_on = datetime.now()
    db.session.commit()


def pull_rule_repo(repo):
    """Perform a 'pull' operation on the rule repository.
    The rule repository's 'last_update_on' attribute will be updated.

    Args:
        repo (RuleRepository): rule repository to pull
    """
    repo_path = os.path.join(RULES_PATH, repo.name)
    git.cmd.Git(repo_path).pull()
    repo.last_update_on = datetime.now()
    db.session.commit()


def remove_rule_repo(repo):
    """Delete the rule repository from the database (along with all its
    associated rules), and remove its folder from disk.

    Args:
        repo (RuleRepository): rule repository to remove
    """
    # Remove repository folder on disk
    repo_path = os.path.join(RULES_PATH, repo.name)
    if os.path.isdir(repo_path):
        rmtree(repo_path)
    db.session.delete(repo)
    db.session.commit()

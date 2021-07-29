# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

import re
import grepmarx


def validate_languages_rules(form):
    err = None
    # Need at least one language
    if len(form.languages.data) <= 0:
        err = "Please define at least one associated language for the rule pack"
    # Check the given rule list (comma separated integers)
    if not re.search("(\d+,)*\d+", form.rules.data, re.IGNORECASE):
        err = "Please define at least one rule for the rule pack"
    return err


def generate_severity(cwe_string):
    """Generates a severity level from a CWE full name.

    For Top 40 CWE, the severity is an average of the CVSS scores
    for CVEs corresponding to this CWE. For CWE outside of the
    Top 40, the severity is MEDIUM by default. If no CWE is set,
    the severity is then LOW.
    """
    ret = grepmarx.rules.model.Rule.SEVERITY_LOW
    if cwe_string is not None:
        match = re.search("(CWE-\d+)", cwe_string, re.IGNORECASE)
        if match:
            cwe_id = match.group(1).upper()
            if cwe_id in grepmarx.rules.model.Rule.TOP40_CWE_SEVERITIES:
                ret = grepmarx.rules.model.Rule.TOP40_CWE_SEVERITIES[cwe_id]
            else:
                ret = grepmarx.rules.model.Rule.SEVERITY_MEDIUM
    return ret


def comma_separated_to_list(comma_separated):
    # We have a list of comma separated ids
    # Split that into a list, then remove empty and duplicate elements
    r_list = list(dict.fromkeys(filter(None, comma_separated.split(","))))
    # Convert elements to integers
    for i in range(0, len(r_list)):
        r_list[i] = int(r_list[i])
    return r_list

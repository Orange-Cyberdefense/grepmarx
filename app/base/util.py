# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""

import binascii
import hashlib
import json
import os
import shutil
from calendar import monthrange
from datetime import date, datetime, timedelta

from sqlalchemy import and_, func

from app import db
from app.administration.models import LdapConfiguration
from app.analysis.models import Analysis
from app.rules.models import SupportedLanguage


# Inspiration -> https://www.vitoshacademy.com/hashing-passwords-in-python/
def hash_pass(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode("ascii")
    pwdhash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return salt + pwdhash  # return bytes


def verify_pass(provided_password, stored_password):
    """Verify a stored password against one provided by user"""
    stored_password = stored_password.decode("ascii")
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac(
        "sha512", provided_password.encode("utf-8"), salt.encode("ascii"), 100000
    )
    pwdhash = binascii.hexlify(pwdhash).decode("ascii")
    return pwdhash == stored_password


def month_analysis_count(date_in_month):
    """Get analysis count for a specific month."""
    year = int(date_in_month.strftime("%Y"))
    month = int(date_in_month.strftime("%m"))
    start_date = date(year, month, 1)
    end_date = date(year, month, monthrange(year, month)[1])
    return (
        date_in_month.strftime("%b %y"),
        Analysis.query.filter(
            and_(
                func.date(Analysis.finished_on) >= start_date,
                func.date(Analysis.finished_on) <= end_date,
            )
        ).count(),
    )


def last_12_months_analysis_count():
    """Get analysis count for the last 12 months."""
    ret = dict()
    now = datetime.now()
    month, count = month_analysis_count(now)
    ret[month] = count
    for _ in range(0, 11):
        now = now.replace(day=1) - timedelta(days=1)
        month, count = month_analysis_count(now)
        ret[month] = count
    return ret


def init_db():
    """Insert a default admin/admin user in the database."""
    db.session.add(SupportedLanguage(name="Python", extensions=".py"))
    db.session.add(
        SupportedLanguage(
            name="C", extensions=".cpp,.c++,.cxx,.hpp,.hh,.h++,.hxx,.c,.cc,.h"
        )
    )
    db.session.add(SupportedLanguage(name="JavaScript", extensions=".js,.htm,.html"))
    db.session.add(SupportedLanguage(name="TypeScript", extensions=".ts,.html"))
    db.session.add(SupportedLanguage(name="JSON", extensions=".json"))
    db.session.add(
        SupportedLanguage(
            name="PHP",
            extensions=".php,.php3,.php4,.php5,.php5.6,.phtm,.phtml,.tpl,.ctp,.twig",
        )
    )
    db.session.add(
        SupportedLanguage(
            name="Java",
            extensions=".javasln,.project,.java,.jsp,.jspf,.tag,.tld,.hbs,.properties",
        )
    )
    db.session.add(SupportedLanguage(name="Go", extensions=".go"))
    db.session.add(SupportedLanguage(name="OCaml", extensions=".ml,.mli"))
    db.session.add(
        SupportedLanguage(name="Ruby", extensions=".rb,.rhtml,.rxml,.rjs,.erb")
    )
    db.session.add(SupportedLanguage(name="Kotlin", extensions=".kt,.kts"))
    db.session.add(SupportedLanguage(name="Bash", extensions=".sh,.bash"))
    db.session.add(SupportedLanguage(name="Rust", extensions=".rs,.rlib"))
    db.session.add(SupportedLanguage(name="Scala", extensions=".scala,.sc"))
    db.session.add(SupportedLanguage(name="Solidity", extensions=".sol"))
    db.session.add(SupportedLanguage(name="Terraform", extensions=".tf"))
    db.session.add(SupportedLanguage(name="Generic", extensions=""))
    db.session.add(SupportedLanguage(name="Swift", extensions=".swift,.SWIFT"))
    db.session.add(
        SupportedLanguage(
            name="C#",
            extensions=".cs,.cshtml,.xaml,.vb,.config,.aspx,.ascx,.asax,.tag,.master,.xml",
        )
    )
    db.session.commit()


def is_admin(role):
    if str(role) == "1":
        return True
    else:
        return False


def remove_dir_content(directory):
    # https://stackoverflow.com/questions/185936/how-to-delete-the-contents-of-a-folder
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print("Failed to delete %s. Reason: %s" % (file_path, e))


def ldap_config_dict():
    ldap_config = LdapConfiguration.query.first()
    config = dict()
    config["LDAP_HOST"] = ldap_config.server_host
    config["LDAP_PORT"] = ldap_config.server_port
    config["LDAP_BASE_DN"] = ldap_config.base_dn
    config["LDAP_USER_DN"] = ldap_config.users_dn
    config["LDAP_GROUP_DN"] = ldap_config.groups_dn
    config["LDAP_USER_RDN_ATTR"] = ldap_config.user_rdn_attr
    config["LDAP_USER_LOGIN_ATTR"] = ldap_config.user_login_attr
    config["LDAP_BIND_USER_DN"] = ldap_config.bind_dn
    config["LDAP_BIND_USER_PASSWORD"] = ldap_config.bind_password
    config["LDAP_USER_OBJECT_FILTER"] = ldap_config.user_object_filter
    config["LDAP_GROUP_OBJECT_FILTER"] = ldap_config.group_object_filter
    config["LDAP_ADD_SERVER"] = False
    return config

def print_form_erros(errors):
    ret = ""
    for field in errors:
        for error in errors[field]:
            ret += f"{field}: {error}"
    return ret
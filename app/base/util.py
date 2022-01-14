# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
Copyright (c) 2021 - present Orange Cyberdefense
"""

import binascii
import hashlib
import os
from calendar import monthrange
from datetime import date, datetime, timedelta

from app import db
from app.analysis.models import Analysis
from app.base import models
from app.rules.models import SupportedLanguage
from sqlalchemy import and_, func


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
    """Get analysis count for the last 6 months."""
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
    """Insert a default admin/admin user and supported languages in the database."""
    db.session.add(
        models.User(username="admin", email="admin@grepmarx", password="admin")
    )
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
    db.session.add(SupportedLanguage(name="Generic", extensions=""))
    db.session.commit()

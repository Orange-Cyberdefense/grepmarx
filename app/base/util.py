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
import shutil

from app import db
from app.analysis.models import Analysis
from app.base import models
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
    db.session.add(
        models.User(
            username="admin", email="admin@grepmarx", password="admin", role="1"
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

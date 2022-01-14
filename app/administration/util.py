# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from app.base.models import User


def validate_user_form(
    form, skip_username=False, skip_email=False, skip_password=False
):
    err = None
    if not skip_username:
        # Check username exists
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            err = "Username already registered"
    if not skip_email:
        # Check email exists
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            err = "Email already registered"
    if not skip_password:
        # Check password not empty
        if form.password.data == "":
            err = "Please define a password for the new user"
        # Check passwords match
        if form.password.data != form.password_confirm.data:
            err = "Passwords does not match"
    return err

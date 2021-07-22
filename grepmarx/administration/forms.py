# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from flask_wtf import FlaskForm
from wtforms import TextField, PasswordField, HiddenField
from wtforms.validators import Email, DataRequired, InputRequired, EqualTo


class UserForm(FlaskForm):
    id = HiddenField("User id")
    username = TextField("Username", id="user-username", validators=[DataRequired()])
    first_name = TextField("First name", id="user-first-name")
    last_name = TextField("Last name", id="user-last-name")
    email = TextField("Email", id="user-email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", id="user-password")
    password_confirm = PasswordField("Confirm password", id="user-confirm-password")

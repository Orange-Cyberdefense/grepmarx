# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import PasswordField, HiddenField, SelectField, StringField
from wtforms.validators import DataRequired, Email, Regexp

## login and registration


class LoginForm(FlaskForm):
    username = StringField(
        "Username",
        id="username_login",
        validators=[
            DataRequired(),
            Regexp(
                "^[a-zA-Z0-9-_@\.]+$",
                message="Username name must contain only letters, numbers, at (@), dot (.), dash (-) or underscore (_) characters",
            ),
        ],
    )
    password = PasswordField("Password", id="pwd_login", validators=[DataRequired()])


class CreateAccountForm(FlaskForm):
    username = StringField(
        "Username",
        id="username_create",
        validators=[
            DataRequired(),
            Regexp(
                "^[a-zA-Z0-9-_@\.]+$",
                message="Username name must contain only letters, numbers, dash (-) or underscore (_) characters",
            ),
        ],
    )
    password = PasswordField("Password", id="pwd_login", validators=[DataRequired()])
    email = StringField("Email", id="email_create", validators=[DataRequired(), Email()])
    password = PasswordField("Password", id="pwd_create", validators=[DataRequired()])

class CreateUserForm(FlaskForm):
    id = HiddenField("User id")
    username = StringField(
        "Username",
        id="user-username",
        validators=[
            DataRequired(),
            Regexp(
                "^[a-zA-Z0-9-_@\.]+$",
                message="Username name must contain only letters, numbers, at (@), dot (.), dash (-) or underscore (_) characters",
            ),
        ],
    )
    first_name = StringField("First name", id="user-first-name", validators=[
            Regexp(
                "^[a-zA-Z0-9]+$",
                message="First name must contain only letters characters",
            ),
        ],)
    last_name = StringField("Last name", id="user-last-name", validators=[
            Regexp(
                "^[a-zA-Z0-9]+$",
                message="Last name must contain only letters characters",
            ),
        ],)
    email = StringField("Email", id="user-email", validators=[Email()])
    password = PasswordField("Password", id="user-password", validators=[DataRequired()])
    password_confirm = PasswordField("Confirm password", id="user-confirm-password", validators=[DataRequired()])
    role = (int(1), "admin")

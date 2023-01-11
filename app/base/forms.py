# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask_wtf import FlaskForm
from wtforms import TextField, PasswordField
from wtforms.validators import InputRequired, Email, DataRequired, Regexp

## login and registration


class LoginForm(FlaskForm):
    username = TextField(
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
    username = TextField(
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
    email = TextField("Email", id="email_create", validators=[DataRequired(), Email()])
    password = PasswordField("Password", id="pwd_create", validators=[DataRequired()])

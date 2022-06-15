# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from email.policy import default
from multiprocessing.sharedctypes import Value
from pickle import FALSE
from tkinter.tix import Select
from xmlrpc.client import Boolean
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, HiddenField, SelectField
from wtforms.fields.simple import TextAreaField
from wtforms.validators import Email, DataRequired, Regexp


class UserForm(FlaskForm):
    id = HiddenField("User id")
    username = StringField("Username", id="user-username", validators=[DataRequired()])
    first_name = StringField("First name", id="user-first-name")
    last_name = StringField("Last name", id="user-last-name")
    email = StringField("Email", id="user-email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", id="user-password")
    password_confirm = PasswordField("Confirm password", id="user-confirm-password")
    roles = [(int(0), 'user'),(int(1),'admin')]
    role = SelectField(choices=roles, validators=[DataRequired()])

class RepositoryForm(FlaskForm):
    id = HiddenField("Repository id")
    name = StringField("Repository name", id="repo-name", validators=[DataRequired(), Regexp('^[a-zA-Z0-9-_]+$', message="Repository name must contain only letters, numbers, dash (-) or underscore (_) characters"),])
    description = TextAreaField("Repository description", id="repo-description")
    uri = StringField("Repository URI", id="repo-uri", validators=[DataRequired()])
    git_username = StringField("Git username", id="repo-username")
    git_token = StringField("Git Acess Token", id="repo-token")

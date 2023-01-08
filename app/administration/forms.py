# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from flask_wtf import FlaskForm
from wtforms import HiddenField, PasswordField, SelectField, TextField
from wtforms.fields.simple import TextAreaField
from wtforms.validators import DataRequired, Email, Regexp


class UserForm(FlaskForm):
    id = HiddenField("User id")
    username = TextField("Username", id="user-username", validators=[DataRequired(), Regexp('^[a-zA-Z0-9-_@\.]+$', message="Username name must contain only letters, numbers, dash (-) or underscore (_) characters")])
    first_name = TextField("First name", id="user-first-name")
    last_name = TextField("Last name", id="user-last-name")
    email = TextField("Email", id="user-email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", id="user-password")
    password_confirm = PasswordField("Confirm password", id="user-confirm-password")
    roles = [(int(0), 'user'),(int(1),'admin')]
    role = SelectField(choices=roles, validators=[DataRequired()])

class RepositoryForm(FlaskForm):
    id = HiddenField("Repository id")
    name = TextField("Repository name", id="repo-name", validators=[DataRequired(), Regexp('^[a-zA-Z0-9-_]+$', message="Repository name must contain only letters, numbers, dash (-) or underscore (_) characters")])
    description = TextAreaField("Repository description", id="repo-description")
    uri = TextField("Repository URI", id="repo-uri", validators=[DataRequired()])
    git_username = TextField("Git username", id="repo-username")
    git_token = TextField("Git Acess Token", id="repo-token")

class LdapForm(FlaskForm):
    server_uri = TextField("LDAP server URI", id="ldap-server-uri", validators=[DataRequired(),Regexp('^[a-zA-Z0-9-_\/\.:]+$', message="Server URI must contain only letters, numbers, dash (-), slash (/), colon (:), dot (.), or underscore (_) characters")])
    bind_dn = TextField("Bind DN", id="ldap-bind-dn", validators=[DataRequired(),Regexp('^[a-zA-Z0-9-_,=]+$', message="Bind DN must contain only letters, numbers, dash (-), slash (/), equals (=) and comma(,) characters")])
    bind_password = PasswordField("Bind password", id="ldap-bind-password")
    base_dn = TextField("Base", id="ldap-base-dn", validators=[DataRequired(),Regexp('^[a-zA-Z0-9,=]+$', message="Base DN name must contain only letters, numbers, equals (=) and comma(,) characters")])

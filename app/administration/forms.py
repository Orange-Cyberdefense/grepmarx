# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from flask_wtf import FlaskForm
from wtforms import (BooleanField, HiddenField, IntegerField, PasswordField,
                     SelectField, StringField)
from wtforms.fields.simple import TextAreaField
from wtforms.validators import DataRequired, Optional, Email, Regexp


class UserForm(FlaskForm):
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
    first_name = StringField("First name", id="user-first-name")
    last_name = StringField("Last name", id="user-last-name")
    email = StringField("Email", id="user-email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", id="user-password")
    password_confirm = PasswordField("Confirm password", id="user-confirm-password")
    roles = [(int(0), "user"), (int(1), "admin")]
    role = SelectField(choices=roles, validators=[DataRequired()])


class RepositoryForm(FlaskForm):
    id = HiddenField("Repository id")
    name = StringField(
        "Repository name",
        id="repo-name",
        validators=[
            DataRequired(),
            Regexp(
                "^[a-zA-Z0-9-_]+$",
                message="Repository name must contain only letters, numbers, dash (-) or underscore (_) characters",
            ),
        ],
    )
    description = TextAreaField("Repository description", id="repo-description")
    uri = StringField("Repository URI", id="repo-uri", validators=[DataRequired()])
    git_username = StringField("Git username", id="repo-username")
    git_token = PasswordField("Git access token", id="repo-token")


class LdapForm(FlaskForm):
    ldap_activated = BooleanField(
        "Activate LDAP authentication", id="ldap-activated"
    )
    users_approval = BooleanField("LDAP users approval", id="ldap-users-approval")
    server_host = StringField(
        "LDAP server host",
        id="ldap-server-uri",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9-_\.]+$",
                message="Server host must contain only letters, numbers, dash (-), dot (.), or underscore (_) characters",
            )
        ],
    )
    server_port = IntegerField("Port", id="ldap-server-port", validators=[Optional()])
    use_tls = BooleanField("Activate TLS", id="ldap-use-tls")
    cacert_path = StringField(
        "CA certificate path",
        id="ldap-cacert-path",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9/\\-_\. ]+$",
                message="CA certificate path must contain only letters, numbers, dash (-), slash (/), equals (=), dot (.), slash (\/), space ( ) and comma (,) characters",
            )
        ],
    )
    bind_dn = StringField(
        "Bind DN",
        id="ldap-bind-dn",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9-_,=]+$",
                message="Bind DN must contain only letters, numbers, dash (-), underscore (_), slash (/), equals (=) and comma (,) characters",
            )
        ],
    )
    bind_password = PasswordField("Bind password", id="ldap-bind-password")
    base_dn = StringField(
        "Base DN",
        id="ldap-base-dn",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9-_,=]+$",
                message="Base DN must contain only letters, numbers, dash (-), underscore (_), slash (/), equals (=) and comma (,) characters",
            )
        ],
    )
    users_dn = StringField(
        "Users DN",
        id="ldap-users-dn",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9-_,=]+$",
                message="Users DN must contain only letters, numbers, dash (-), underscore (_), equals (=) and comma (,) characters",
            )
        ],
    )
    groups_dn = StringField(
        "Groups DN",
        id="ldap-groups-dn",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9-_,=]+$",
                message="Groups DN must contain only letters, numbers, dash (-), underscore (_), equals (=) and comma (,) characters",
            )
        ],
    )
    user_rdn_attr = StringField(
        "User RDN Attribute",
        id="ldap-user-rdn-attr",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9]+$",
                message="User RDN attribute must contain only letters and numbers characters",
            )
        ],
    )
    user_login_attr = StringField(
        "User login attribute",
        id="ldap-user-login-attr",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9]+$",
                message="User login attribute must contain only letters and numbers characters",
            )
        ],
    )
    user_object_filter = StringField(
        "User object filter",
        id="ldap-user-object-filter",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9-_\(\)=&|*:! ]+$",
                message="User object filter must contain only letters, numbers, dash (-), underscore (_), parenthesis (), colon (:), exclamation mark (!), equal (=), space ( ), ampersand (&), pipe (|) ans star (*) characters",
            )
        ],
    )
    group_object_filter = StringField(
        "Group object filter",
        id="ldap-group-object-filter",
        validators=[
            Optional(),
            Regexp(
                "^[a-zA-Z0-9-_\(\)=&|*:! ]+$",
                message="Group object filter must contain only letters, numbers, dash (-), underscore (_), parenthesis (), colon (:), exclamation mark (!), equal (=), space ( ), ampersand (&), pipe (|) ans star (*) characters",
            )
        ],
    )

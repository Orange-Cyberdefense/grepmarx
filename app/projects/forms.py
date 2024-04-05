# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import StringField, RadioField, SubmitField
from wtforms.validators import DataRequired


class ProjectForm(FlaskForm):
    name = StringField("Project name", id="project-name", validators=[DataRequired()])
    source_archive = FileField(
        "Source archive",
        id="project-source-archive",
        validators=[FileRequired(), FileAllowed(["zip"], "Zip archives only")],
    )


class XLSExportForm(FlaskForm):
    choice = RadioField(
        "Filter findings to export",
        choices=[
            ("only_confirmed", "Export only Confirmed vulnerabilities"),
            (
                "confirmed_and_undefined",
                "Export Confirmed and To review vulnerabilities",
            ),
            ("all", "Export all vulnerabilities"),
        ],
        default="all",
    )
    submit = SubmitField("Submit")

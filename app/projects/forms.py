# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField, FileRequired
from wtforms import TextField
from wtforms.validators import DataRequired


class ProjectForm(FlaskForm):
    name = TextField("Project name", id="project-name", validators=[DataRequired()])
    source_archive = FileField(
        "Source archive",
        id="project-source-archive",
        validators=[FileRequired(), FileAllowed(["zip"], "Zip archives only")],
    )

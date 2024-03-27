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

class ExcelForm(FlaskForm):
    choice = RadioField('Select Option', choices=[('only_confirmed', 'Only Confirmed'),
                                                  ('confirmed_and_undefined', 'Confirmed and To review'),
                                                  ('all', 'All')])
    submit = SubmitField('Submit')
# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from cgitb import text
from wsgiref.validate import validator
from flask_wtf import FlaskForm
from wtforms import TextAreaField, SelectMultipleField, widgets
from wtforms.fields.simple import HiddenField, TextField
from wtforms.validators import DataRequired

class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()

class RulePackForm(FlaskForm):
    id = HiddenField("Rule pack id", id="rule-pack-id")
    name = TextField("Rule pack name", id="rule-pack-name", validators=[DataRequired()])
    description = TextAreaField("Rule pack description", id="rule-pack-description")
    languages = MultiCheckboxField("Languages", coerce=int)
    rules = HiddenField("Rule pack rules", id="datatable-selection")

class RulesAddForm(FlaskForm):
    name = TextField("Name of rule", id="rule-name", validators=[DataRequired()])
    rule = TextAreaField("Rule code", id="rule-code")
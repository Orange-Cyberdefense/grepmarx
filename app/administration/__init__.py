# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from flask import Blueprint

blueprint = Blueprint(
    'administration_blueprint',
    __name__,
    url_prefix='/',
    template_folder='templates',
    static_folder='static'
)

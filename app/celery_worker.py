#!/usr/bin/env python3
from app import create_app
from sys import exit
from decouple import config
from app.config import config_dict

DEBUG = True
DEBUG = config('DEBUG', default=True, cast=bool)
get_config_mode = 'Debug' if DEBUG else 'Production'
try:
    app_config = config_dict[get_config_mode]
except KeyError:
    exit('Error: Invalid <config_mode>. Expected values [Debug, Production] ')

app = create_app(app_config)
app.app_context().push()

from app import celery
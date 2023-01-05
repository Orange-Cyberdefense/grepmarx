#!/usr/bin/env bash

export FLASK_APP=run.py
flask db stamp head
flask db upgrade

/usr/bin/supervisord
#!/usr/bin/env bash

export FLASK_APP=run.py

if [ -z "$(flask db current 2>/dev/null | grep -v INFO)" ]
    then
        flask db stamp head
    else
        flask db upgrade
fi

/usr/bin/supervisord
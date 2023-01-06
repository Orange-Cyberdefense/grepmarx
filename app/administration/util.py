# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from multiprocessing import connection
from app.base.models import User
from ldap3 import Server, Connection,Tls, ALL
from ldap3.core.exceptions import LDAPException, LDAPBindError
import re
import ssl

def validate_user_form(
    form, skip_username=False, skip_email=False, skip_password=False
):
    err = None
    if not skip_username:
        # Check username exists
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            err = "Username already registered"
    if not skip_email:
        # Check email exists
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            err = "Email already registered"
    if not skip_password:
        # Check password not empty
        if form.password.data == "":
            err = "Please define a password for the new user"
        # Check passwords match
        if form.password.data != form.password_confirm.data:
            err = "Passwords does not match"
    return err

def bind(password, url, dnd):

    ldap_server =url

    tls = Tls( validate = ssl.CERT_REQUIRED,ca_certs_file = '/opt/grepmarx/ldap-cert/ca.crt')
    server = Server(ldap_server,port=636, use_ssl=True,get_info=ALL)
    c = Connection(server, user=dnd, password=password,auto_bind=True)
    print(c)
    if not c.bind():
        tested =0
    else:
        tested = 1
 
    return tested


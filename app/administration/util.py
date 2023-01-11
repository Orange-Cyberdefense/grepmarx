# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from app.base.models import User


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

def validate_ldap_form(form):
    err = None
    # Fields are mandatory only if LDAP is enabled
    if form.ldap_activated.data:
        # Check server not empty
        if form.server_host.data == "":
            err = "Please define LDAP server"
        # Check port not empty
        if form.server_port.data == "":
            err = "Please define LDAP server port"
        # Check base DN not empty
        if form.base_dn.data == "":
            err = "Please define a base DN"
         # Check bind DN and password
        if not form.anonymous_bind.data:
            if form.bind_dn.data == "":
                err = "Please define bind DN"
            if form.bind_password.data == "":
                err = "Please define bind password"
    return err

# def bind(password, url, dnd):

#     ldap_server =url

#     tls = Tls(ciphers='ALL', validate = ssl.CERT_REQUIRED,ca_certs_file = '/opt/grepmarx/ldap-cert/ca.crt')
#     server = Server(ldap_server,port=636, use_ssl=True,get_info=ALL, tls=tls)
#     c = Connection(server, user=dnd, password=password,auto_bind=True)
#     print(c)
#     if not c.bind():
#         tested =0
#     else:
#         tested = 1
 
#     return tested


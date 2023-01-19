# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""
from sqlalchemy import Boolean, Column, Integer, String

from app import db


class LdapConfiguration(db.Model):

    __tablename__ = "LdapConfiguration"

    id = Column(Integer, primary_key=True)
    ldap_activated = Column(Boolean, nullable=False)
    server_host = Column(String, nullable=True)
    server_port = Column(Integer, nullable=True)
    use_tls = Column(Boolean, nullable=True)
    cacert_path = Column(String, nullable=True)
    users_approval = Column(Boolean, nullable=True)
    bind_dn = Column(String, nullable=True)
    bind_password = Column(String, nullable=True)
    base_dn = Column(String, nullable=True)
    users_dn = Column(String, nullable=True)
    groups_dn = Column(String, nullable=True)
    user_rdn_attr = Column(String, nullable=True)
    user_login_attr =  Column(String, nullable=True)
    user_object_filter =  Column(String, nullable=True)
    group_object_filter =  Column(String, nullable=True)

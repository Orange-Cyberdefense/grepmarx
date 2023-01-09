# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""
from app import db
from sqlalchemy import Column, Integer, String, Boolean


class LdapConfiguration(db.Model):

    __tablename__ = "LdapConfiguration"

    id = Column(Integer, primary_key=True)
    ldap_activated = Column(Boolean, nullable=False)
    server_host = Column(String, nullable=True)
    server_port = Column(Integer, nullable=True)
    use_tls = Column(Integer, nullable=True)
    bind_dn = Column(String, nullable=True)
    bind_password = Column(String, nullable=True)
    base_dn = Column(String, nullable=True)

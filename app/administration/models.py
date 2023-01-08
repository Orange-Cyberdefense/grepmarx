# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""
from app import db
from sqlalchemy import Column, Integer, String


class LdapConfiguration(db.Model):

    __tablename__ = "LdapConfiguration"

    id = Column(Integer, primary_key=True)
    server_uri = Column(String, nullable=True)
    bind_dn = Column(String, nullable=True)
    bind_password = Column(String, nullable=True)
    base_dn = Column(String, nullable=True)
